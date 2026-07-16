//! The Frida engine actor.
//!
//! All of frida-rust's core objects (`Frida`, `DeviceManager`, `Device`, `Session`,
//! `Script`) are `!Send`/`!Sync` and lifetime-chained, so they live on a single
//! dedicated OS thread that owns them and the session registry. Everything else talks
//! to it over a bounded [`mpsc`] channel of [`Command`]s.
//!
//! Two kinds of injected agent:
//! * the **bridge** in GameGuardian's process ([`ForwardHandler`]) — its `send()`s are
//!   forwarded back here as [`Command::BridgeMessage`] and serviced (`run`/`pull`/…);
//! * **target** sessions ([`BufferHandler`]) that FGGB attaches to GG's current target
//!   on the bridge's behalf, buffering their messages for `pull`.

pub mod command;
mod live;
pub mod session;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use frida::{Device, DeviceManager, Frida, ScriptOption};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

pub use command::{Command, EngineError, InjectOutcome};
pub use session::{SessionId, SessionInfo};

use live::LiveScript;
use session::{BufferHandler, ForwardHandler, LiveSession, MessageBuffer, Registry};

/// Command-channel capacity.
const COMMAND_BUFFER: usize = 256;

/// How long to let a freshly-run target script emit its top-level `send()`s before the
/// `run` reply is assembled. (Later/async hook events are read via `pull`.)
const RUN_SETTLE: Duration = Duration::from_millis(150);

/// Handle returned by [`spawn`], owned by `main`.
pub struct EngineHandle {
    pub tx: mpsc::Sender<Command>,
    pub ready_rx: oneshot::Receiver<Result<(), String>>,
    pub join: JoinHandle<()>,
}

/// Spawn the engine actor thread. It obtains the Frida runtime and the local device
/// (FGGB's own embedded frida-core injects directly, as root — no frida-server, so no
/// client/server version to match). Those objects never leave the thread.
pub fn spawn() -> EngineHandle {
    let (tx, rx) = mpsc::channel::<Command>(COMMAND_BUFFER);
    let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();

    let self_tx = tx.clone();
    let join = thread::Builder::new()
        .name("frida-engine".into())
        .spawn(move || engine_main(rx, self_tx, ready_tx))
        .expect("failed to spawn frida-engine thread");

    EngineHandle { tx, ready_rx, join }
}

/// Actor thread entry point: leak the singletons, open the local device, run the loop.
fn engine_main(
    rx: mpsc::Receiver<Command>,
    self_tx: mpsc::Sender<Command>,
    ready_tx: oneshot::Sender<Result<(), String>>,
) {
    // Leak the three program-lifetime singletons so their lifetime parameters become
    // `'static` and the borrow chain is erased.
    let frida: &'static Frida = Box::leak(Box::new(unsafe { Frida::obtain() }));
    let manager: &'static DeviceManager<'static> = Box::leak(Box::new(DeviceManager::obtain(frida)));

    let device: &'static Device<'static> = match manager.get_local_device() {
        Ok(device) => Box::leak(Box::new(device)),
        Err(err) => {
            let _ = ready_tx.send(Err(format!(
                "could not open local frida device: {err} (FGGB must run as root)"
            )));
            return;
        }
    };

    let _ = ready_tx.send(Ok(()));
    Engine::new(device, self_tx).run(rx);
}

/// Owns the connected device and the session registry; runs on the actor thread.
struct Engine {
    device: &'static Device<'static>,
    /// A clone of the command sender, so message handlers can forward events back here.
    self_tx: mpsc::Sender<Command>,
    registry: Registry,
    next_id: u64,
}

impl Engine {
    fn new(device: &'static Device<'static>, self_tx: mpsc::Sender<Command>) -> Self {
        Self { device, self_tx, registry: Registry::new(), next_id: 0 }
    }

    /// Blocking command loop. `blocking_recv` parks this (non-Tokio) thread.
    fn run(mut self, mut rx: mpsc::Receiver<Command>) {
        while let Some(command) = rx.blocking_recv() {
            match command {
                Command::Inject { pid, source, name, reply } => {
                    let _ = reply.send(self.inject(pid, source, name));
                }
                Command::InjectBridge { pid, source, reply } => {
                    let _ = reply.send(self.inject_bridge(pid, source));
                }
                Command::BridgeMessage { bridge_id, payload } => {
                    self.handle_bridge_message(bridge_id, payload);
                }
                Command::Rpc { id, function, args, reply } => {
                    let _ = reply.send(self.rpc(id, &function, args));
                }
                Command::DrainMessages { id, reply } => {
                    let _ = reply.send(Ok(self.drain_values(id)));
                }
                Command::ListExports { id, reply } => {
                    let _ = reply.send(self.list_exports(id));
                }
                Command::Kill { id, reply } => {
                    let _ = reply.send(self.kill(id));
                }
                Command::ListSessions { reply } => {
                    let _ = reply.send(self.list_sessions());
                }
                Command::Shutdown { reply } => {
                    self.shutdown_all();
                    let _ = reply.send(());
                    break;
                }
            }
        }
    }

    /// Attach to `pid`, create + load `source`, register the session. `forward` selects
    /// the message handler: the bridge forwards requests here; targets buffer for `pull`.
    fn inject_with(
        &mut self,
        pid: u32,
        source: String,
        name: Option<String>,
        forward: bool,
    ) -> Result<InjectOutcome, EngineError> {
        if source.trim().is_empty() {
            return Err(EngineError::EmptyScript);
        }

        let session = self
            .device
            .attach(pid)
            .map_err(|source| EngineError::Attach { pid, source })?;
        if session.is_detached() {
            return Err(EngineError::Detached);
        }

        self.next_id += 1;
        let id = SessionId(self.next_id);

        let mut live = LiveScript::try_new(session, |session| {
            // We deliberately skip ScriptOption::set_name (upstream over-reads a
            // non-NUL-terminated &str); the name is tracked in our registry instead.
            let mut option = ScriptOption::default();
            session.create_script(&source, &mut option).map_err(EngineError::Script)
        })?;

        let buffer: MessageBuffer = Arc::new(Mutex::new(VecDeque::new()));
        {
            let handler_buffer = buffer.clone();
            let handler_tx = self.self_tx.clone();
            live.with_dependent_mut(|_session, script| -> Result<(), EngineError> {
                if forward {
                    script
                        .handle_message(ForwardHandler::new(id, handler_tx))
                        .map_err(EngineError::Script)?;
                } else {
                    script
                        .handle_message(BufferHandler::new(handler_buffer))
                        .map_err(EngineError::Script)?;
                }
                script.load().map_err(EngineError::Script)
            })?;
        }

        let script_name = name.unwrap_or_else(|| format!("fggb-{}", id.0));
        self.registry.insert(
            id,
            LiveSession {
                pid,
                package: None,
                name: script_name,
                created_at: Instant::now(),
                messages: buffer,
                live,
            },
        );
        Ok(InjectOutcome { id, pid, package: None })
    }

    fn inject(&mut self, pid: u32, source: String, name: Option<String>) -> Result<InjectOutcome, EngineError> {
        self.inject_with(pid, source, name, false)
    }

    fn inject_bridge(&mut self, pid: u32, source: String) -> Result<InjectOutcome, EngineError> {
        self.inject_with(pid, source, Some("fggb-bridge".into()), true)
    }

    /// Service a message from the GG bridge and post a reply back to it.
    fn handle_bridge_message(&mut self, bridge_id: SessionId, payload: Value) {
        let op = payload.get("op").and_then(Value::as_str).unwrap_or("");
        if op.is_empty() {
            // Diagnostic (bridge-ready, install counts, …) — just surface it.
            tracing::info!("bridge: {payload}");
            return;
        }
        let req_id = payload.get("id").and_then(Value::as_u64).unwrap_or(0);
        let mut reply = self.route_bridge_op(op, &payload);
        reply["type"] = json!(format!("fggb-reply-{req_id}"));
        self.post_to_session(bridge_id, &reply);
    }

    /// Route a bridge request op to the matching engine action, returning a reply body.
    fn route_bridge_op(&mut self, op: &str, payload: &Value) -> Value {
        match op {
            // Run `code` inside GG's target `pid`; return the session id + its top-level
            // output. `keep` (default true) leaves the session loaded (for `pull` / hooks);
            // one-shot helpers pass keep=false so the target session is detached right after.
            "run" => {
                let pid = payload.get("pid").and_then(Value::as_u64).map(|p| p as u32);
                let code = payload.get("code").and_then(Value::as_str).map(String::from);
                let keep = payload.get("keep").and_then(Value::as_bool).unwrap_or(true);
                match (pid, code) {
                    (Some(pid), Some(code)) => {
                        match self.inject(pid, code, Some("fggb-target".into())) {
                            Ok(out) => {
                                thread::sleep(RUN_SETTLE);
                                let messages = self.drain_values(out.id);
                                if !keep {
                                    let _ = self.kill(out.id);
                                }
                                json!({ "ok": true, "sid": out.id.0, "messages": messages })
                            }
                            Err(e) => json!({ "ok": false, "error": e.to_string() }),
                        }
                    }
                    _ => json!({ "ok": false, "error": "run requires pid and code" }),
                }
            }
            // Drain buffered events from a previously-run target session.
            "pull" => match payload.get("sid").and_then(Value::as_u64).map(SessionId) {
                Some(sid) => json!({ "ok": true, "messages": self.drain_values(sid) }),
                None => json!({ "ok": false, "error": "pull requires sid" }),
            },
            // Unload + detach a target session.
            "kill" => match payload.get("sid").and_then(Value::as_u64).map(SessionId) {
                Some(sid) => {
                    let ok = self.kill(sid).is_ok();
                    json!({ "ok": ok })
                }
                None => json!({ "ok": false, "error": "kill requires sid" }),
            },
            other => json!({ "ok": false, "error": format!("unknown op '{other}'") }),
        }
    }

    /// Post a JSON message to a session's injected script (delivered to its `recv`).
    fn post_to_session(&self, id: SessionId, msg: &Value) {
        if let Some(session) = self.registry.get(&id) {
            let text = msg.to_string();
            let _ = session.live.with_dependent(|_session, script| script.post(&text, None));
        }
    }

    fn rpc(
        &mut self,
        id: SessionId,
        function: &str,
        args: Option<Value>,
    ) -> Result<Option<Value>, EngineError> {
        let session = self.registry.get_mut(&id).ok_or(EngineError::UnknownSession(id.0))?;
        session
            .live
            .with_dependent_mut(|_session, script| script.exports.call(function, args))
            .map_err(EngineError::Rpc)
    }

    fn list_exports(&mut self, id: SessionId) -> Result<Vec<String>, EngineError> {
        let session = self.registry.get_mut(&id).ok_or(EngineError::UnknownSession(id.0))?;
        session
            .live
            .with_dependent_mut(|_session, script| script.list_exports())
            .map_err(EngineError::Rpc)
    }

    /// Drain a session's buffered messages (empty if the session is unknown).
    fn drain_values(&self, id: SessionId) -> Vec<Value> {
        match self.registry.get(&id) {
            Some(session) => {
                let mut queue = session.messages.lock().unwrap_or_else(|p| p.into_inner());
                queue.drain(..).collect()
            }
            None => Vec::new(),
        }
    }

    fn kill(&mut self, id: SessionId) -> Result<(), EngineError> {
        let session = self.registry.remove(&id).ok_or(EngineError::UnknownSession(id.0))?;
        detach_session(&session);
        Ok(())
    }

    fn list_sessions(&self) -> Vec<SessionInfo> {
        self.registry
            .iter()
            .map(|(id, session)| SessionInfo {
                id: id.0,
                pid: session.pid,
                package: session.package.clone(),
                name: session.name.clone(),
                queued_messages: session.messages.lock().map(|q| q.len()).unwrap_or(0),
                uptime_secs: session.created_at.elapsed().as_secs(),
            })
            .collect()
    }

    fn shutdown_all(&mut self) {
        for (_, session) in self.registry.drain() {
            detach_session(&session);
        }
    }
}

/// Best-effort unload + detach of a session's script (ignores errors).
fn detach_session(session: &LiveSession) {
    let _ = session.live.with_dependent(|_session, script| script.unload());
    let _ = session.live.with_dependent(|session, _script| session.detach());
}
