//! The Frida engine actor.
//!
//! All of frida-rust's core objects (`Frida`, `DeviceManager`, `Device`, `Session`,
//! `Script`) are `!Send`/`!Sync` and lifetime-chained, so they cannot live in
//! multithreaded Axum state. Instead a single dedicated OS thread owns them and the
//! session registry; the async layer talks to it over a bounded [`mpsc`] channel of
//! [`Command`]s, each carrying a `oneshot` reply.

pub mod command;
mod live;
pub mod session;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use frida::{Device, DeviceManager, Frida, ScriptOption};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

pub use command::{Command, EngineError, InjectOutcome};
pub use session::{SessionId, SessionInfo};

use live::LiveScript;
use session::{BufferHandler, LiveSession, MessageBuffer, Registry};

/// Command-channel capacity. A full channel back-pressures HTTP handlers (they park
/// on `send().await`) rather than dropping work.
const COMMAND_BUFFER: usize = 128;

/// Handle returned by [`spawn`], owned by `main`.
pub struct EngineHandle {
    /// Cloneable command sender for the HTTP layer.
    pub tx: mpsc::Sender<Command>,
    /// Resolves once the engine has connected to frida-server (or failed to).
    pub ready_rx: oneshot::Receiver<Result<(), String>>,
    /// The actor thread's join handle (for graceful shutdown).
    pub join: JoinHandle<()>,
}

/// Spawn the engine actor thread. It obtains the Frida runtime and connects to
/// frida-server at `host` itself (those objects must never leave this thread).
pub fn spawn(host: String) -> EngineHandle {
    let (tx, rx) = mpsc::channel::<Command>(COMMAND_BUFFER);
    let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();

    let join = thread::Builder::new()
        .name("frida-engine".into())
        .spawn(move || engine_main(host, rx, ready_tx))
        .expect("failed to spawn frida-engine thread");

    EngineHandle { tx, ready_rx, join }
}

/// Actor thread entry point: leak the singletons, connect, then run the loop.
fn engine_main(
    host: String,
    rx: mpsc::Receiver<Command>,
    ready_tx: oneshot::Sender<Result<(), String>>,
) {
    // Leak the three program-lifetime singletons so their lifetime parameters become
    // `'static` and the borrow chain is erased. There is exactly one of each for the
    // whole process; their `Drop` (frida_deinit / manager close) simply never runs.
    let frida: &'static Frida = Box::leak(Box::new(unsafe { Frida::obtain() }));
    let manager: &'static DeviceManager<'static> = Box::leak(Box::new(DeviceManager::obtain(frida)));

    let device: &'static Device<'static> = match manager.get_remote_device(&host) {
        Ok(device) => Box::leak(Box::new(device)),
        Err(err) => {
            let _ = ready_tx.send(Err(format!(
                "could not reach frida-server at '{host}': {err} \
                 (is frida-server running on the device and reachable over loopback?)"
            )));
            return;
        }
    };

    let _ = ready_tx.send(Ok(()));
    Engine::new(device).run(rx);
}

/// Owns the connected device and the session registry; runs on the actor thread.
struct Engine {
    device: &'static Device<'static>,
    registry: Registry,
    next_id: u64,
}

impl Engine {
    fn new(device: &'static Device<'static>) -> Self {
        Self {
            device,
            registry: Registry::new(),
            next_id: 0,
        }
    }

    /// Blocking command loop. `blocking_recv` parks this (non-Tokio) thread.
    fn run(mut self, mut rx: mpsc::Receiver<Command>) {
        while let Some(command) = rx.blocking_recv() {
            match command {
                Command::Inject { pid, source, name, reply } => {
                    let _ = reply.send(self.inject(pid, source, name));
                }
                Command::Rpc { id, function, args, reply } => {
                    let _ = reply.send(self.rpc(id, &function, args));
                }
                Command::DrainMessages { id, reply } => {
                    let _ = reply.send(self.drain(id));
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

    fn inject(
        &mut self,
        pid: u32,
        source: String,
        name: Option<String>,
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

        // Build the Session+Script self-referential pair.
        let mut live = LiveScript::try_new(session, |session| {
            // NOTE: we deliberately do not call ScriptOption::set_name — upstream passes
            // a non-NUL-terminated `&str` pointer to C, causing an over-read. The script
            // name is tracked in our registry instead.
            let mut option = ScriptOption::default();
            session
                .create_script(&source, &mut option)
                .map_err(EngineError::Script)
        })?;

        // Install the message-capture handler (connects the "message" signal, which is
        // also what makes rpc replies flow), then load the script.
        let buffer: MessageBuffer = Arc::new(Mutex::new(VecDeque::new()));
        {
            let buffer = buffer.clone();
            live.with_dependent_mut(|_session, script| -> Result<(), EngineError> {
                script
                    .handle_message(BufferHandler::new(buffer))
                    .map_err(EngineError::Script)?;
                script.load().map_err(EngineError::Script)
            })?;
        }

        let package = self.lookup_package(pid);

        self.next_id += 1;
        let id = SessionId(self.next_id);
        let script_name = name.unwrap_or_else(|| format!("fggb-{}", id.0));
        self.registry.insert(
            id,
            LiveSession {
                pid,
                package: package.clone(),
                name: script_name,
                created_at: Instant::now(),
                messages: buffer,
                live,
            },
        );

        Ok(InjectOutcome { id, pid, package })
    }

    fn rpc(
        &mut self,
        id: SessionId,
        function: &str,
        args: Option<Value>,
    ) -> Result<Option<Value>, EngineError> {
        let session = self
            .registry
            .get_mut(&id)
            .ok_or(EngineError::UnknownSession(id.0))?;
        session
            .live
            .with_dependent_mut(|_session, script| script.exports.call(function, args))
            .map_err(EngineError::Rpc)
    }

    fn list_exports(&mut self, id: SessionId) -> Result<Vec<String>, EngineError> {
        let session = self
            .registry
            .get_mut(&id)
            .ok_or(EngineError::UnknownSession(id.0))?;
        session
            .live
            .with_dependent_mut(|_session, script| script.list_exports())
            .map_err(EngineError::Rpc)
    }

    fn drain(&mut self, id: SessionId) -> Result<Vec<Value>, EngineError> {
        let session = self
            .registry
            .get(&id)
            .ok_or(EngineError::UnknownSession(id.0))?;
        let mut queue = session
            .messages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(queue.drain(..).collect())
    }

    fn kill(&mut self, id: SessionId) -> Result<(), EngineError> {
        let session = self
            .registry
            .remove(&id)
            .ok_or(EngineError::UnknownSession(id.0))?;
        detach_session(&session);
        // Dropping `session` drops LiveScript (Script before Session, via self_cell).
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

    /// Best-effort: find the process name for `pid` on the connected device.
    fn lookup_package(&self, pid: u32) -> Option<String> {
        self.device
            .enumerate_processes()
            .into_iter()
            .find(|process| process.get_pid() == pid)
            .map(|process| process.get_name().to_string())
    }
}

/// Best-effort unload + detach of a session's script (ignores errors).
fn detach_session(session: &LiveSession) {
    let _ = session.live.with_dependent(|_session, script| script.unload());
    let _ = session.live.with_dependent(|session, _script| session.detach());
}
