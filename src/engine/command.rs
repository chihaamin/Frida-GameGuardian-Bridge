//! The message protocol between the async HTTP layer and the single-threaded
//! Frida engine actor.
//!
//! Every variant that can fail carries a [`oneshot`] reply channel typed
//! `Result<T, EngineError>`; the HTTP handler `.await`s it. The engine actor runs
//! on a dedicated OS thread (it owns the `!Send` Frida objects), so the reply
//! channel is the only thing that crosses the thread boundary back to Tokio.

use serde_json::Value;
use tokio::sync::oneshot;

use super::session::{SessionId, SessionInfo};

/// Convenience alias for a fallible reply channel.
pub type Reply<T> = oneshot::Sender<Result<T, EngineError>>;

/// Result of a successful injection.
pub struct InjectOutcome {
    pub id: SessionId,
    pub pid: u32,
    pub package: Option<String>,
}

/// A request sent to the engine actor thread.
pub enum Command {
    /// Attach to `pid`, create + load `source`, register the session.
    Inject {
        pid: u32,
        source: String,
        name: Option<String>,
        reply: Reply<InjectOutcome>,
    },
    /// Inject the GG bridge agent into `pid` with a `ForwardHandler` — its messages are
    /// forwarded back to the actor as [`Command::BridgeMessage`] so they can be serviced.
    InjectBridge {
        pid: u32,
        source: String,
        reply: Reply<InjectOutcome>,
    },
    /// A message emitted by a bridge agent (forwarded from the frida dispatcher thread).
    /// The actor routes it (`frida.run`/`pull`/…) and posts a reply back to the bridge.
    BridgeMessage {
        bridge_id: SessionId,
        payload: Value,
    },
    /// Call an `rpc.exports.<function>` on a live session.
    Rpc {
        id: SessionId,
        function: String,
        args: Option<Value>,
        reply: Reply<Option<Value>>,
    },
    /// Drain the buffered script messages for a session.
    DrainMessages { id: SessionId, reply: Reply<Vec<Value>> },
    /// List the names of a session's rpc exports.
    ListExports { id: SessionId, reply: Reply<Vec<String>> },
    /// Unload + detach a session and remove it from the registry.
    Kill { id: SessionId, reply: Reply<()> },
    /// Snapshot of all live sessions (infallible).
    ListSessions { reply: oneshot::Sender<Vec<SessionInfo>> },
    /// Unload + detach everything and break the actor loop.
    Shutdown { reply: oneshot::Sender<()> },
}

/// Errors produced by the engine actor.
#[derive(thiserror::Error, Debug)]
pub enum EngineError {
    /// No session with this id in the registry.
    #[error("no session with id {0}")]
    UnknownSession(u64),

    /// `Device::attach` failed for the target pid.
    #[error("attach failed for pid {pid}: {source}")]
    Attach {
        pid: u32,
        #[source]
        source: frida::Error,
    },

    /// The session came back already detached (target gone / not attachable).
    #[error("session is detached")]
    Detached,

    /// Script create / load / handler-install failed.
    #[error("script error: {0}")]
    Script(#[source] frida::Error),

    /// An rpc call (or list) failed on the Frida side.
    #[error("rpc error: {0}")]
    Rpc(#[source] frida::Error),

    /// The request carried an empty script body.
    #[error("empty script source")]
    EmptyScript,
}
