//! Session registry types and the script-message capture handler.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use frida::{Message, ScriptHandler};
use serde_json::{json, Value};

use super::live::LiveScript;

/// Opaque, monotonically-increasing session identifier.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct SessionId(pub u64);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Per-session message buffer, shared between frida-core's dispatcher thread
/// (producer, via [`BufferHandler`]) and the engine actor thread (consumer, on drain).
/// A `std` mutex is required because the producer is not a Tokio worker.
pub type MessageBuffer = Arc<Mutex<VecDeque<Value>>>;

/// Cap on buffered messages so a client that never drains cannot grow memory unbounded.
pub const MAX_BUFFERED_MESSAGES: usize = 4096;

/// A live, registered session: the attached `Session` + loaded `Script` plus bookkeeping.
pub struct LiveSession {
    pub pid: u32,
    pub package: Option<String>,
    pub name: String,
    pub created_at: Instant,
    pub messages: MessageBuffer,
    pub live: LiveScript,
}

/// The engine's session table (only ever touched on the actor thread).
pub type Registry = HashMap<SessionId, LiveSession>;

/// Serializable summary of a session for `GET /sessions`.
#[derive(serde::Serialize)]
pub struct SessionInfo {
    pub id: u64,
    pub pid: u32,
    pub package: Option<String>,
    pub name: String,
    pub queued_messages: usize,
    pub uptime_secs: u64,
}

/// [`ScriptHandler`] that converts each non-rpc script message into an owned
/// `serde_json::Value` and pushes it onto the session's buffer.
///
/// `on_message` is invoked from frida-core's dispatcher thread, across the FFI
/// boundary, so it must never panic and must use blocking-safe primitives.
pub struct BufferHandler {
    buf: MessageBuffer,
    seq: u64,
}

impl BufferHandler {
    pub fn new(buf: MessageBuffer) -> Self {
        Self { buf, seq: 0 }
    }
}

impl ScriptHandler for BufferHandler {
    fn on_message(&mut self, message: Message, data: Option<Vec<u8>>) {
        self.seq += 1;
        let value = message_to_value(message, data, self.seq);
        // Tolerate a poisoned lock rather than unwrap-panic across the FFI boundary.
        if let Ok(mut queue) = self.buf.lock() {
            if queue.len() >= MAX_BUFFERED_MESSAGES {
                queue.pop_front();
            }
            queue.push_back(value);
        }
    }
}

/// Convert a Frida [`Message`] into an owned JSON object. `Message` is not
/// `Serialize`/`Clone`, so we reconstruct it by hand.
fn message_to_value(message: Message, data: Option<Vec<u8>>, seq: u64) -> Value {
    let mut value = match message {
        Message::Send(send) => json!({ "type": "send", "payload": send.payload }),
        Message::Log(log) => json!({
            "type": "log",
            "level": format!("{:?}", log.level).to_lowercase(),
            "payload": log.payload,
        }),
        Message::Error(err) => json!({
            "type": "error",
            "description": err.description,
            "stack": err.stack,
            "fileName": err.file_name,
            "lineNumber": err.line_number,
            "columnNumber": err.column_number,
        }),
        Message::Other(other) => json!({ "type": "other", "raw": other }),
    };
    value["seq"] = json!(seq);
    if let Some(bytes) = data {
        value["data"] = json!(bytes);
    }
    value
}
