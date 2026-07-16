//! Shared Axum application state.

use tokio::sync::mpsc;

use crate::engine::Command;

/// Cloneable, `Send + Sync` state handed to every handler. It holds only the command
/// sender to the Frida engine actor — no Frida objects (which are `!Send`) live here.
#[derive(Clone)]
pub struct AppState {
    pub tx: mpsc::Sender<Command>,
}
