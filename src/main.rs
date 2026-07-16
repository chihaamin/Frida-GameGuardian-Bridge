//! FGGB — Frida GameGuardian Bridge.
//!
//! A localhost HTTP bridge that lets GameGuardian (GG) Lua scripts POST a Frida JS
//! snippet + a target pid and have it injected into that process. Frida's `!Send`
//! objects are confined to a single [`engine`] actor thread; this file wires that
//! thread to an Axum HTTP server.
//!
//! Config via env vars:
//!   FGGB_BIND        listen address       (default 127.0.0.1:6699)
//!   FGGB_FRIDA_HOST  frida-server host    (default localhost)
//!   RUST_LOG         tracing filter       (default info)

mod engine;
mod error;
mod http;
mod state;

use std::process::ExitCode;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing_subscriber::EnvFilter;

use crate::engine::{Command, EngineHandle};
use crate::state::AppState;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let bind = std::env::var("FGGB_BIND").unwrap_or_else(|_| "127.0.0.1:6699".to_string());
    let frida_host = std::env::var("FGGB_FRIDA_HOST").unwrap_or_else(|_| "localhost".to_string());

    // Start the single-threaded Frida engine actor and wait for it to connect.
    let EngineHandle { tx, ready_rx, join } = engine::spawn(frida_host.clone());
    match ready_rx.await {
        Ok(Ok(())) => tracing::info!("frida engine connected to '{frida_host}'"),
        Ok(Err(err)) => {
            tracing::error!("{err}");
            return ExitCode::FAILURE;
        }
        Err(_) => {
            tracing::error!("frida engine thread exited during startup");
            return ExitCode::FAILURE;
        }
    }

    let app = http::build_router(AppState { tx: tx.clone() });

    let listener = match TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!("failed to bind {bind}: {err}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!("FGGB listening on http://{bind}");

    let served = axum::serve(listener, app)
        .with_graceful_shutdown(http::shutdown_signal())
        .await;
    if let Err(err) = served {
        tracing::error!("server error: {err}");
        return ExitCode::FAILURE;
    }

    // Graceful shutdown: unload + detach every session, then join the actor thread.
    tracing::info!("shutting down: unloading scripts and detaching sessions");
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(Command::Shutdown { reply: reply_tx }).await.is_ok() {
        let _ = reply_rx.await;
    }
    let _ = join.join();
    tracing::info!("shutdown complete");
    ExitCode::SUCCESS
}
