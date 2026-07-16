//! FGGB — Frida GameGuardian Bridge (resident controller).
//!
//! Runs on the device (as root, via frida-server). It discovers GameGuardian, injects
//! the `frida` bridge agent into its process — registering a `frida` global into GG's
//! embedded LuaJ so GG scripts can call `frida.*` — and keeps it injected, re-injecting
//! whenever GG restarts.
//!
//! Config via env vars:
//!   FGGB_GG_PACKAGE  override GG package (default: auto-discover via version.gg marker)
//!   FGGB_POLL_SECS   watchdog interval   (default 3)
//!   RUST_LOG         tracing filter      (default info)

mod engine;
mod gg;

use std::process::ExitCode;
use std::time::Duration;

use tokio::sync::oneshot;
use tracing_subscriber::EnvFilter;

use crate::engine::{Command, EngineHandle, SessionId};

/// The bridge agent, compiled into the binary.
const BRIDGE_JS: &str = include_str!("agent/bridge.js");

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let poll = Duration::from_secs(
        std::env::var("FGGB_POLL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3),
    );

    // Start the single-threaded Frida engine actor and wait for it to open the device.
    let EngineHandle { tx, ready_rx, join } = engine::spawn();
    match ready_rx.await {
        Ok(Ok(())) => tracing::info!("frida local device ready"),
        Ok(Err(err)) => {
            tracing::error!("{err}");
            return ExitCode::FAILURE;
        }
        Err(_) => {
            tracing::error!("engine thread exited during startup");
            return ExitCode::FAILURE;
        }
    }

    tracing::info!("FGGB resident controller running; watching for GameGuardian");

    // Watchdog: keep the `frida` bridge injected into GG, re-injecting on (re)start.
    let mut injected: Option<(u32, SessionId)> = None;
    let mut ticker = tokio::time::interval(poll);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            _ = ticker.tick() => {
                let Some(package) = gg::find_package() else {
                    if injected.take().is_some() { tracing::warn!("GameGuardian no longer found"); }
                    continue;
                };
                let Some(pid) = gg::find_pid(&package) else {
                    if injected.take().is_some() { tracing::info!("{package} not running"); }
                    continue;
                };

                match injected {
                    // Already injected into this exact process: drain any bridge messages.
                    Some((p, sid)) if p == pid => {
                        for msg in drain(&tx, sid).await { tracing::info!("bridge: {msg}"); }
                    }
                    // New or restarted GG: inject the bridge.
                    _ => {
                        let ver = gg::version(&package).unwrap_or_else(|| "?".into());
                        match inject_bridge(&tx, pid).await {
                            Ok(sid) => {
                                tracing::info!("injected frida bridge into {package} (v{ver}) pid {pid}");
                                injected = Some((pid, sid));
                            }
                            Err(e) => tracing::warn!("inject into pid {pid} failed: {e}"),
                        }
                    }
                }
            }
        }
    }

    // Graceful shutdown: unload + detach every session, then join the actor thread.
    tracing::info!("shutting down");
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(Command::Shutdown { reply: reply_tx }).await.is_ok() {
        let _ = reply_rx.await;
    }
    let _ = join.join();
    ExitCode::SUCCESS
}

/// Inject the bridge agent into `pid`, returning the live session id.
async fn inject_bridge(
    tx: &tokio::sync::mpsc::Sender<Command>,
    pid: u32,
) -> Result<SessionId, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(Command::Inject {
        pid,
        source: BRIDGE_JS.to_string(),
        name: Some("fggb-bridge".into()),
        reply: reply_tx,
    })
    .await
    .map_err(|_| "engine gone".to_string())?;
    match reply_rx.await {
        Ok(Ok(outcome)) => Ok(outcome.id),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("engine reply lost".to_string()),
    }
}

/// Drain buffered bridge messages for a session (best effort).
async fn drain(
    tx: &tokio::sync::mpsc::Sender<Command>,
    id: SessionId,
) -> Vec<String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(Command::DrainMessages { id, reply: reply_tx }).await.is_err() {
        return Vec::new();
    }
    match reply_rx.await {
        Ok(Ok(values)) => values.into_iter().map(|v| v.to_string()).collect(),
        _ => Vec::new(),
    }
}
