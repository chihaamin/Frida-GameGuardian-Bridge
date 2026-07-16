//! HTTP layer: the Axum router and the shutdown signal.

pub mod dto;
pub mod routes;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::state::AppState;

/// Build the application router. Route path params use Axum 0.8 `{id}` syntax.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Inject (legacy `?pid=&GG=` + body, and the new form) on both `/` and `/inject`.
        .route("/", post(routes::inject))
        .route("/inject", post(routes::inject))
        // Per-session interaction.
        .route("/messages/{id}", get(routes::messages))
        .route("/rpc/{id}", post(routes::rpc))
        .route("/exports/{id}", get(routes::exports))
        .route("/session/{id}", delete(routes::kill))
        // Introspection.
        .route("/sessions", get(routes::sessions))
        .route("/health", get(routes::health))
        .with_state(state)
}

/// Completes on Ctrl-C, driving Axum's graceful shutdown.
pub async fn shutdown_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::error!("failed to listen for ctrl_c: {err}");
    }
}
