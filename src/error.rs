//! HTTP-facing error type. Maps engine/channel failures to status codes + a JSON body.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::engine::EngineError;

/// Error returned by HTTP handlers.
#[derive(Debug)]
pub enum AppError {
    /// Request body was empty.
    NoScript,
    /// `pid` query parameter missing or unparseable.
    NoPid,
    /// The engine actor thread is gone or unresponsive.
    EngineGone,
    /// Referenced session id does not exist.
    UnknownSession(u64),
    /// Any other engine-side failure.
    Engine(EngineError),
}

impl From<EngineError> for AppError {
    fn from(error: EngineError) -> Self {
        match error {
            EngineError::UnknownSession(id) => AppError::UnknownSession(id),
            other => AppError::Engine(other),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::NoScript => (StatusCode::BAD_REQUEST, "no script provided".to_string()),
            AppError::NoPid => (StatusCode::BAD_REQUEST, "no pid provided".to_string()),
            AppError::EngineGone => (
                StatusCode::SERVICE_UNAVAILABLE,
                "frida engine unavailable".to_string(),
            ),
            AppError::UnknownSession(id) => {
                (StatusCode::NOT_FOUND, format!("no session with id {id}"))
            }
            AppError::Engine(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
