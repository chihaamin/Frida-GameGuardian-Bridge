//! Axum request handlers. Each handler builds a [`Command`], sends it to the engine
//! actor, and awaits the `oneshot` reply.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::engine::{Command, SessionId, SessionInfo};
use crate::error::AppError;
use crate::state::AppState;

use super::dto::{InjectResponse, RpcRequest};

/// Whether the client asked for a JSON response (via `Accept` header).
fn accepts_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|accept| accept.contains("application/json"))
        .unwrap_or(false)
}

/// `POST /` and `POST /inject` — inject a script into a target pid.
///
/// Accepts the legacy GG contract (`?pid=<pid>&GG=<pkg>` with the body as raw Frida JS)
/// as well as the new form. Returns JSON `{session_id,pid,package}` when the client
/// sends `?format=json` or `Accept: application/json`; otherwise a `text/plain` body
/// containing just the session id (so `gg.makeRequest`, which reads the body as an
/// opaque string and branches on the 200 status, keeps working).
pub async fn inject(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let pid: u32 = params
        .get("pid")
        .and_then(|value| value.trim().parse().ok())
        .ok_or(AppError::NoPid)?;
    if body.trim().is_empty() {
        return Err(AppError::NoScript);
    }
    let name = params.get("name").cloned();

    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .tx
        .send(Command::Inject { pid, source: body, name, reply: reply_tx })
        .await
        .map_err(|_| AppError::EngineGone)?;
    let outcome = reply_rx.await.map_err(|_| AppError::EngineGone)??;

    let wants_json =
        params.get("format").map(|f| f == "json").unwrap_or(false) || accepts_json(&headers);

    if wants_json {
        Ok(Json(InjectResponse {
            session_id: outcome.id.0,
            pid: outcome.pid,
            package: outcome.package,
        })
        .into_response())
    } else {
        Ok((StatusCode::OK, outcome.id.0.to_string()).into_response())
    }
}

/// `GET /messages/{id}` — drain and return the session's buffered messages.
pub async fn messages(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<Vec<Value>>, AppError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .tx
        .send(Command::DrainMessages { id: SessionId(id), reply: reply_tx })
        .await
        .map_err(|_| AppError::EngineGone)?;
    let messages = reply_rx.await.map_err(|_| AppError::EngineGone)??;
    Ok(Json(messages))
}

/// `POST /rpc/{id}` — call `rpc.exports.<function>(args...)` and return its result.
pub async fn rpc(
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(request): Json<RpcRequest>,
) -> Result<Json<Value>, AppError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .tx
        .send(Command::Rpc {
            id: SessionId(id),
            function: request.function,
            args: request.args,
            reply: reply_tx,
        })
        .await
        .map_err(|_| AppError::EngineGone)?;
    let result = reply_rx.await.map_err(|_| AppError::EngineGone)??;
    Ok(Json(result.unwrap_or(Value::Null)))
}

/// `GET /exports/{id}` — list the session's rpc export names.
pub async fn exports(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<Vec<String>>, AppError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .tx
        .send(Command::ListExports { id: SessionId(id), reply: reply_tx })
        .await
        .map_err(|_| AppError::EngineGone)?;
    let names = reply_rx.await.map_err(|_| AppError::EngineGone)??;
    Ok(Json(names))
}

/// `DELETE /session/{id}` — unload + detach a session.
pub async fn kill(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<Value>, AppError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .tx
        .send(Command::Kill { id: SessionId(id), reply: reply_tx })
        .await
        .map_err(|_| AppError::EngineGone)?;
    reply_rx.await.map_err(|_| AppError::EngineGone)??;
    Ok(Json(json!({ "status": "killed", "session_id": id })))
}

/// `GET /sessions` — list all live sessions.
pub async fn sessions(State(state): State<AppState>) -> Result<Json<Vec<SessionInfo>>, AppError> {
    let list = list_sessions(&state).await?;
    Ok(Json(list))
}

/// `GET /health` — liveness + frida version + session count.
pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let sessions = list_sessions(&state).await.map(|l| l.len()).unwrap_or(0);
    Json(json!({
        "status": "ok",
        "frida": frida::Frida::version(),
        "sessions": sessions,
    }))
}

async fn list_sessions(state: &AppState) -> Result<Vec<SessionInfo>, AppError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .tx
        .send(Command::ListSessions { reply: reply_tx })
        .await
        .map_err(|_| AppError::EngineGone)?;
    reply_rx.await.map_err(|_| AppError::EngineGone)
}
