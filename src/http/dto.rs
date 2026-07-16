//! Request/response bodies for the JSON endpoints.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Body of `POST /rpc/{id}`.
#[derive(Deserialize)]
pub struct RpcRequest {
    /// The rpc export name to invoke.
    pub function: String,
    /// A JSON array of arguments (or `null`/absent for none).
    #[serde(default)]
    pub args: Option<Value>,
}

/// JSON body returned by the inject endpoints when JSON is requested.
#[derive(Serialize)]
pub struct InjectResponse {
    pub session_id: u64,
    pub pid: u32,
    pub package: Option<String>,
}
