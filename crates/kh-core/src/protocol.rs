//! Messages between `kh` (MCP shim / run / scan) and the KeyHolder app over the local pipe.
//! Newline-delimited JSON, one message per line.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u32 = 1;
/// Upper bound for one line (check_leak may carry up to 1 MB of text).
pub const MAX_LINE: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    Hello {
        protocol: u32,
        /// Client token (KH_TOKEN). Not needed for `kh run --ticket`.
        token: Option<String>,
        /// "mcp" | "run" | "scan" | "status"
        purpose: String,
        pid: u32,
    },
    /// Name/version from the MCP `initialize` request; informational only.
    ClientInfo { name: String, version: String },
    Request { id: u64, method: String, params: Value },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Welcome { session: String, client: Option<String>, app_version: String },
    Response { id: u64, ok: bool, result: Value, error: Option<String> },
    /// Interface channel only: something the UI shows has changed.
    Event { what: String },
    Fatal { message: String },
}

/// Method names on the pipe. MCP tools map 1:1 onto these.
pub mod methods {
    pub const LIST_SECRETS: &str = "list_secrets";
    pub const REQUEST_GRANT: &str = "request_grant";
    pub const MY_GRANTS: &str = "my_grants";
    pub const GET_SECRET: &str = "get_secret";
    pub const PREPARE_RUN: &str = "prepare_run";
    pub const REPORT_LEAK: &str = "report_leak";
    pub const CHECK_LEAK: &str = "check_leak";
    pub const REDEEM_TICKET: &str = "redeem_ticket";
    pub const STATUS: &str = "status";
}
