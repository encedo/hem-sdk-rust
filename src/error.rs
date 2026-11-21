//! The one error type of the SDK, with the same `code` strings as hem-sdk-js,
//! so a caller can tell the cases apart the same way in both languages.

use serde_json::Value;

/// Every failure the SDK reports.
///
/// `code` is the machine-readable part and matches hem-sdk-js:
/// `http_<status>` for a non-2xx answer (with `status` and the parsed body in
/// `data`), `timeout`, `network`, `invalid_arg` (caught before any request),
/// `bad_mode` (a key mode that does not fit the type), `auth_failed`,
/// `auth_password_required`, `checkin_error`, `broker_error`, `sign_error`,
/// `bad_response`.
///
/// There is no `aborted`: in Rust a request is cancelled by dropping its future.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct HemError {
    pub code: String,
    pub status: u16,
    pub data: Option<Value>,
    message: String,
}

impl HemError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { code: code.into(), status: 0, data: None, message: message.into() }
    }

    pub(crate) fn http(status: u16, data: Option<Value>, message: String) -> Self {
        Self { code: format!("http_{status}"), status, data, message }
    }

    pub(crate) fn invalid_arg(message: impl Into<String>) -> Self {
        Self::new("invalid_arg", message)
    }
}

pub type Result<T> = std::result::Result<T, HemError>;
