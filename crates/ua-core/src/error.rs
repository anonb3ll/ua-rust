//! The error type returned by every tool and domain operation.

use serde::Serialize;
use serde_json::{Value, json};

/// Result alias used across the workspace.
pub type UaResult<T> = Result<T, UaError>;

/// An error a tool call can end with. Each variant maps to a stable `code`
/// string that clients can branch on.
#[derive(Debug, thiserror::Error)]
pub enum UaError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("denied: {reason}")]
    Denied { reason: String, reason_code: String },
    #[error("approval required for {tool} (approval id {approval_id})")]
    ApprovalRequired { tool: String, approval_id: i64 },
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("unauthenticated: {0}")]
    Unauthenticated(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl UaError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::InvalidArgument(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn denied(reason_code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Denied { reason: reason.into(), reason_code: reason_code.into() }
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidArgument(_) => "invalid_argument",
            Self::NotFound(_) => "not_found",
            Self::Denied { .. } => "denied",
            Self::ApprovalRequired { .. } => "approval_required",
            Self::Conflict(_) => "conflict",
            Self::Unauthenticated(_) => "unauthenticated",
            Self::Internal(_) => "internal",
        }
    }

    /// The JSON body sent to clients. Internal details are not echoed.
    pub fn to_json(&self) -> Value {
        let mut body = json!({ "ok": false, "error": self.code(), "message": self.to_string() });
        match self {
            Self::Denied { reason_code, .. } => body["reason_code"] = json!(reason_code),
            Self::ApprovalRequired { approval_id, tool } => {
                body["approval_id"] = json!(approval_id);
                body["tool"] = json!(tool);
                body["status"] = json!("pending");
            }
            Self::Internal(_) => body["message"] = json!("internal error"),
            _ => {}
        }
        body
    }
}

impl From<serde_json::Error> for UaError {
    fn from(e: serde_json::Error) -> Self {
        Self::InvalidArgument(e.to_string())
    }
}

impl From<anyhow::Error> for UaError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(format!("{e:#}"))
    }
}

#[cfg(feature = "rusqlite")]
impl From<rusqlite::Error> for UaError {
    fn from(e: rusqlite::Error) -> Self {
        use rusqlite::ErrorCode;
        match &e {
            rusqlite::Error::QueryReturnedNoRows => Self::NotFound("no such row".into()),
            rusqlite::Error::SqliteFailure(f, msg) if f.code == ErrorCode::ConstraintViolation => {
                Self::Conflict(msg.clone().unwrap_or_else(|| "constraint violation".into()))
            }
            _ => Self::Internal(e.to_string()),
        }
    }
}

/// Wire shape of an error, for documentation and schema generation.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub ok: bool,
    pub error: String,
    pub message: String,
}
