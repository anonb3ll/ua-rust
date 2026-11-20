//! Server-rendered Control Center at `/ui`.
//!
//! Pages are askama templates (`templates/ui/`), interactivity is htmx with
//! its SSE extension, and the static files are embedded with memory-serve.
//! Every read and write goes through [`ua_tools::Registry::call`] with the
//! request's caller (transport `ui`), so profiles, policy, the approval gate
//! and the ledger apply exactly as they do for MCP. Two reads have no tool
//! yet and use a read-only query: one task row (task detail) and the ledger's
//! highest sequence number (activity backfill); both check the caller's
//! profile allows the matching list tool first.
//!
//! State-changing requests need the CSRF token ([`csrf`]). Actions answer
//! with `303 See Other` back to the page plus a fixed flash code; a refused
//! action re-renders the page with the error and the refusal's status.

pub mod csrf;

mod activity;
mod coord;
mod inbox;
mod memory;
mod work;

use std::collections::HashMap;

use axum::Router;
use axum::extract::{FromRequestParts, Query};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde_json::{Map, Value, json};
use ua_core::identity::Transport;
use ua_core::{Caller, UaError, UaResult};

use crate::AppState;
use crate::auth::{AuthIdentity, caller_for, session_key};

/// Every `/ui` route, with the CSRF middleware and the embedded assets.
pub fn routes() -> Router<AppState> {
    let assets = memory_serve::load!().index_file(None).into_router();
    Router::new()
        .route("/ui", get(|| async { Redirect::to("/ui/inbox") }))
        .route("/ui/", get(|| async { Redirect::to("/ui/inbox") }))
        .route("/ui/inbox", get(inbox::page))
        .route("/ui/approvals/{id}/resolve", post(inbox::resolve))
        .route("/ui/work", get(work::board))
        .route("/ui/tasks", post(work::create))
        .route("/ui/tasks/{id}", get(work::detail))
        .route("/ui/tasks/{id}/update", post(work::update))
        .route("/ui/tasks/{id}/note", post(work::note))
        .route("/ui/tasks/{id}/comments", post(work::comment))
        .route("/ui/tasks/{id}/dependencies", post(work::dependency_add))
        .route("/ui/tasks/{id}/dependencies/{dep}/remove", post(work::dependency_remove))
        .route("/ui/plans", get(coord::plans))
        .route("/ui/plans/{id}", get(coord::plan))
        .route("/ui/delegations/{id}", get(coord::delegation))
        .route("/ui/agents", get(coord::agents))
        .route("/ui/messages", get(coord::messages))
        .route("/ui/memory", get(memory::search))
        .route("/ui/memory/{id}", get(memory::note))
        .route("/ui/activity", get(activity::page))
        .route("/ui/activity/stream", get(activity::stream))
        .nest("/ui/static", assets)
        .layer(axum::middleware::from_fn(csrf::protect))
}

/// What the shared layout needs on every page.
#[derive(Debug, Clone)]
pub struct PageCtx {
    pub nav: &'static str,
    pub title: String,
    pub who: String,
    pub verified: bool,
    pub kind: String,
    pub profile: String,
    pub csrf: String,
    pub flash: Option<String>,
    pub error: Option<String>,
}

/// The per-request UI context: the governed caller plus layout data.
pub struct Ui {
    pub state: AppState,
    pub caller: Caller,
    pub verified: bool,
    pub csrf: String,
    pub flash: Option<String>,
}

impl FromRequestParts<AppState> for Ui {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        // Fail closed: the auth layer always sets the identity. If a router
        // change ever drops that layer, refuse rather than run as anonymous.
        let Some(id) = parts.extensions.get::<AuthIdentity>().cloned() else {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "identity layer missing").into_response());
        };
        let csrf = parts
            .extensions
            .get::<csrf::CsrfToken>()
            .map(|t| t.0.clone())
            .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "csrf layer missing").into_response())?;
        let caller = caller_for(state, &id, session_key(&parts.headers), Transport::Ui);
        let q: HashMap<String, String> =
            Query::try_from_uri(&parts.uri).map(|Query(q)| q).unwrap_or_default();
        let approval = q.get("approval").and_then(|a| a.parse::<i64>().ok());
        let flash = q.get("flash").and_then(|f| flash_text(f, approval));
        Ok(Self { state: state.clone(), caller, verified: id.verified, csrf, flash })
    }
}

impl Ui {
    /// Call a tool as this request's caller.
    pub async fn call(&self, tool: &str, args: Value) -> UaResult<Value> {
        self.state.registry.call(&self.state.hub, &self.caller, tool, args).await
    }

    /// A read that composes a page: [`Ui::call`] inside
    /// [`ua_tools::registry::page_reads`], so a successful read-only tool
    /// leaves no `tool_calls` row.
    pub async fn call_read(&self, tool: &str, args: Value) -> UaResult<Value> {
        ua_tools::registry::page_reads(self.call(tool, args)).await
    }

    /// Like [`Ui::call_read`], with the error flattened to display text.
    pub async fn read(&self, tool: &str, args: Value) -> Result<Value, String> {
        self.call_read(tool, args).await.map_err(|e| describe(tool, &e))
    }

    /// Whether the caller's profile exposes `tool` (for direct reads).
    pub fn may(&self, tool: &str) -> bool {
        !self.caller.enforce_profile || self.caller.profile.allows_tool(tool)
    }

    pub fn page(&self, nav: &'static str, title: impl Into<String>, error: Option<String>) -> PageCtx {
        PageCtx {
            nav,
            title: title.into(),
            who: self.caller.label.clone(),
            verified: self.verified,
            kind: serde_json::to_value(self.caller.kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
            profile: self.caller.profile.as_str().to_string(),
            csrf: self.csrf.clone(),
            flash: self.flash.clone(),
            error,
        }
    }
}

/// Fixed flash messages. Only these codes render, so a crafted link cannot
/// put arbitrary text on the page.
fn flash_text(code: &str, approval: Option<i64>) -> Option<String> {
    let text = match code {
        "approved" => "Approved. The requester can retry the call once.",
        "denied" => "Denied.",
        "revoked" => "Pass revoked.",
        "task_created" => "Task created.",
        "task_updated" => "Task updated.",
        "note_added" => "Note appended.",
        "comment_added" => "Comment added.",
        "dependency_added" => "Dependency added.",
        "dependency_removed" => "Dependency removed.",
        "parked" => {
            return Some(match approval {
                Some(id) => {
                    format!("This change needs a human approval: approval #{id} is pending in the Inbox.")
                }
                None => "This change needs a human approval; it is pending in the Inbox.".into(),
            });
        }
        _ => return None,
    };
    Some(text.to_string())
}

/// One line describing a refused call.
pub fn describe(tool: &str, e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, reason } if reason_code == "profile_denied" => {
            format!("{tool} is not available to your profile ({reason})")
        }
        other => other.to_string(),
    }
}

/// The result of a write through the registry.
pub enum Outcome {
    Done(Value),
    Parked(i64),
    Failed(StatusCode, String),
}

pub fn outcome(tool: &str, r: UaResult<Value>) -> Outcome {
    match r {
        Ok(v) => Outcome::Done(v),
        Err(UaError::ApprovalRequired { approval_id, .. }) => Outcome::Parked(approval_id),
        Err(e) => Outcome::Failed(crate::api::status_for(&e), describe(tool, &e)),
    }
}

/// `303 See Other` to `path` with a flash code.
pub fn redirect(path: &str, flash: &str, approval: Option<i64>) -> Response {
    let sep = if path.contains('?') { '&' } else { '?' };
    let mut loc = format!("{path}{sep}flash={flash}");
    if let Some(a) = approval {
        loc.push_str(&format!("&approval={a}"));
    }
    (StatusCode::SEE_OTHER, [(header::LOCATION, loc)]).into_response()
}

/// Render a template with a status code.
pub fn render(status: StatusCode, tpl: impl IntoResponse) -> Response {
    (status, tpl).into_response()
}

// ---------------------------------------------------------------------------
// JSON helpers for view models.

/// A field as display text: strings as-is, numbers and booleans printed,
/// null and missing as empty.
pub fn text(v: &Value, key: &str) -> String {
    match v.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

pub fn int(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(Value::as_i64).unwrap_or_default()
}

pub fn list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default()
}

/// Shorten long text for a list cell.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

const SECRET_HINTS: [&str; 8] =
    ["token", "secret", "password", "passwd", "api_key", "apikey", "authorization", "cookie"];

/// Replace values under secret-shaped keys with a marker, at any depth.
pub fn redact(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, val) in m {
                let lk = k.to_ascii_lowercase();
                if SECRET_HINTS.iter().any(|h| lk.contains(h)) {
                    out.insert(k.clone(), json!("[redacted]"));
                } else {
                    out.insert(k.clone(), redact(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(redact).collect()),
        other => other.clone(),
    }
}

/// Pretty, redacted JSON for display.
pub fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(&redact(v)).unwrap_or_default()
}

/// Treat an empty form field as absent.
pub fn non_empty(s: &Option<String>) -> Option<String> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_hides_secret_keys_at_depth() {
        let v = json!({"a": 1, "nested": {"api_key": "x", "list": [{"Token": "y"}]}});
        let r = redact(&v);
        assert_eq!(r["nested"]["api_key"], "[redacted]");
        assert_eq!(r["nested"]["list"][0]["Token"], "[redacted]");
        assert_eq!(r["a"], 1);
    }

    #[test]
    fn unknown_flash_codes_render_nothing() {
        assert!(flash_text("<script>", None).is_none());
        assert!(flash_text("parked", Some(4)).unwrap().contains("#4"));
    }
}
