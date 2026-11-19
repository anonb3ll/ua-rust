//! Inbox: pending approvals, live one-shot passes and expired passes.

use askama::Template;
use askama_web::WebTemplate;
use axum::Form;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Outcome, PageCtx, Ui, list, non_empty, outcome, pretty, redirect, render, text};

#[derive(Debug, Clone)]
pub struct ApprovalView {
    pub id: i64,
    pub tool: String,
    pub requested_by: String,
    pub created_at: String,
    pub resolved_by: String,
    pub resolved_at: String,
    pub expires_at: String,
    pub payload: String,
}

impl ApprovalView {
    fn from(v: &Value) -> Self {
        Self {
            id: super::int(v, "id"),
            tool: text(v, "tool"),
            requested_by: text(v, "requested_by"),
            created_at: text(v, "created_at"),
            resolved_by: text(v, "resolved_by"),
            resolved_at: text(v, "resolved_at"),
            expires_at: text(v, "expires_at"),
            payload: pretty(v.get("payload").unwrap_or(&Value::Null)),
        }
    }
}

pub struct Queue {
    pub pending: Vec<ApprovalView>,
    pub live: Vec<ApprovalView>,
    pub expired: Vec<ApprovalView>,
    pub gated_tools: Vec<String>,
    pub ttl_hours: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/inbox.html")]
pub struct InboxPage {
    pub page: PageCtx,
    pub queue: Result<Queue, String>,
}

async fn build(ui: &Ui, error: Option<String>) -> InboxPage {
    let queue = ui.read("approval_pending", json!({ "newest_expired": true })).await.map(|v| {
        let rows = |k: &str| list(&v, k).iter().map(ApprovalView::from).collect::<Vec<_>>();
        let mut expired = rows("expired_passes");
        expired.reverse();
        Queue {
            pending: rows("pending"),
            live: rows("approved_unconsumed"),
            expired,
            gated_tools: list(&v, "gated_tools").iter().filter_map(|t| t.as_str().map(str::to_string)).collect(),
            ttl_hours: text(&v, "pass_ttl_hours"),
        }
    });
    InboxPage { page: ui.page("inbox", "Inbox", error), queue }
}

pub async fn page(ui: Ui) -> InboxPage {
    build(&ui, None).await
}

#[derive(Debug, Deserialize)]
pub struct ResolveForm {
    pub decision: String,
    pub reason: Option<String>,
}

pub async fn resolve(ui: Ui, Path(id): Path<i64>, Form(f): Form<ResolveForm>) -> Response {
    let flash = match f.decision.as_str() {
        "approve" => "approved",
        "deny" => "denied",
        "revoke" => "revoked",
        _ => {
            let page = build(&ui, Some("decision must be approve, deny or revoke".into())).await;
            return render(StatusCode::BAD_REQUEST, page);
        }
    };
    let mut args = json!({ "id": id, "decision": f.decision });
    if let Some(r) = non_empty(&f.reason) {
        args["reason"] = json!(r);
    }
    match outcome("approval_resolve", ui.call("approval_resolve", args).await) {
        Outcome::Done(_) => redirect("/ui/inbox", flash, None),
        Outcome::Parked(a) => redirect("/ui/inbox", "parked", Some(a)),
        Outcome::Failed(status, msg) => render(status, build(&ui, Some(msg)).await),
    }
}
