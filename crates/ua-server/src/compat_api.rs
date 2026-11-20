//! Compatibility API: the Control Center routes the TypeScript SDK
//! (`ControlCenterClient`) calls, with the request and response shapes of the
//! Python hub, mapped onto registered tools.
//!
//! | Route | Tool |
//! |---|---|
//! | `GET  /api/tasks` | `task_list` (active queue, optional `completed_after`) |
//! | `POST /api/tasks` | `task_add` |
//! | `POST /api/action/task` | `task_update` |
//! | `POST /api/action/approval` | `approval_resolve` (verified human only) |
//! | `GET  /api/approvals` | `approval_pending` |
//! | `GET  /api/approvals/{id}` | one approval row (read-only, gated on `approval_pending`) |
//! | `POST /api/approvals/request` | the approval gate, request-only |
//! | `GET  /api/sessions` | `session_list` |
//! | `GET  /api/capability-catalog` | the registry, grouped by family |
//! | `GET  /api/board` | `task_list`, `dependency_list`, `delegate_list` |
//!
//! `/api/nodes/*` (node acceptance and discovered sessions) is not built yet
//! and answers `501` with `{"error": "not_implemented", "capability": ...}`.
//! `GET /api/nodes` itself is served by [`crate::node_api`]; runs, platform
//! objects, evidence and work products by [`crate::platform_api`].
//!
//! Writes go through [`ua_tools::Registry::call`] with the request's caller,
//! except `/api/approvals/request`: it queues a request without running or
//! consuming anything, which no tool does, so it evaluates
//! [`ua_tools::approvals::gate`] directly in one write transaction after the
//! same profile check the Python route makes.

use std::collections::{BTreeMap, HashMap};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Extension, Json, Router};
use rusqlite::{OptionalExtension, params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::identity::Transport;
use ua_core::{ActorKind, Caller, UaError};
use ua_tools::approvals::{self, GateOutcome};

use crate::AppState;
use crate::api::status_for;
use crate::auth::{AuthIdentity, caller_for, session_key};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/tasks", get(tasks).post(task_create))
        .route("/api/action/task", post(action_task))
        .route("/api/action/approval", post(action_approval))
        .route("/api/approvals", get(approvals_list))
        .route("/api/approvals/request", post(approval_request))
        .route("/api/approvals/{id}", get(approval_detail))
        .route("/api/sessions", get(sessions))
        .route("/api/capability-catalog", get(capability_catalog))
        .route("/api/board", get(board))
        .route("/api/nodes/{*rest}", any(|| async { not_built("nodes", "discovered native sessions") }))
}

pub(crate) fn not_built(capability: &str, what: &str) -> Response {
    let body = json!({
        "error": "not_implemented",
        "capability": capability,
        "message": format!("{what} is not built in this hub yet"),
    });
    (StatusCode::NOT_IMPLEMENTED, Json(body)).into_response()
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

pub(crate) fn tool_err(e: &UaError) -> Response {
    let mut body = json!({ "error": e.to_string(), "code": e.code() });
    if let UaError::Denied { reason_code, .. } = e {
        body["reason_code"] = json!(reason_code);
    }
    if let UaError::Internal(_) = e {
        body["error"] = json!("internal error");
    }
    (status_for(e), Json(body)).into_response()
}

pub(crate) fn pending(approval_id: i64, tool: &str, payload: Value) -> Response {
    let body = json!({
        "approval_id": approval_id,
        "code": "approval_required",
        "status": "pending",
        "tool": tool,
        "payload": payload,
    });
    (StatusCode::ACCEPTED, Json(body)).into_response()
}

fn caller(state: &AppState, id: &AuthIdentity, headers: &HeaderMap) -> Caller {
    caller_for(state, id, session_key(headers), Transport::Http)
}

/// Parse a JSON object body the way the Python routes do.
pub(crate) fn object_body(body: &Bytes) -> Result<Map<String, Value>, Box<Response>> {
    let v: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(body).map_err(|_| Box::new(err(StatusCode::BAD_REQUEST, "invalid JSON")))?
    };
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(Box::new(err(StatusCode::BAD_REQUEST, "request body must be a JSON object"))),
    }
}

fn may(caller: &Caller, tool: &str) -> bool {
    !caller.enforce_profile || caller.profile.allows_tool(tool)
}

/// The one "is this a human approver" rule for the compatibility API: a
/// verified identity of kind human. `approval_detail` reports what
/// `action_approval` will actually allow, so both use this.
fn is_human(id: &AuthIdentity) -> bool {
    id.verified && id.kind == ActorKind::Human
}

/// Normalize an ISO 8601 date or datetime to the stored UTC form. A value
/// without an offset is read as UTC.
fn normalize_ts(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let candidate = if raw.len() == 10 {
        format!("{raw}T00:00:00Z")
    } else if raw.ends_with('Z') || raw.contains('+') || raw.get(10..).is_some_and(|t| t.contains('-')) {
        raw.to_string()
    } else {
        format!("{raw}Z")
    };
    ua_core::time::parse_ts(&candidate).map(ua_core::time::format_ts)
}

fn now_s() -> i64 {
    ua_core::time::now_ms() / 1000
}

fn ts_s(raw: Option<&str>) -> Option<i64> {
    raw.and_then(ua_core::time::parse_ts).map(|t| t.as_second())
}

fn ts_from_s(s: i64) -> String {
    jiff::Timestamp::from_second(s).map(ua_core::time::format_ts).unwrap_or_default()
}

/// Every task of one status, paging through `task_list`.
async fn all_tasks(
    state: &AppState,
    caller: &Caller,
    status: &str,
    extra: &Map<String, Value>,
) -> (Vec<Value>, Option<String>, bool) {
    const PAGE: i64 = 500;
    const MAX_PAGES: usize = 20;
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut args = extra.clone();
        args.insert("status".into(), json!(status));
        args.insert("fields".into(), json!("compact"));
        args.insert("limit".into(), json!(PAGE));
        if let Some(c) = &cursor {
            args.insert("cursor".into(), json!(c));
        }
        match state.registry.call(&state.hub, caller, "task_list", Value::Object(args)).await {
            Ok(v) => {
                out.extend(v.get("tasks").and_then(Value::as_array).cloned().unwrap_or_default());
                cursor = v.get("next_cursor").and_then(Value::as_str).map(str::to_string);
                if cursor.is_none() {
                    return (out, None, false);
                }
            }
            Err(e) => return (out, Some(e.to_string()), true),
        }
    }
    (out, None, true)
}

const ACTIVE: [&str; 4] = ["open", "doing", "waiting_review", "blocked"];

// ---------------------------------------------------------------------------
// Tasks

async fn tasks(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let caller = caller(&state, &id, &headers);
    let completed_after = match q.get("completed_after") {
        Some(raw) => match normalize_ts(raw) {
            Some(ts) => Some(ts),
            None => {
                return err(StatusCode::BAD_REQUEST, "completed_after must be an ISO 8601 date or datetime");
            }
        },
        None => None,
    };
    let project = q.get("project").filter(|p| !p.is_empty()).cloned();
    let mut all = Vec::new();
    let mut errors = Vec::new();
    let mut truncated = false;
    for status in ACTIVE {
        let (rows, e, t) = all_tasks(&state, &caller, status, &Map::new()).await;
        all.extend(rows);
        errors.extend(e);
        truncated |= t;
    }
    let mut projects: BTreeMap<String, i64> = BTreeMap::new();
    for t in &all {
        *projects.entry(t["project"].as_str().unwrap_or("default").to_string()).or_default() += 1;
    }
    let tasks: Vec<&Value> =
        all.iter().filter(|t| project.as_deref().is_none_or(|p| t["project"].as_str() == Some(p))).collect();
    let mut buckets: BTreeMap<String, i64> = BTreeMap::new();
    for t in &tasks {
        *buckets.entry(t["status"].as_str().unwrap_or("unknown").to_string()).or_default() += 1;
    }
    let active: Vec<&Value> = tasks
        .iter()
        .copied()
        .filter(|t| matches!(t["status"].as_str(), Some("doing" | "blocked" | "waiting_review")))
        .collect();
    let mut out = json!({ "buckets": buckets, "active": active, "total": tasks.len(), "projects": projects });
    if let Some(after) = completed_after {
        let mut extra = Map::new();
        extra.insert("completed_after".into(), json!(after));
        if let Some(p) = &project {
            extra.insert("project".into(), json!(p));
        }
        let (done, e, t) = all_tasks(&state, &caller, "done", &extra).await;
        out["completed"] = json!(done);
        out["completed_after"] = json!(after);
        out["completed_truncated"] = json!(t);
        if let Some(e) = e {
            out["completed_error"] = json!(e);
        }
    }
    if !errors.is_empty() {
        out["error"] = json!(errors.join("; "));
        out["truncated"] = json!(true);
    } else if truncated {
        out["truncated"] = json!(true);
    }
    Json(out).into_response()
}

const CREATE_FIELDS: [&str; 11] = [
    "title",
    "notes",
    "priority",
    "parent_id",
    "untrusted",
    "project",
    "domain",
    "due_at",
    "evidence_ref",
    "idempotency_key",
    "lane",
];

async fn task_create(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let mut unknown: Vec<&String> = body.keys().filter(|k| !CREATE_FIELDS.contains(&k.as_str())).collect();
    if !unknown.is_empty() {
        unknown.sort();
        let names: Vec<&str> = unknown.iter().map(|s| s.as_str()).collect();
        return err(StatusCode::BAD_REQUEST, format!("unknown task_add field(s): {}", names.join(", ")));
    }
    if !body.get("title").and_then(Value::as_str).is_some_and(|t| !t.trim().is_empty()) {
        return err(StatusCode::BAD_REQUEST, "title is required");
    }
    if body.get("untrusted").is_some_and(|v| !v.is_boolean()) {
        return err(StatusCode::BAD_REQUEST, "untrusted must be true or false");
    }
    let caller = caller(&state, &id, &headers);
    let args = Value::Object(body);
    match state.registry.call(&state.hub, &caller, "task_add", args.clone()).await {
        Ok(v) => (StatusCode::CREATED, Json(v)).into_response(),
        Err(UaError::ApprovalRequired { approval_id, .. }) => pending(approval_id, "task_add", args),
        Err(e) => tool_err(&e),
    }
}

const UPDATE_FIELDS: [&str; 18] = [
    "status",
    "title",
    "notes",
    "append_note",
    "priority",
    "parent_id",
    "untrusted",
    "worktree",
    "project",
    "expected_project",
    "expected_updated_at",
    "domain",
    "lane",
    "due_at",
    "clear_due_at",
    "evidence_ref",
    "idempotency_key",
    "archived",
];

const TASK_STATUSES: [&str; 6] = ["open", "doing", "waiting_review", "blocked", "done", "cancelled"];

async fn action_task(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut body = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let task_id = match body.remove("id") {
        None | Some(Value::Null) => return err(StatusCode::BAD_REQUEST, "missing task id"),
        Some(Value::Number(n)) if n.as_i64().is_some() => n.as_i64().unwrap_or_default(),
        Some(Value::String(s)) if s.trim().parse::<i64>().is_ok() => {
            s.trim().parse::<i64>().unwrap_or_default()
        }
        Some(_) => return err(StatusCode::BAD_REQUEST, "invalid task id; expected integer"),
    };
    let mut unknown: Vec<&str> =
        body.keys().map(String::as_str).filter(|k| !UPDATE_FIELDS.contains(k)).collect();
    if !unknown.is_empty() {
        unknown.sort();
        let mut allowed = UPDATE_FIELDS.to_vec();
        allowed.sort();
        return err(
            StatusCode::BAD_REQUEST,
            format!("unknown task_update field(s): {}; allowed: {}", unknown.join(", "), allowed.join(", ")),
        );
    }
    for flag in ["archived", "untrusted", "worktree", "clear_due_at"] {
        if body.get(flag).is_some_and(|v| !v.is_null() && !v.is_boolean()) {
            return err(StatusCode::BAD_REQUEST, format!("{flag} must be true or false"));
        }
    }
    // Worktree creation on `doing` is not part of this hub's task_update; an
    // explicit `false` asks for what already happens, `true` cannot be honoured.
    if let Some(Value::Bool(true)) = body.remove("worktree") {
        return err(
            StatusCode::BAD_REQUEST,
            "worktree=true is not supported by this hub; create worktrees with git_worktree_add",
        );
    }
    if let Some(note) = body.get("append_note")
        && !note.as_str().is_some_and(|s| !s.trim().is_empty() && s.chars().count() <= 2000)
    {
        return err(StatusCode::BAD_REQUEST, "append_note must be a non-empty string under 2000 characters");
    }
    if let Some(s) = body.get("status")
        && !s.as_str().is_some_and(|s| TASK_STATUSES.contains(&s))
    {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid task status; expected open, doing, waiting_review, blocked, done, or cancelled",
        );
    }
    let caller = caller(&state, &id, &headers);
    let mut args = body;
    args.insert("id".into(), json!(task_id));
    let args = Value::Object(args);
    match state.registry.call(&state.hub, &caller, "task_update", args.clone()).await {
        Ok(v) => Json(v).into_response(),
        Err(UaError::ApprovalRequired { approval_id, .. }) => pending(approval_id, "task_update", args),
        Err(e) => tool_err(&e),
    }
}

// ---------------------------------------------------------------------------
// Approvals

async fn action_approval(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let mut unknown: Vec<&str> =
        body.keys().map(String::as_str).filter(|k| !["id", "decision", "reason"].contains(k)).collect();
    if !unknown.is_empty() {
        unknown.sort();
        return err(StatusCode::BAD_REQUEST, format!("unknown approval field(s): {}", unknown.join(", ")));
    }
    if !id.verified {
        return err(StatusCode::UNAUTHORIZED, "authenticated identity required");
    }
    if !is_human(&id) {
        return err(StatusCode::FORBIDDEN, "approval resolution requires a human identity");
    }
    let approval_id = match body.get("id") {
        None | Some(Value::Null) => return err(StatusCode::BAD_REQUEST, "missing approval id"),
        Some(v) => match v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())) {
            Some(n) => n,
            None => return err(StatusCode::BAD_REQUEST, "invalid approval id; expected integer"),
        },
    };
    let decision = body.get("decision").and_then(Value::as_str).unwrap_or("approve");
    if !matches!(decision, "approve" | "deny") {
        return err(StatusCode::BAD_REQUEST, "invalid decision; expected approve or deny");
    }
    let reason = match body.get("reason") {
        None | Some(Value::Null) => "via HTTP API".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    };
    let caller = caller(&state, &id, &headers);
    let args = json!({ "id": approval_id, "decision": decision, "reason": reason });
    match state.registry.call(&state.hub, &caller, "approval_resolve", args).await {
        Ok(v) => {
            let mut out = v.get("approval").and_then(Value::as_object).cloned().unwrap_or_default();
            out.insert("ok".into(), json!(true));
            Json(Value::Object(out)).into_response()
        }
        Err(e) => tool_err(&e),
    }
}

fn strip_list_row(row: &Value) -> Value {
    let mut r = row.clone();
    if let Some(m) = r.as_object_mut() {
        m.remove("payload");
        m.remove("reason");
    }
    r
}

/// JSON with a weak ETag over the body; `304` when the client has it.
fn conditional_json(headers: &HeaderMap, v: &Value) -> Response {
    let body = serde_json::to_vec(v).unwrap_or_default();
    let etag = format!("W/\"{}\"", &hex::encode(Sha256::digest(&body))[..32]);
    let matched = headers.get(header::IF_NONE_MATCH).and_then(|h| h.to_str().ok()).is_some_and(|inm| {
        inm.split(',')
            .map(str::trim)
            .any(|c| c == "*" || c.trim_start_matches("W/") == etag.trim_start_matches("W/"))
    });
    let mut resp = if matched {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        ([(header::CONTENT_TYPE, "application/json")], body).into_response()
    };
    if let Ok(v) = HeaderValue::from_str(&etag) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
    resp
}

/// Most expired passes listed; the total is reported alongside.
const EXPIRED_CAP: usize = 50;

async fn approvals_list(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
) -> Response {
    let caller = caller(&state, &id, &headers);
    let v = match state
        .registry
        .call(&state.hub, &caller, "approval_pending", json!({ "newest_expired": true }))
        .await
    {
        Ok(v) => v,
        Err(e) => return tool_err(&e),
    };
    let rows = |k: &str| -> Vec<Value> {
        v.get(k).and_then(Value::as_array).map(|a| a.iter().map(strip_list_row).collect()).unwrap_or_default()
    };
    let mut expired = rows("expired_passes");
    let expired_total = v.get("expired_passes_total").and_then(Value::as_u64).unwrap_or(expired.len() as u64);
    if expired.len() > EXPIRED_CAP {
        expired.drain(..expired.len() - EXPIRED_CAP);
    }
    let out = json!({
        "pending": rows("pending"),
        "approved_unconsumed": rows("approved_unconsumed"),
        "expired_passes_truncated": (expired.len() as u64) < expired_total,
        "expired_passes": expired,
        "expired_passes_total": expired_total,
        "gated_tools": v.get("gated_tools").cloned().unwrap_or(json!([])),
        "pass_ttl_hours": v.get("pass_ttl_hours").cloned().unwrap_or(Value::Null),
    });
    conditional_json(&headers, &out)
}

async fn approval_detail(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let Ok(approval_id) = raw.parse::<i64>() else {
        return err(StatusCode::BAD_REQUEST, "invalid approval id; expected integer");
    };
    let caller = caller(&state, &id, &headers);
    if !may(&caller, "approval_pending") {
        return err(
            StatusCode::FORBIDDEN,
            format!("approval_pending is not available to profile {}", caller.profile),
        );
    }
    let row = match state
        .hub
        .db()
        .read_async(move |c| {
            approvals::get(c, approval_id).map(Some).or_else(|e| match e {
                UaError::NotFound(_) => Ok(None),
                other => Err(other),
            })
        })
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return err(StatusCode::NOT_FOUND, format!("no approval request with id {approval_id}")),
        Err(e) => return tool_err(&e),
    };
    let cfg = state.hub.cfg();
    let ttl_s = (cfg.approval_pass_ttl_hours * 3600.0) as i64;
    let expires = ts_s(row.resolved_at.as_deref()).map(|t| t + ttl_s);
    let pass_state = match row.status.as_str() {
        "approved" if expires.is_some_and(|e| e < now_s()) => "expired",
        "approved" => "live",
        "consumed" => "consumed",
        "expired" => "expired",
        "revoked" => "revoked",
        _ => "none",
    };
    let human = is_human(&id);
    let (may_approve, why) = if row.status != "pending" {
        ("no", format!("approval is {}", row.status))
    } else if !human {
        ("no", "only a human operator can approve".to_string())
    } else if row.requested_by.as_deref() == Some(caller.label.as_str()) {
        ("no", "the approver must differ from the requester".to_string())
    } else if caller.enforce_profile && !caller.profile.allows_tool("approval_resolve") {
        ("no", format!("approval_resolve is not available to profile {}", caller.profile))
    } else {
        ("yes", "you may approve this request".to_string())
    };
    let gated_by_config = cfg.approval_tools.contains(&row.tool);
    let gate = if gated_by_config {
        json!({ "kind": "global_allowlist", "label": "Global allowlist (approval_tools)" })
    } else {
        json!({ "kind": "always_gated", "label": "Tool always needs a human approval" })
    };
    let pr_url = row.payload.get("pr_url").and_then(Value::as_str).map(str::to_string);
    let commit_sha = row.payload.get("commit_sha").and_then(Value::as_str).map(str::to_string);
    let out = json!({
        "id": row.id,
        "tool": row.tool,
        "status": row.status,
        "requested_by": row.requested_by,
        "run_id": row.run_id,
        "resolved_by": row.resolved_by,
        "reason": row.reason,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "resolved_at": row.resolved_at,
        "gate": gate,
        "payload": crate::ui::redact(&row.payload),
        "payload_complete": true,
        "payload_omissions": [],
        "pass": {
            "state": pass_state,
            "expires_at": if row.status == "approved" { expires.map(ts_from_s) } else { None },
        },
        "approver": { "may_approve": may_approve, "reason": why },
        "pr_url": pr_url,
        "commit_sha": commit_sha,
    });
    Json(out).into_response()
}

enum RequestOutcome {
    Pending(i64),
    Approved(i64),
    Denied(i64, Option<String>),
    TooMany,
}

/// Open approval requests one requester may have queued at once.
const MAX_PENDING_PER_REQUESTER: i64 = 20;

async fn approval_request(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !id.verified {
        return err(StatusCode::UNAUTHORIZED, "authenticated identity required");
    }
    let body = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let mut unknown: Vec<&str> =
        body.keys().map(String::as_str).filter(|k| !["tool", "payload"].contains(k)).collect();
    if !unknown.is_empty() {
        unknown.sort();
        return err(
            StatusCode::BAD_REQUEST,
            format!("unknown approval request field(s): {}", unknown.join(", ")),
        );
    }
    let Some(tool) = body.get("tool").and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty()) else {
        return err(StatusCode::BAD_REQUEST, "tool is required");
    };
    let tool = tool.to_string();
    let payload = match body.get("payload") {
        None => json!({}),
        Some(Value::Object(m)) => Value::Object(m.clone()),
        Some(_) => return err(StatusCode::BAD_REQUEST, "payload must be a JSON object"),
    };
    let Some(def) = state.registry.get(&tool) else {
        return err(StatusCode::BAD_REQUEST, format!("unknown tool: {tool}"));
    };
    let caller = caller(&state, &id, &headers);
    if !may(&caller, "approval_pending") {
        return err(StatusCode::FORBIDDEN, "approval requests are not exposed by the active profile");
    }
    // Only for a tool the caller could actually run: no inbox spam for tools
    // its profile hides.
    if !may(&caller, &tool) {
        return err(StatusCode::FORBIDDEN, format!("tool {tool:?} is not available to the active profile"));
    }
    let gated = def.always_gated || state.hub.cfg().approval_tools.contains(&tool);
    if !gated {
        return err(StatusCode::CONFLICT, format!("tool {tool:?} is not configured to require approval"));
    }
    let (hub, c, t, p) = (state.hub.clone(), caller.clone(), tool.clone(), payload.clone());
    let res = state
        .hub
        .db()
        .write_async(move |tx| {
            let cfg = hub.cfg();
            let canon = approvals::canonical_payload(&p);
            let denied: Option<(i64, Option<String>)> = tx
                .query_row(
                    "SELECT id, reason FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
                     AND status = 'denied' ORDER BY id DESC LIMIT 1",
                    params![t, canon, c.label],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((id, reason)) = denied {
                return Ok(RequestOutcome::Denied(id, reason));
            }
            // Bound the human inbox: one requester cannot queue more than
            // MAX_PENDING_PER_REQUESTER open requests.
            let open: i64 = tx.query_row(
                "SELECT COUNT(*) FROM approvals WHERE requested_by = ?1 AND status = 'pending'",
                params![c.label],
                |r| r.get(0),
            )?;
            if open >= MAX_PENDING_PER_REQUESTER {
                return Ok(RequestOutcome::TooMany);
            }
            // A live pass is reported, never consumed: this route runs nothing.
            let ttl_s = (cfg.approval_pass_ttl_hours * 3600.0) as i64;
            let passes: Vec<(i64, Option<String>)> = {
                let mut stmt = tx.prepare(
                    "SELECT id, resolved_at FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
                     AND status = 'approved' ORDER BY id ASC",
                )?;
                stmt.query_map(params![t, canon, c.label], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?
            };
            if let Some((id, _)) =
                passes.iter().find(|(_, at)| ts_s(at.as_deref()).is_some_and(|s| s + ttl_s >= now_s()))
            {
                return Ok(RequestOutcome::Approved(*id));
            }
            match approvals::gate(tx, cfg, &c, &t, &p)? {
                GateOutcome::Pending { approval_id } => Ok(RequestOutcome::Pending(approval_id)),
                GateOutcome::Denied { approval_id, reason } => Ok(RequestOutcome::Denied(approval_id, reason)),
                // Unreachable: live passes were handled above in this transaction.
                GateOutcome::Pass { approval_id } => Ok(RequestOutcome::Approved(approval_id)),
            }
        })
        .await;
    let (status, approval_id, decision, reason) = match res {
        Ok(RequestOutcome::Pending(a)) => (StatusCode::ACCEPTED, a, "pending", None),
        Ok(RequestOutcome::Approved(a)) => (StatusCode::OK, a, "approved", None),
        Ok(RequestOutcome::Denied(a, r)) => (StatusCode::OK, a, "denied", r),
        Ok(RequestOutcome::TooMany) => {
            return err(
                StatusCode::TOO_MANY_REQUESTS,
                format!("{MAX_PENDING_PER_REQUESTER} approval requests are already open for this identity"),
            );
        }
        Err(e) => return tool_err(&e),
    };
    let mut out = json!({ "approval_id": approval_id, "status": decision, "tool": tool, "payload": payload });
    if let Some(r) = reason.filter(|r| !r.is_empty()) {
        out["reason"] = json!(r);
    }
    (status, Json(out)).into_response()
}

// ---------------------------------------------------------------------------
// Sessions and the capability catalog

async fn sessions(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let caller = caller(&state, &id, &headers);
    let mut args =
        json!({ "limit": q.get("limit").and_then(|l| l.parse::<i64>().ok()).unwrap_or(100).clamp(1, 500) });
    if let Some(a) = q.get("agent").filter(|a| !a.is_empty()) {
        args["agent"] = json!(a);
    }
    if let Some(s) = q.get("status").filter(|s| !s.is_empty()) {
        args["status"] = json!(s);
    }
    match state.registry.call(&state.hub, &caller, "session_list", args).await {
        Ok(mut v) => {
            v["can_grant_wake"] = json!(false);
            Json(v).into_response()
        }
        Err(e) => (status_for(&e), Json(json!({ "sessions": [], "error": e.to_string() }))).into_response(),
    }
}

async fn capability_catalog(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
) -> Json<Value> {
    let caller = caller(&state, &id, &headers);
    let mut families: BTreeMap<&str, Vec<&ua_tools::ToolDef>> = BTreeMap::new();
    for t in state.registry.visible_to(&caller) {
        families.entry(t.family).or_default().push(t);
    }
    let items: Vec<Value> = families
        .values()
        .flatten()
        .map(|t| {
            json!({
                "id": t.name,
                "name": t.name,
                "description": t.description,
                "family": t.family,
                "read_only": t.read_only,
                "always_gated": t.always_gated,
                "consumer": "agents",
                "connection_state": "live",
                "implementation_state": "implemented",
                "entry_point": { "kind": "tool", "ref": t.name },
            })
        })
        .collect();
    let family_rows: Vec<Value> = families
        .iter()
        .map(|(f, tools)| {
            json!({
                "id": f,
                "name": f,
                "description": format!("{} tool(s)", tools.len()),
                "connection_state": "live",
                "implementation_state": "implemented",
                "entry_point": { "kind": "family", "ref": f },
                "tools": tools.iter().map(|t| t.name).collect::<Vec<_>>(),
            })
        })
        .collect();
    let total = items.len();
    Json(json!({
        "available": true,
        "status": 200,
        "catalog": {
            "schema_version": "ua-rust.registry.v1",
            "families": family_rows,
            "items": items,
            "queue_coverage": [],
            "traceable_paths": [],
        },
        "manifest": null,
        "meta": {
            "as_of": ua_core::time::now(),
            "source_baseline_sha": "",
            "origin_main_sha": "",
            "live_hub_checked_at": ua_core::time::now(),
            "total_items": total,
            "pilot_families": families.keys().collect::<Vec<_>>(),
            "counts_by_state": { "live": total },
            "counts_by_implementation": { "implemented": total },
            "source": "registry",
        },
    }))
}

// ---------------------------------------------------------------------------
// Board

const BOARD_LABELS: [(&str, &str); 6] = [
    ("open", "Backlog"),
    ("doing", "Doing"),
    ("waiting_review", "Waiting review"),
    ("blocked", "Blocked"),
    ("done", "Done"),
    ("cancelled", "Cancelled"),
];
const DONE_WINDOW_DAYS: i64 = 30;
const AGING_OPEN_DAYS: i64 = 14;
const AGING_DOING_HOURS: i64 = 48;

fn task_card(t: &Value, now: i64, dep_counts: &HashMap<i64, i64>, swimlane_by: &str) -> Value {
    let id = t["id"].as_i64().unwrap_or_default();
    let status = t["status"].as_str().unwrap_or("open");
    let created = ts_s(t["created_at"].as_str());
    let mut alerts = Vec::new();
    if status == "open" && created.is_some_and(|c| now - c > AGING_OPEN_DAYS * 86400) {
        alerts.push("aging_open");
    }
    if status == "doing" {
        let anchor = ts_s(t["claimed_at"].as_str()).or_else(|| ts_s(t["updated_at"].as_str())).or(created);
        if anchor.is_some_and(|a| now - a > AGING_DOING_HOURS * 3600) {
            alerts.push("aging_doing");
        }
        if ts_s(t["lock_expires_at"].as_str()).is_some_and(|l| l < now) {
            alerts.push("lock_expired");
        }
    }
    let lane = t["lane"].as_str().filter(|l| !l.is_empty()).unwrap_or("default");
    let project = t["project"].as_str().filter(|p| !p.is_empty()).unwrap_or("default");
    json!({
        "kind": "task",
        "id": id,
        "title": t["title"],
        "status": status,
        "priority": t["priority"].as_str().unwrap_or("med"),
        "claimed_by": t["claimed_by"],
        "lane": lane,
        "project": project,
        "domain": t["domain"],
        "parent_id": t["parent_id"],
        "age_s": created.map(|c| (now - c).max(0)),
        "worktree_path": t["worktree_path"],
        "branch": t["branch"],
        "dep_count": dep_counts.get(&id).copied().unwrap_or(0),
        "blocked_reason": if status == "blocked" { json!(format!("task #{id} is blocked")) } else { Value::Null },
        "lock_expires_at": t["lock_expires_at"],
        "created_at": t["created_at"],
        "updated_at": t["updated_at"],
        "evidence_ref": t["evidence_ref"],
        "alerts": alerts,
        "subtasks": [],
        "swimlane": if swimlane_by == "project" { project } else { lane },
        "rollup": t.get("rollup").cloned().unwrap_or(Value::Null),
    })
}

struct BoardFilters {
    project: Option<String>,
    lane: Option<String>,
    agent: Option<String>,
    claimed_by: Option<String>,
    priority: Option<String>,
    min_age_days: Option<f64>,
}

impl BoardFilters {
    fn keeps(&self, card: &Value) -> bool {
        let eq = |k: &str, want: &Option<String>| want.as_deref().is_none_or(|w| card[k].as_str() == Some(w));
        if !eq("project", &self.project) || !eq("lane", &self.lane) || !eq("priority", &self.priority) {
            return false;
        }
        if let Some(a) = &self.agent
            && !["claimed_by", "to_agent", "from_agent"].iter().any(|k| card[*k].as_str() == Some(a.as_str()))
        {
            return false;
        }
        if !eq("claimed_by", &self.claimed_by) {
            return false;
        }
        if let Some(days) = self.min_age_days {
            match card["age_s"].as_i64() {
                Some(age) if age as f64 >= days * 86400.0 => {}
                _ => return false,
            }
        }
        true
    }
}

async fn board(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let caller = caller(&state, &id, &headers);
    let now = now_s();
    let get = |k: &str| q.get(k).filter(|v| !v.is_empty()).cloned();
    let include_cancelled = q
        .get("include_cancelled")
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    let swimlane_by = if get("swimlane_by").as_deref() == Some("project") { "project" } else { "lane" };
    let filters = BoardFilters {
        project: get("project"),
        lane: get("lane"),
        agent: get("agent"),
        claimed_by: get("claimed_by"),
        priority: get("priority"),
        min_age_days: get("min_age_days").or_else(|| get("age")).and_then(|v| v.parse().ok()),
    };
    let mut errors: Vec<String> = Vec::new();
    let mut tasks: Vec<Value> = Vec::new();
    for status in ACTIVE {
        let (rows, e, _) = all_tasks(&state, &caller, status, &Map::new()).await;
        tasks.extend(rows);
        errors.extend(e);
    }
    let mut done_extra = Map::new();
    done_extra.insert("completed_after".into(), json!(ts_from_s(now - DONE_WINDOW_DAYS * 86400)));
    let (rows, e, _) = all_tasks(&state, &caller, "done", &done_extra).await;
    tasks.extend(rows);
    errors.extend(e);
    if include_cancelled {
        let (rows, e, _) = all_tasks(&state, &caller, "cancelled", &Map::new()).await;
        tasks.extend(rows);
        errors.extend(e);
    }
    let mut dep_counts: HashMap<i64, i64> = HashMap::new();
    match state.registry.call(&state.hub, &caller, "dependency_list", json!({ "limit": 2000 })).await {
        Ok(v) => {
            for edge in v["dependencies"].as_array().into_iter().flatten() {
                if let Some(t) = edge["task_id"].as_i64() {
                    *dep_counts.entry(t).or_default() += 1;
                }
            }
        }
        Err(e) => errors.push(e.to_string()),
    }
    let mut columns: BTreeMap<&str, Vec<Value>> =
        BOARD_LABELS.iter().map(|(s, _)| (*s, Vec::new())).collect();
    let by_id: HashMap<i64, &Value> = tasks.iter().filter_map(|t| t["id"].as_i64().map(|i| (i, t))).collect();
    for t in &tasks {
        let card = task_card(t, now, &dep_counts, swimlane_by);
        if !filters.keeps(&card) {
            continue;
        }
        let status = card["status"].as_str().unwrap_or("open").to_string();
        if let Some(col) = columns.get_mut(status.as_str()) {
            col.push(card);
        }
    }
    match state
        .registry
        .call(&state.hub, &caller, "delegate_list", json!({ "status": "pending", "limit": 200 }))
        .await
    {
        Ok(v) => {
            for d in v["delegations"].as_array().into_iter().flatten() {
                let deadline = ts_s(d["deadline"].as_str());
                let remaining = deadline.map(|dl| dl - now);
                let linked = d["task_id"].as_i64().and_then(|t| by_id.get(&t));
                let summary: String =
                    d["task_spec"].as_str().unwrap_or("Delegation").chars().take(120).collect();
                let card = json!({
                    "kind": "delegation",
                    "id": format!("delegation:{}", d["id"]),
                    "delegation_id": d["id"],
                    "title": summary,
                    "status": "doing",
                    "priority": "med",
                    "claimed_by": d["to_agent"],
                    "from_agent": d["from_agent"],
                    "to_agent": d["to_agent"],
                    "task_id": d["task_id"],
                    "lane": linked.and_then(|t| t["lane"].as_str()).unwrap_or("default"),
                    "project": linked.and_then(|t| t["project"].as_str()).unwrap_or("default"),
                    "parent_id": null,
                    "age_s": ts_s(d["created_at"].as_str()).map(|c| (now - c).max(0)),
                    "worktree_path": null,
                    "branch": null,
                    "dep_count": 0,
                    "blocked_reason": null,
                    "deadline": d["deadline"],
                    "deadline_remaining_s": remaining,
                    "alerts": if remaining.is_some_and(|r| r < 0) { json!(["overdue"]) } else { json!([]) },
                    "subtasks": [],
                    "swimlane": d["to_agent"].as_str().unwrap_or("default"),
                });
                if filters.keeps(&card)
                    && let Some(col) = columns.get_mut("doing")
                {
                    col.push(card);
                }
            }
        }
        Err(e) => errors.push(e.to_string()),
    }
    let mut lane_counts: BTreeMap<String, i64> = BTreeMap::new();
    let mut agent_counts: BTreeMap<String, i64> = BTreeMap::new();
    for t in tasks.iter().filter(|t| t["status"] == "doing") {
        if ts_s(t["lock_expires_at"].as_str()).is_some_and(|l| l < now) {
            continue;
        }
        *lane_counts.entry(t["lane"].as_str().unwrap_or("default").to_string()).or_default() += 1;
        if let Some(owner) = t["claimed_by"].as_str().filter(|o| !o.is_empty()) {
            *agent_counts.entry(owner.to_string()).or_default() += 1;
        }
    }
    let wip_lanes: Map<String, Value> = lane_counts
        .into_iter()
        .map(|(l, c)| (l, json!({ "count": c, "cap": null, "mode": null, "over": false })))
        .collect();
    let wip_agents: Map<String, Value> = agent_counts
        .into_iter()
        .map(|(a, c)| (a, json!({ "count": c, "cap": null, "over": false })))
        .collect();
    let column_rows: Vec<Value> = BOARD_LABELS
        .iter()
        .map(|(status, label)| {
            let cards = columns.remove(status).unwrap_or_default();
            json!({
                "status": status,
                "label": label,
                "count": cards.len(),
                "cards": cards,
                "hidden_by_default": *status == "cancelled",
            })
        })
        .collect();
    let mut out = json!({
        "as_of": ts_from_s(now),
        "columns": column_rows,
        "swimlane_by": swimlane_by,
        "wip": { "lanes": wip_lanes, "agents": wip_agents, "agent_cap": null },
        "alerts": [],
        "filters": {
            "project": filters.project,
            "lane": filters.lane,
            "agent": filters.agent,
            "claimed_by": filters.claimed_by,
            "priority": filters.priority,
            "min_age_days": filters.min_age_days,
            "include_cancelled": include_cancelled,
        },
        "thresholds": {
            "aging_open_days": AGING_OPEN_DAYS,
            "aging_doing_hours": AGING_DOING_HOURS,
            "done_window_days": DONE_WINDOW_DAYS,
        },
    });
    if !errors.is_empty() {
        out["error"] = json!(errors.join("; "));
        out["errors"] = json!(errors);
    }
    Json(out).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_normalize_to_stored_utc() {
        assert_eq!(normalize_ts("2026-11-01").as_deref(), Some("2026-11-01T00:00:00+00:00"));
        assert_eq!(normalize_ts("2026-11-01T10:00:00").as_deref(), Some("2026-11-01T10:00:00+00:00"));
        assert_eq!(normalize_ts("2026-11-01T10:00:00+02:00").as_deref(), Some("2026-11-01T08:00:00+00:00"));
        assert_eq!(normalize_ts("2026-11-01T10:00:00Z").as_deref(), Some("2026-11-01T10:00:00+00:00"));
        assert!(normalize_ts("yesterday").is_none());
    }
}
