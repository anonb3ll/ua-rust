//! The platform routes of the TypeScript SDK (`ControlCenterClient`): runs,
//! the platform object model and evidence, with the Python hub's paths and
//! shapes, each mapped onto one registered tool.
//!
//! | Route | Tool |
//! |---|---|
//! | `GET  /api/runs` | `run_list` (SDK kinds unless `kind` says otherwise) |
//! | `GET  /api/runs/{run_id}` | `run_get` (SDK kinds unless `kind` says otherwise) |
//! | `GET  /api/platform/manifest` | `platform_manifest` |
//! | `GET  /api/platform/objects/{kind}` | `platform_object_get` (collection kinds) |
//! | `GET  /api/platform/objects/{kind}/{id}` | `platform_object_get` |
//! | `GET  /api/evidence` | `evidence_report` (JSON only) |
//! | `POST /api/evidence` | `evidence_append` (201; 200 for a deduplicated repeat; 202 while an approval is pending) |
//!
//! `GET /api/runs` without `kind` lists `dispatch` and `session` runs: the
//! SDK's `Run` schema accepts only those kinds (and `selfpickup`, which this
//! hub does not record), so the other stores are opt-in with `kind=workflow`,
//! `kind=node` or `kind=all`. `GET /api/runs/{id}` looks in the same kinds:
//! a workflow run or node item id is 404 there unless `kind` names its kind
//! (or `all`), so `getRun` never receives a row its schema rejects.
//!
//! Not built: the provenance graph (`/api/platform/provenance-graph`) and the
//! evidence export (`/api/evidence/export`) answer `501`. Work products are
//! not ported pending an explicit product decision (hub task #2658);
//! `/api/work-products*` answers `501` and says so.
//!
//! Every route is behind the same middleware as the rest of `/api` (bearer or
//! session cookie, host check, cross-site and CSRF checks on writes) and
//! every read and write goes through [`ua_tools::Registry::call`] with the
//! request's caller: profile, policy, approval gate and telemetry apply.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Extension, Json, Router};
use serde_json::{Map, Value, json};
use ua_core::identity::Transport;
use ua_core::{Caller, UaError};
use ua_tools::families::runs::{KINDS, SDK_KINDS};

use crate::AppState;
use crate::auth::{AuthIdentity, caller_for, session_key};
use crate::compat_api::{not_built, object_body, pending, tool_err};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/runs", get(runs))
        .route("/api/runs/{run_id}", get(run_detail))
        .route("/api/platform/manifest", get(manifest))
        .route("/api/platform/objects/{kind}", get(object_collection))
        .route("/api/platform/objects/{kind}/{id}", get(object))
        .route(
            "/api/platform/{*rest}",
            any(|| async { not_built("platform", "the provenance graph and other platform views") }),
        )
        .route("/api/evidence", get(evidence_report).post(evidence_append))
        .route("/api/evidence/{*rest}", any(|| async { not_built("evidence", "the evidence export") }))
        .route("/api/work-products", any(|| async { not_ported() }))
        .route("/api/work-products/{*rest}", any(|| async { not_ported() }))
}

/// Work products are not part of this hub until a product decision says
/// otherwise (hub task #2658).
fn not_ported() -> Response {
    let body = json!({
        "error": "not_implemented",
        "capability": "work_products",
        "message": "work products (submit, review and release) are not ported to this hub pending a \
                    product decision (hub task #2658); use the Python hub for them",
    });
    (StatusCode::NOT_IMPLEMENTED, Json(body)).into_response()
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

fn caller(state: &AppState, id: &AuthIdentity, headers: &HeaderMap) -> Caller {
    caller_for(state, id, session_key(headers), Transport::Http)
}

async fn call(state: &AppState, caller: &Caller, tool: &str, args: Value) -> Result<Value, Box<Response>> {
    match state.registry.call(&state.hub, caller, tool, args.clone()).await {
        Ok(v) => Ok(v),
        Err(UaError::ApprovalRequired { approval_id, .. }) => Err(Box::new(pending(approval_id, tool, args))),
        Err(e) => Err(Box::new(tool_err(&e))),
    }
}

/// A positive integer query parameter, `Ok(None)` when absent or empty.
fn int_param(q: &HashMap<String, String>, name: &str) -> Result<Option<i64>, Box<Response>> {
    match q.get(name).map(|s| s.trim()).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(raw) => match raw.parse::<i64>() {
            Ok(n) if n > 0 => Ok(Some(n)),
            _ => Err(Box::new(err(StatusCode::BAD_REQUEST, format!("{name} must be a positive integer")))),
        },
    }
}

fn text_param(q: &HashMap<String, String>, name: &str) -> Option<String> {
    q.get(name).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// Runs

/// The run kinds a `kind` query parameter selects: the SDK's kinds when it
/// is absent.
fn route_kinds(q: &HashMap<String, String>) -> Result<Vec<&'static str>, Box<Response>> {
    Ok(match text_param(q, "kind").as_deref() {
        None => SDK_KINDS.to_vec(),
        Some("all") => KINDS.to_vec(),
        // The SDK names it; this hub records no self-pickup runs.
        Some("selfpickup") => vec!["selfpickup"],
        Some(k) => match KINDS.iter().find(|x| **x == k) {
            Some(x) => vec![*x],
            None => {
                return Err(Box::new(err(
                    StatusCode::BAD_REQUEST,
                    "kind must be dispatch, selfpickup, session, workflow, node or all",
                )));
            }
        },
    })
}

async fn runs(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let kinds = match route_kinds(&q) {
        Ok(k) => k,
        Err(r) => return *r,
    };
    let task_id = match int_param(&q, "task_id") {
        Ok(t) => t,
        Err(r) => return *r,
    };
    let limit = match int_param(&q, "limit") {
        Ok(l) => l,
        Err(r) => return *r,
    };
    let mut args = json!({ "kinds": kinds });
    if let Some(a) = text_param(&q, "agent") {
        args["agent"] = json!(a);
    }
    if let Some(t) = task_id {
        args["task_id"] = json!(t);
    }
    if let Some(l) = limit {
        args["limit"] = json!(l);
    }
    if let Some(c) = text_param(&q, "cursor") {
        args["cursor"] = json!(c);
    }
    let caller = caller(&state, &id, &headers);
    match call(&state, &caller, "run_list", args).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => *r,
    }
}

async fn run_detail(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let kinds = match route_kinds(&q) {
        Ok(k) => k,
        Err(r) => return *r,
    };
    let caller = caller(&state, &id, &headers);
    let args = json!({ "run_id": run_id, "kinds": kinds });
    match state.registry.call(&state.hub, &caller, "run_get", args).await {
        Ok(v) => Json(v).into_response(),
        Err(UaError::NotFound(_)) => err(StatusCode::NOT_FOUND, "unknown run"),
        Err(e) => tool_err(&e),
    }
}

// ---------------------------------------------------------------------------
// Platform objects

async fn manifest(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
) -> Response {
    let caller = caller(&state, &id, &headers);
    match call(&state, &caller, "platform_manifest", json!({})).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => *r,
    }
}

async fn read_object(state: &AppState, caller: &Caller, kind: String, object_id: Option<String>) -> Response {
    let mut args = json!({ "kind": kind });
    if let Some(i) = object_id {
        args["id"] = json!(i);
    }
    match call(state, caller, "platform_object_get", args).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => *r,
    }
}

async fn object_collection(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Path(kind): Path<String>,
) -> Response {
    let caller = caller(&state, &id, &headers);
    read_object(&state, &caller, kind, None).await
}

async fn object(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Path((kind, object_id)): Path<(String, String)>,
) -> Response {
    let caller = caller(&state, &id, &headers);
    read_object(&state, &caller, kind, Some(object_id)).await
}

// ---------------------------------------------------------------------------
// Evidence

/// Query parameters `GET /api/evidence` passes to `evidence_report`.
const REPORT_TEXT: [&str; 6] = ["since", "until", "agent", "project", "pr", "item"];

async fn evidence_report(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Some(f) = text_param(&q, "format")
        && !f.eq_ignore_ascii_case("json")
    {
        return err(
            StatusCode::BAD_REQUEST,
            "this hub serves the evidence report as JSON only (format=json)",
        );
    }
    if q.contains_key("cursor") {
        return err(StatusCode::BAD_REQUEST, "cursor paging is not supported by this hub's evidence report");
    }
    let mut args = Map::new();
    let task = q.get("task_id").or_else(|| q.get("task")).map(|s| s.trim()).filter(|s| !s.is_empty());
    if let Some(raw) = task {
        match raw.parse::<i64>() {
            Ok(n) if n > 0 => {
                args.insert("task_id".into(), json!(n));
            }
            _ => return err(StatusCode::BAD_REQUEST, format!("invalid task_id: {raw:?}")),
        }
    }
    for k in ["project_id", "limit"] {
        match int_param(&q, k) {
            Ok(Some(n)) => {
                args.insert(k.into(), json!(n));
            }
            Ok(None) => {}
            Err(r) => return *r,
        }
    }
    for k in REPORT_TEXT {
        if let Some(v) = text_param(&q, k) {
            args.insert(k.into(), json!(v));
        }
    }
    let caller = caller(&state, &id, &headers);
    match call(&state, &caller, "evidence_report", Value::Object(args)).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => *r,
    }
}

async fn evidence_append(
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
    let mut unknown: Vec<&str> = body
        .keys()
        .map(String::as_str)
        .filter(|k| !["channel", "payload", "dedupe_key"].contains(k))
        .collect();
    if !unknown.is_empty() {
        unknown.sort();
        return err(StatusCode::BAD_REQUEST, format!("unknown evidence field(s): {}", unknown.join(", ")));
    }
    if !body.get("channel").and_then(Value::as_str).is_some_and(|c| c.starts_with("sdk.")) {
        return err(StatusCode::BAD_REQUEST, "channel must use the sdk. namespace");
    }
    if !body.get("payload").is_some_and(Value::is_object) {
        return err(StatusCode::BAD_REQUEST, "payload must be a JSON object");
    }
    let mut args = body;
    if args.get("dedupe_key").is_some_and(Value::is_null) {
        args.remove("dedupe_key");
    }
    let caller = caller(&state, &id, &headers);
    match call(&state, &caller, "evidence_append", Value::Object(args)).await {
        Ok(v) => {
            let status = if v["inserted"] == json!(true) { StatusCode::CREATED } else { StatusCode::OK };
            (status, Json(v)).into_response()
        }
        Err(r) => *r,
    }
}
