//! Web UI and compatibility API, driven through the full router with an
//! in-memory hub.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_server::AppState;
use ua_tools::{Hub, builtin_registry};

mod common;

const OPERATOR_TOKEN: &str = "operator-test-token-0001";
const BUILDER_TOKEN: &str = "builder-test-token-0002";

/// The suite covers both token and local (unauthenticated) callers, so auth
/// enforcement is switched off explicitly.
fn local_config() -> Config {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.enforce_auth = false;
    cfg
}

fn config() -> Config {
    let mut cfg = local_config();
    cfg.agent_tokens =
        Some(SecretString::from(format!("operator:{OPERATOR_TOKEN},builder-1:{BUILDER_TOKEN}")));
    cfg.human_identities = vec!["operator".into()];
    cfg.profiles.insert("operator".into(), "operator".into());
    cfg
}

fn app(cfg: Config) -> (Router, AppState) {
    let hub = Hub::in_memory(cfg).unwrap();
    let state = AppState::new(hub, Arc::new(builtin_registry()));
    (ua_server::router(state.clone(), CancellationToken::new()), state)
}

fn builder() -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Mcp,
    }
}

fn local() -> Caller {
    Caller::local("local", Transport::Cli)
}

async fn call(state: &AppState, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
    state.registry.call(&state.hub, who, tool, args).await
}

async fn send(app: &Router, req: Request<Body>) -> Response<Body> {
    app.clone().oneshot(req).await.unwrap()
}

async fn body_text(resp: Response<Body>) -> String {
    String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

async fn body_json(resp: Response<Body>) -> Value {
    serde_json::from_str(&body_text(resp).await).unwrap()
}

fn get(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::get(uri);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

fn post_json(uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// GET a UI page and return the CSRF cookie it sets.
async fn csrf_cookie(app: &Router, token: Option<&str>) -> String {
    let resp = send(app, get("/ui/inbox", token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = resp.headers().get(header::SET_COOKIE).expect("csrf cookie").to_str().unwrap().to_string();
    assert!(cookie.contains("SameSite=Strict") && cookie.contains("HttpOnly"), "{cookie}");
    cookie.split(';').next().unwrap().split_once('=').unwrap().1.to_string()
}

fn form(
    uri: &str,
    token: Option<&str>,
    csrf_cookie: Option<&str>,
    header_token: Option<&str>,
    body: &str,
) -> Request<Body> {
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    if let Some(c) = csrf_cookie {
        b = b.header(header::COOKIE, format!("ua_csrf={c}"));
    }
    if let Some(h) = header_token {
        b = b.header("x-csrf-token", h);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn approval_status(state: &AppState, id: i64) -> String {
    state.hub.db().read(|c| ua_tools::approvals::get(c, id)).unwrap().status
}

/// builder-1 calls a gated tool and gets a pending approval id.
async fn park(state: &AppState, title: &str) -> i64 {
    match call(state, &builder(), "task_add", json!({ "title": title })).await {
        Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
        other => panic!("expected a pending approval, got {other:?}"),
    }
}

fn gated_config() -> Config {
    let mut cfg = config();
    cfg.approval_tools = vec!["task_add".into()];
    cfg
}

#[tokio::test]
async fn every_page_renders_with_its_key_elements() {
    let (app, state) = app(local_config());
    let me = local();
    let t1 = call(
        &state,
        &me,
        "task_add",
        json!({ "title": "Wire the board", "project": "demo", "priority": "high" }),
    )
    .await
    .unwrap()["id"]
        .as_i64()
        .unwrap();
    let t2 =
        call(&state, &me, "task_add", json!({ "title": "Follow-up" })).await.unwrap()["id"].as_i64().unwrap();
    call(&state, &me, "dependency_add", json!({ "task_id": t2, "depends_on_task_id": t1 })).await.unwrap();
    call(
        &state,
        &me,
        "task_comment",
        json!({ "action": "append", "params": { "task_id": t1, "body": "first comment" } }),
    )
    .await
    .unwrap();
    let plan = call(
        &state,
        &me,
        "plan_create",
        json!({ "goal": "Ship the control center", "steps": ["render", "test"] }),
    )
    .await
    .unwrap()["plan_id"]
        .as_str()
        .unwrap()
        .to_string();
    let note = call(
        &state,
        &me,
        "memory_save",
        json!({ "title": "Build cache note", "content": "keep the shared cache", "tags": ["demo"] }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    call(&state, &me, "session_start", json!({ "kind": "interactive", "agent": "builder-1" })).await.unwrap();
    call(&state, &me, "message_send", json!({ "to_agent": "local", "from_agent": "builder-1", "act": "inform", "body": "hello from builder" }))
        .await
        .unwrap();

    let pages: Vec<(String, Vec<&str>)> = vec![
        (
            "/ui/inbox".into(),
            vec!["<h1>Inbox</h1>", "Pending approvals", "Live passes", "Expired passes", "/login"],
        ),
        ("/ui/work".into(), vec!["Backlog", "Wire the board", "In review", "name=\"_csrf\""]),
        ("/ui/work?project=demo&priority=high".into(), vec!["Wire the board"]),
        ("/ui/work?q=board".into(), vec!["Ranked search", "Wire the board"]),
        (format!("/ui/tasks/{t1}"), vec!["Wire the board", "first comment", "Blocks", &"/ui/tasks/2"]),
        (format!("/ui/tasks/{t2}"), vec!["Waits on", "Remove dependency on #1"]),
        ("/ui/plans".into(), vec!["Ship the control center", "Delegations"]),
        (format!("/ui/plans/{plan}"), vec!["render", "Steps"]),
        ("/ui/agents".into(), vec!["builder-1", "Open sessions", "live"]),
        ("/ui/messages".into(), vec!["hello from builder", "unread"]),
        ("/ui/memory".into(), vec!["Build cache note", "Recent notes"]),
        ("/ui/memory?q=cache".into(), vec!["Build cache note", "Search results"]),
        (format!("/ui/memory/{note}"), vec!["keep the shared cache", "data, not instructions"]),
        (
            "/ui/activity".into(),
            vec!["Verify the hash chain", "sse-connect=\"/ui/activity/stream\"", "agent.task."],
        ),
        ("/ui/activity?verify=1".into(), vec!["Ledger hash chain verified"]),
        (
            "/ui/activity?channel_prefix=agent.memory.".into(),
            vec!["agent.memory.saved", "channel_prefix=agent.memory."],
        ),
    ];
    for (uri, needles) in pages {
        let resp = send(&app, get(&uri, None)).await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let csp = resp.headers().get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap().to_string();
        assert!(csp.contains("script-src 'self'"), "{uri}: {csp}");
        let html = body_text(resp).await;
        assert!(html.contains("hx-headers='{\"X-CSRF-Token\":"), "{uri} lacks the csrf header");
        for n in needles {
            assert!(html.contains(n), "{uri} lacks {n:?}");
        }
    }

    let resp = send(&app, get("/ui/tasks/999", None)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = send(&app, get("/ui", None)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let resp = send(&app, get("/ui/static/htmx-2.0.11.min.js", None)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&app, get("/ui/static/ui.css", None)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&app, get("/ui/activity/stream", None)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/event-stream"));
}

#[tokio::test]
async fn approving_through_the_inbox_form_lets_the_retry_through() {
    let (app, state) = app(gated_config());
    let id = park(&state, "Needs a human").await;

    let resp = send(&app, get("/ui/inbox", Some(OPERATOR_TOKEN))).await;
    let html = body_text(resp).await;
    assert!(
        html.contains(&format!("approval-{id}"))
            && html.contains("builder-1")
            && html.contains("Needs a human")
    );
    assert!(html.contains("Signed in as <strong>operator</strong>"));

    let csrf = csrf_cookie(&app, Some(OPERATOR_TOKEN)).await;
    // A plain form post carries the token in the hidden field.
    let resp = send(
        &app,
        form(
            &format!("/ui/approvals/{id}/resolve"),
            Some(OPERATOR_TOKEN),
            Some(&csrf),
            None,
            &format!("_csrf={csrf}&decision=approve&reason=looks+fine"),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()[header::LOCATION], "/ui/inbox?flash=approved");
    assert_eq!(approval_status(&state, id), "approved");

    let html = body_text(send(&app, get("/ui/inbox?flash=approved", Some(OPERATOR_TOKEN))).await).await;
    assert!(html.contains("Approved. The requester can retry"));
    assert!(html.contains("value=\"revoke\""), "the live pass offers revoke");

    // The identical retry consumes the pass.
    call(&state, &builder(), "task_add", json!({ "title": "Needs a human" })).await.unwrap();
    assert_eq!(approval_status(&state, id), "consumed");
}

/// The inbox shows which adapter each live pass was approved through;
/// a row resolved before that was recorded reads "unknown".
#[tokio::test]
async fn the_inbox_shows_how_each_pass_was_approved() {
    let (app, state) = app(gated_config());
    let via_ui = park(&state, "Approved in the inbox").await;
    let via_slack = park(&state, "Approved from chat").await;
    let csrf = csrf_cookie(&app, Some(OPERATOR_TOKEN)).await;
    let resp = send(
        &app,
        form(
            &format!("/ui/approvals/{via_ui}/resolve"),
            Some(OPERATOR_TOKEN),
            Some(&csrf),
            None,
            &format!("_csrf={csrf}&decision=approve&reason=ok"),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let slack_human = ua_core::Caller {
        label: "operator".into(),
        kind: ua_core::ActorKind::Human,
        profile: ua_core::Profile::Coordinator,
        enforce_profile: true,
        session_key: None,
        transport: ua_core::identity::Transport::Slack,
    };
    call(&state, &slack_human, "approval_resolve", json!({ "id": via_slack, "decision": "approve" }))
        .await
        .unwrap();
    // A pass resolved before the transport was recorded.
    let old = park(&state, "Approved long ago").await;
    let now = ua_core::time::now();
    state
        .hub
        .db()
        .write(move |tx| {
            tx.execute(
                "UPDATE approvals SET status = 'approved', resolved_by = 'operator', resolved_at = ?2, \
                 resolved_transport = NULL WHERE id = ?1",
                rusqlite::params![old, now],
            )?;
            Ok(())
        })
        .unwrap();

    let html = body_text(send(&app, get("/ui/inbox", Some(OPERATOR_TOKEN))).await).await;
    let row = |id: i64| {
        let start = html.find(&format!("id=\"approval-{id}\"")).unwrap_or_else(|| panic!("row {id}: {html}"));
        let end = html[start..].find("</tr>").unwrap() + start;
        html[start..end].to_string()
    };
    assert!(row(via_ui).contains("<td>ui</td>"), "{}", row(via_ui));
    assert!(row(via_slack).contains("<td>slack</td>"), "{}", row(via_slack));
    assert!(row(old).contains("<td>unknown</td>"), "{}", row(old));
    assert!(html.contains("<th scope=\"col\">Via</th>"));
}

#[tokio::test]
async fn deny_and_revoke_go_through_the_same_form_with_the_header_token() {
    let (app, state) = app(gated_config());
    let denied = park(&state, "Deny me").await;
    let revoked = park(&state, "Revoke me").await;
    let csrf = csrf_cookie(&app, Some(OPERATOR_TOKEN)).await;
    let post = |id: i64, decision: &str| {
        form(
            &format!("/ui/approvals/{id}/resolve"),
            Some(OPERATOR_TOKEN),
            Some(&csrf),
            Some(&csrf),
            &format!("decision={decision}"),
        )
    };
    assert_eq!(send(&app, post(denied, "deny")).await.status(), StatusCode::SEE_OTHER);
    assert_eq!(approval_status(&state, denied), "denied");
    assert_eq!(send(&app, post(revoked, "approve")).await.status(), StatusCode::SEE_OTHER);
    assert_eq!(send(&app, post(revoked, "revoke")).await.status(), StatusCode::SEE_OTHER);
    assert_eq!(approval_status(&state, revoked), "revoked");

    // Approving a resolved row is refused and the page says why.
    let resp = send(&app, post(denied, "approve")).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(body_text(resp).await.contains("not pending"));
}

#[tokio::test]
async fn an_agent_cannot_approve_through_the_ui() {
    let (app, state) = app(gated_config());
    let id = park(&state, "Agent tries").await;
    let csrf = csrf_cookie(&app, Some(BUILDER_TOKEN)).await;
    let resp = send(
        &app,
        form(
            &format!("/ui/approvals/{id}/resolve"),
            Some(BUILDER_TOKEN),
            Some(&csrf),
            Some(&csrf),
            "decision=approve",
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(body_text(resp).await.contains("role=\"alert\""));
    assert_eq!(approval_status(&state, id), "pending");
}

#[tokio::test]
async fn state_changes_without_a_valid_csrf_token_are_refused() {
    let (app, state) = app(gated_config());
    let id = park(&state, "CSRF target").await;
    let uri = format!("/ui/approvals/{id}/resolve");
    let csrf = csrf_cookie(&app, Some(OPERATOR_TOKEN)).await;
    let other = "b".repeat(64);

    // No cookie, no token.
    let resp = send(&app, form(&uri, Some(OPERATOR_TOKEN), None, None, "decision=approve")).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Cookie but no token.
    let resp = send(&app, form(&uri, Some(OPERATOR_TOKEN), Some(&csrf), None, "decision=approve")).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Token that does not match the cookie, in the header and in the form.
    let resp =
        send(&app, form(&uri, Some(OPERATOR_TOKEN), Some(&csrf), Some(&other), "decision=approve")).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = send(
        &app,
        form(&uri, Some(OPERATOR_TOKEN), Some(&csrf), None, &format!("decision=approve&_csrf={other}")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // A valid token from another site.
    let mut req = form(&uri, Some(OPERATOR_TOKEN), Some(&csrf), Some(&csrf), "decision=approve");
    req.headers_mut().insert(header::HOST, "hub.example.com".parse().unwrap());
    req.headers_mut().insert(header::ORIGIN, "https://evil.example.net".parse().unwrap());
    assert_eq!(send(&app, req).await.status(), StatusCode::FORBIDDEN);

    assert_eq!(approval_status(&state, id), "pending");
}

#[tokio::test]
async fn task_forms_create_update_comment_and_link() {
    let (app, state) = app(local_config());
    let csrf = csrf_cookie(&app, None).await;
    let post = |uri: &str, body: &str| form(uri, None, Some(&csrf), Some(&csrf), body);

    let resp =
        send(&app, post("/ui/tasks", "title=From+the+UI&priority=high&project=demo&notes=spec+text")).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()[header::LOCATION], "/ui/tasks/1?flash=task_created");
    let other = call(&state, &local(), "task_add", json!({ "title": "Prerequisite" })).await.unwrap()["id"]
        .as_i64()
        .unwrap();

    let resp =
        send(&app, post("/ui/tasks/1/update", "title=From+the+UI&status=blocked&priority=low&project=demo"))
            .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        send(&app, post("/ui/tasks/1/note", "append_note=a+new+line")).await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        send(&app, post("/ui/tasks/1/comments", "body=looks+good")).await.status(),
        StatusCode::SEE_OTHER
    );
    let resp = send(&app, post("/ui/tasks/1/dependencies", &format!("depends_on_task_id={other}"))).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let html = body_text(send(&app, get("/ui/tasks/1?flash=task_updated", None)).await).await;
    assert!(html.contains("Task updated."));
    assert!(
        html.contains("a new line")
            && html.contains("looks good")
            && html.contains(&format!("/ui/tasks/{other}"))
    );
    assert!(html.contains("<option value=\"blocked\" selected>"));
    assert!(html.contains("<option value=\"low\" selected>"));

    // A self-dependency is refused by the tool and shown on the page.
    let resp = send(&app, post("/ui/tasks/1/dependencies", "depends_on_task_id=1")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(resp).await.contains("cannot depend on itself"));

    // Removing the edge.
    let deps = call(&state, &local(), "dependency_list", json!({ "task_id": 1 })).await.unwrap();
    let dep = deps["dependencies"][0]["id"].as_i64().unwrap();
    let resp = send(&app, post(&format!("/ui/tasks/1/dependencies/{dep}/remove"), "")).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let deps = call(&state, &local(), "dependency_list", json!({ "task_id": 1 })).await.unwrap();
    assert!(deps["dependencies"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_gated_ui_write_parks_and_says_so() {
    let mut cfg = local_config();
    cfg.approval_tools = vec!["task_add".into()];
    let (app, _state) = app(cfg);
    let csrf = csrf_cookie(&app, None).await;
    let resp = send(&app, form("/ui/tasks", None, Some(&csrf), Some(&csrf), "title=Gated")).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers()[header::LOCATION].to_str().unwrap().to_string();
    assert_eq!(loc, "/ui/work?flash=parked&approval=1");
    let html = body_text(send(&app, get(&loc, None)).await).await;
    assert!(html.contains("approval #1 is pending"));
}

#[tokio::test]
async fn profile_limits_show_as_section_errors() {
    let (app, _state) = app(config());
    // The operator profile has no plan or agent tools.
    let html = body_text(send(&app, get("/ui/plans", Some(OPERATOR_TOKEN))).await).await;
    assert!(html.contains("plan_list is not available to your profile"), "{html}");
    let resp = send(&app, get("/ui/work", Some(OPERATOR_TOKEN))).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Compatibility API

#[tokio::test]
async fn api_tasks_has_the_sdk_shape() {
    let (app, state) = app(local_config());
    let me = local();
    call(&state, &me, "task_add", json!({ "title": "Open one", "project": "alpha" })).await.unwrap();
    let blocked =
        call(&state, &me, "task_add", json!({ "title": "Blocked one", "project": "beta" })).await.unwrap();
    call(&state, &me, "task_update", json!({ "id": blocked["id"], "status": "blocked" })).await.unwrap();
    let done =
        call(&state, &me, "task_add", json!({ "title": "Done one", "project": "alpha" })).await.unwrap();
    call(&state, &me, "task_update", json!({ "id": done["id"], "status": "done" })).await.unwrap();

    let v = body_json(send(&app, get("/api/tasks", None)).await).await;
    assert_eq!(v["total"], 2);
    assert_eq!(v["buckets"], json!({ "open": 1, "blocked": 1 }));
    assert_eq!(v["projects"], json!({ "alpha": 1, "beta": 1 }));
    assert_eq!(v["active"].as_array().unwrap().len(), 1);
    assert_eq!(v["active"][0]["title"], "Blocked one");
    assert!(v.get("completed").is_none());

    let v =
        body_json(send(&app, get("/api/tasks?project=alpha&completed_after=2000-01-01", None)).await).await;
    assert_eq!(v["total"], 1);
    assert_eq!(v["projects"], json!({ "alpha": 1, "beta": 1 }));
    assert_eq!(v["completed_after"], "2000-01-01T00:00:00+00:00");
    assert_eq!(v["completed"][0]["title"], "Done one");
    assert_eq!(v["completed_truncated"], false);

    let resp = send(&app, get("/api/tasks?completed_after=not-a-date", None)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn api_task_create_and_update_match_the_python_contract() {
    let (app, _state) = app(local_config());
    let resp =
        send(&app, post_json("/api/tasks", None, json!({ "title": "From the SDK", "priority": "high" })))
            .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let id = created["id"].as_i64().unwrap();

    let resp = send(&app, post_json("/api/tasks", None, json!({ "title": "x", "bogus": 1 }))).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "unknown task_add field(s): bogus");

    let resp = send(
        &app,
        post_json(
            "/api/action/task",
            None,
            json!({ "id": id, "status": "blocked", "append_note": "waiting on review" }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let row = body_json(resp).await;
    assert_eq!(row["id"], id);
    assert_eq!(row["status"], "blocked");
    assert!(row["notes"].as_str().unwrap().contains("waiting on review"));

    for (body, msg) in [
        (json!({ "status": "open" }), "missing task id"),
        (json!({ "id": "x" }), "invalid task id; expected integer"),
        (json!({ "id": id, "status": "nope" }), "invalid task status"),
        (json!({ "id": id, "archived": "false" }), "archived must be true or false"),
        (json!({ "id": id, "notes_append": "typo" }), "unknown task_update field(s): notes_append"),
        (json!({ "id": id, "append_note": " " }), "append_note must be a non-empty string"),
    ] {
        let resp = send(&app, post_json("/api/action/task", None, body.clone())).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
        let v = body_json(resp).await;
        assert!(v["error"].as_str().unwrap().starts_with(msg), "{body}: {v}");
    }

    let resp = send(&app, post_json("/api/action/task", None, json!({ "id": 999, "status": "done" }))).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn gated_api_writes_return_the_pending_approval_shape() {
    let mut cfg = local_config();
    cfg.approval_tools = vec!["task_update".into()];
    let (app, state) = app(cfg);
    let id = call(&state, &local(), "task_add", json!({ "title": "Gate me" })).await.unwrap()["id"]
        .as_i64()
        .unwrap();
    let resp = send(&app, post_json("/api/action/task", None, json!({ "id": id, "priority": "high" }))).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "pending");
    assert_eq!(v["tool"], "task_update");
    assert_eq!(v["payload"], json!({ "id": id, "priority": "high" }));
    assert!(v["approval_id"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn api_approvals_resolve_detail_and_request() {
    let (app, state) = app(gated_config());
    let id = park(&state, "Via the SDK").await;

    let v = body_json(send(&app, get("/api/approvals", Some(OPERATOR_TOKEN))).await).await;
    assert_eq!(v["pending"][0]["id"], id);
    assert!(v["pending"][0].get("payload").is_none(), "the list strips payloads");
    assert_eq!(v["gated_tools"], json!(["task_add"]));
    // Conditional GET.
    let resp = send(&app, get("/api/approvals", Some(OPERATOR_TOKEN))).await;
    let etag = resp.headers()[header::ETAG].clone();
    let mut req = get("/api/approvals", Some(OPERATOR_TOKEN));
    req.headers_mut().insert(header::IF_NONE_MATCH, etag);
    assert_eq!(send(&app, req).await.status(), StatusCode::NOT_MODIFIED);

    let v = body_json(send(&app, get(&format!("/api/approvals/{id}"), Some(OPERATOR_TOKEN))).await).await;
    assert_eq!(v["payload"]["title"], "Via the SDK");
    assert_eq!(v["approver"]["may_approve"], "yes");
    assert_eq!(v["gate"]["kind"], "global_allowlist");
    assert_eq!(
        send(&app, get("/api/approvals/9999", Some(OPERATOR_TOKEN))).await.status(),
        StatusCode::NOT_FOUND
    );

    // Agents and unauthenticated callers cannot resolve.
    let body = json!({ "id": id, "decision": "approve" });
    assert_eq!(
        send(&app, post_json("/api/action/approval", None, body.clone())).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, post_json("/api/action/approval", Some(BUILDER_TOKEN), body.clone())).await.status(),
        StatusCode::FORBIDDEN
    );
    let resp = send(&app, post_json("/api/action/approval", Some(OPERATOR_TOKEN), body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["id"], id);
    assert_eq!(v["status"], "approved");
    assert_eq!(v["resolved_by"], "operator");

    // Request-only: queues without running, and reports an existing pass.
    let payload = json!({ "title": "Queued ahead" });
    let req = json!({ "tool": "task_add", "payload": payload });
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req.clone())).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "pending");
    let queued = v["approval_id"].as_i64().unwrap();
    let again =
        body_json(send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req.clone())).await)
            .await;
    assert_eq!(again["approval_id"], queued);
    send(&app, post_json("/api/action/approval", Some(OPERATOR_TOKEN), json!({ "id": queued }))).await;
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "approved");
    assert_eq!(approval_status(&state, queued), "approved", "requesting never consumes the pass");

    let resp =
        send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), json!({ "tool": "task_list" })))
            .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let resp = send(
        &app,
        post_json("/api/approvals/request", Some(BUILDER_TOKEN), json!({ "tool": "no_such_tool" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "no enumeration through the request route");
    // A tool the requester's profile hides cannot be queued for a human.
    let resp = send(
        &app,
        post_json("/api/approvals/request", Some(BUILDER_TOKEN), json!({ "tool": "profile_activate" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn api_sessions_catalog_board_and_unbuilt_routes() {
    let (app, state) = app(local_config());
    call(&state, &local(), "session_start", json!({ "kind": "interactive", "agent": "builder-1" }))
        .await
        .unwrap();
    let t = call(&state, &local(), "task_add", json!({ "title": "On the board", "lane": "dispatch-ready" }))
        .await
        .unwrap();

    let v = body_json(send(&app, get("/api/sessions?status=open", None)).await).await;
    assert_eq!(v["sessions"][0]["agent"], "builder-1");
    assert_eq!(v["open"], 1);
    assert_eq!(v["total"], 1);

    let v = body_json(send(&app, get("/api/capability-catalog", None)).await).await;
    assert_eq!(v["available"], true);
    assert_eq!(v["status"], 200);
    let families = v["catalog"]["families"].as_array().unwrap();
    let tasks = families.iter().find(|f| f["id"] == "tasks").unwrap();
    assert!(tasks["tools"].as_array().unwrap().iter().any(|t| t == "task_add"));
    assert_eq!(v["meta"]["total_items"].as_u64().unwrap() as usize, state.registry.len());

    let v = body_json(send(&app, get("/api/board?lane=dispatch-ready", None)).await).await;
    let cols = v["columns"].as_array().unwrap();
    assert_eq!(cols.len(), 6);
    assert_eq!(cols[0]["status"], "open");
    assert_eq!(cols[0]["label"], "Backlog");
    assert_eq!(cols[0]["cards"][0]["id"], t["id"]);
    assert_eq!(cols[0]["cards"][0]["kind"], "task");
    assert_eq!(cols[5]["hidden_by_default"], true);
    assert_eq!(v["filters"]["lane"], "dispatch-ready");

    for uri in ["/api/runs", "/api/platform/manifest", "/api/evidence"] {
        assert_eq!(send(&app, get(uri, None)).await.status(), StatusCode::OK, "{uri}");
    }
    for uri in ["/api/work-products", "/api/platform/provenance-graph"] {
        let resp = send(&app, get(uri, None)).await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED, "{uri}");
        let v = body_json(resp).await;
        assert_eq!(v["error"], "not_implemented");
        assert!(v["capability"].is_string());
    }
}

#[tokio::test]
async fn api_writes_refuse_cross_site_and_non_json_bodies() {
    let (app, _state) = app(local_config());

    // A cross-site page can send text/plain without a preflight; refuse it.
    let req = Request::post("/api/tasks")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(r#"{"title":"from another site"}"#))
        .unwrap();
    assert_eq!(send(&app, req).await.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let mut req = post_json("/api/tasks", None, json!({ "title": "x" }));
    req.headers_mut().insert(header::ORIGIN, "https://evil.example.com".parse().unwrap());
    req.headers_mut().insert(header::HOST, "localhost:8765".parse().unwrap());
    assert_eq!(send(&app, req).await.status(), StatusCode::FORBIDDEN);

    let mut req = post_json("/api/tasks", None, json!({ "title": "x" }));
    req.headers_mut().insert("sec-fetch-site", "cross-site".parse().unwrap());
    assert_eq!(send(&app, req).await.status(), StatusCode::FORBIDDEN);

    // Same-origin JSON still works.
    let mut req = post_json("/api/tasks", None, json!({ "title": "same origin" }));
    req.headers_mut().insert(header::ORIGIN, "http://localhost:8765".parse().unwrap());
    req.headers_mut().insert(header::HOST, "localhost:8765".parse().unwrap());
    assert!(send(&app, req).await.status().is_success());
}

#[tokio::test]
async fn unknown_hosts_are_refused_for_api_and_ui() {
    let (app, _state) = app(local_config());
    for uri in ["/api/tasks", "/ui"] {
        let mut req = get(uri, None);
        req.headers_mut().insert(header::HOST, "rebound.example.com".parse().unwrap());
        assert_eq!(send(&app, req).await.status(), StatusCode::FORBIDDEN, "{uri}");
    }
    let mut req = get("/healthz", None);
    req.headers_mut().insert(header::HOST, "rebound.example.com".parse().unwrap());
    assert_eq!(send(&app, req).await.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Approval requests go through the same checks and projection as a call

const SECRET_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn approvals_containing(state: &AppState, needle: &str) -> i64 {
    let pattern = format!("%{needle}%");
    state
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM approvals WHERE payload LIKE ?1 OR tool LIKE ?1",
                [pattern],
                |r| r.get(0),
            )?)
        })
        .unwrap()
}

#[tokio::test]
async fn an_approval_request_never_parks_a_secret_value() {
    let mut cfg = config();
    cfg.approval_tools = vec!["agent_token_issue".into(), "managed_secret_set".into()];
    cfg.managed_secret_key = Some(SECRET_KEY.to_string().into());
    // agent_token_issue is outside the operator allow list.
    cfg.profiles.insert("operator".into(), "coordinator".into());
    let (app, state) = app(cfg);
    let value = "plain-token-value-0001-0123456789abcdef";
    let req = json!({
        "tool": "agent_token_issue",
        "payload": { "agent_label": "builder-2", "value": value, "note": "for the bench" },
    });
    let resp = send(&app, post_json("/api/approvals/request", Some(OPERATOR_TOKEN), req)).await;
    let status = resp.status();
    let text = body_text(resp).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{text}");
    assert!(!text.contains(value), "the response echoes the secret: {text}");
    assert_eq!(approvals_containing(&state, "builder-2"), 1, "the request is parked");
    assert_eq!(approvals_containing(&state, value), 0, "a secret value landed in the approvals table");
    // It binds the projection the tool's own gate binds: a keyed
    // fingerprint and the length, never the value.
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["payload"]["agent_label"], "builder-2");
    assert!(v["payload"].get("value").is_none(), "{v}");
    assert_eq!(v["payload"]["value_bytes"], value.len());
    assert!(v["payload"]["value_fingerprint"].as_str().is_some_and(|f| f.len() == 32), "{v}");

    // A tool that gates in its handler binds values only it resolves; so
    // does managed_secret_set (a replacement is gated in the handler).
    for (tool, payload) in [
        ("managed_secret_delete", json!({ "name": "docs-token", "consumer": "mcp:docs" })),
        ("managed_secret_set", json!({ "name": "docs-token", "consumer": "mcp:docs", "value": value })),
    ] {
        let resp = send(
            &app,
            post_json(
                "/api/approvals/request",
                Some(OPERATOR_TOKEN),
                json!({ "tool": tool, "payload": payload }),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "{tool}");
        assert!(body_text(resp).await.contains("call the tool"), "{tool}");
    }
    assert_eq!(approvals_containing(&state, value), 0);
}

#[tokio::test]
async fn an_approval_request_needs_a_gated_tool_and_valid_arguments() {
    let (app, state) = app(gated_config());
    // Nothing gates task_update: the settled contract is 409.
    let resp = send(
        &app,
        post_json(
            "/api/approvals/request",
            Some(BUILDER_TOKEN),
            json!({ "tool": "task_update", "payload": { "id": 1, "append_note": "x" } }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    // The payload must be a call the tool accepts: unknown fields and
    // missing ones are refused before anything is parked.
    for payload in [json!({ "title": "x", "bogus": 1 }), json!({})] {
        let resp = send(
            &app,
            post_json(
                "/api/approvals/request",
                Some(BUILDER_TOKEN),
                json!({ "tool": "task_add", "payload": payload }),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{payload}");
    }
    // At most 16 KiB of payload.
    let big = json!({ "tool": "task_add", "payload": { "title": "x".repeat(17 * 1024) } });
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), big)).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // An unknown tool reads like a hidden one for a profile-bound caller.
    let resp = send(
        &app,
        post_json("/api/approvals/request", Some(BUILDER_TOKEN), json!({ "tool": "no_such_tool" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(approvals_containing(&state, "%"), 0, "nothing was parked");

    // The SDK's conformance tool: always gated with no configuration, gated
    // by the registry, and open to a developer token.
    let (app, state) = self::app(config());
    let req = json!({ "tool": "crew_intervene", "payload": { "session_id": "s-1", "message": "pause" } });
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req)).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "pending");
    assert_eq!(approval_status(&state, v["approval_id"].as_i64().unwrap()), "pending");
}

#[tokio::test]
async fn a_requested_pass_is_consumed_by_the_identical_call_and_not_by_its_requester() {
    let mut cfg = gated_config();
    cfg.approval_tools = vec!["task_add".into(), "task_list".into()];
    let (app, state) = app(cfg);
    let req = json!({ "tool": "task_add", "payload": { "title": "Planned ahead" } });
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req)).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let id = body_json(resp).await["approval_id"].as_i64().unwrap();
    let approve = json!({ "id": id, "decision": "approve" });
    assert_eq!(
        send(&app, post_json("/api/action/approval", Some(OPERATOR_TOKEN), approve)).await.status(),
        StatusCode::OK
    );
    call(&state, &builder(), "task_add", json!({ "title": "Planned ahead" })).await.unwrap();
    assert_eq!(approval_status(&state, id), "consumed");

    // Self-approval is refused: the operator's own request needs another human.
    let req = json!({ "tool": "task_list", "payload": {} });
    let resp = send(&app, post_json("/api/approvals/request", Some(OPERATOR_TOKEN), req)).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let own = body_json(resp).await["approval_id"].as_i64().unwrap();
    let approve = json!({ "id": own, "decision": "approve" });
    assert_eq!(
        send(&app, post_json("/api/action/approval", Some(OPERATOR_TOKEN), approve)).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(approval_status(&state, own), "pending");
}

#[tokio::test]
async fn request_caps_name_the_cap_that_refused() {
    let (app, state) = app(gated_config());
    for i in 0..20 {
        let req = json!({ "tool": "task_add", "payload": { "title": format!("t{i}") } });
        let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req)).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED, "{i}");
    }
    let req = json!({ "tool": "task_add", "payload": { "title": "one more" } });
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req.clone())).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(body_text(resp).await.contains("already open"));
    // An identical open request still answers with its row.
    let again = json!({ "tool": "task_add", "payload": { "title": "t0" } });
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), again)).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Requests the requester withdrew itself count toward the hourly cap.
    state
        .hub
        .db()
        .write(|tx| {
            tx.execute(
                "UPDATE approvals SET status = 'denied', resolved_by = requested_by WHERE requested_by = 'builder-1'",
                [],
            )?;
            for i in 0..40 {
                tx.execute(
                    "INSERT INTO approvals (tool, payload, requested_by, status, resolved_by, created_at, updated_at) \
                     VALUES ('task_add', ?1, 'builder-1', 'denied', 'builder-1', ?2, ?2)",
                    rusqlite::params![format!("{{\"title\":\"w{i}\"}}"), ua_core::time::now()],
                )?;
            }
            Ok(())
        })
        .unwrap();
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req)).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(body_text(resp).await.contains("last hour"));
}

#[tokio::test]
async fn an_approval_request_meets_the_same_identity_checks_as_a_call() {
    let dir = std::env::temp_dir().join(format!(
        "ua-ui-overlay-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.yaml");
    // The overlay lowers builder-1 to research, which cannot update tasks.
    std::fs::write(
        &policy,
        "version: 1\nenabled: true\nprofile_defaults:\n  builder-1: research\nrules: []\n",
    )
    .unwrap();
    let mut cfg = config();
    cfg.policy_file = Some(policy);
    cfg.approval_tools = vec!["task_update".into(), "task_add".into()];
    let (app, _state) = app(cfg);
    let req = json!({ "tool": "task_update", "payload": { "id": 1, "append_note": "x" } });
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["reason_code"], "profile_denied");
    // Research may still add tasks, so the overlay is what refused above.
    let req = json!({ "tool": "task_add", "payload": { "title": "x" } });
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req)).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let _ = std::fs::remove_dir_all(&dir);

    // The prod-action check: a revoked agent cannot queue an always-gated call.
    let mut cfg = config();
    cfg.revoked_agents = vec!["builder-1".into()];
    let (app, state) = self::app(cfg);
    let req = json!({ "tool": "crew_intervene", "payload": { "session_id": "s-1", "message": "stop" } });
    let resp = send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), req)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["reason_code"], "agent_revoked");
    assert_eq!(approvals_containing(&state, "%"), 0);
}

#[tokio::test]
async fn an_approval_request_honours_policy_rules() {
    let dir = std::env::temp_dir().join(format!(
        "ua-ui-policy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.yaml");
    std::fs::write(
        &policy,
        "version: 1\nenabled: true\nrules:\n  - name: lists-need-a-human\n    type: tool\n    tool: task_list\n    \
         action: require_approval\n  - name: no-adds\n    type: tool\n    tool: task_add\n    action: deny\n",
    )
    .unwrap();
    let mut cfg = config();
    cfg.policy_file = Some(policy);
    cfg.approval_tools = vec!["task_add".into()];
    let (app, _state) = app(cfg);

    // A policy require_approval rule gates the call, so it can be requested.
    let resp =
        send(&app, post_json("/api/approvals/request", Some(BUILDER_TOKEN), json!({ "tool": "task_list" })))
            .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    // A policy deny refuses the request, even for a tool in approval_tools.
    let resp = send(
        &app,
        post_json(
            "/api/approvals/request",
            Some(BUILDER_TOKEN),
            json!({ "tool": "task_add", "payload": { "title": "x" } }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["reason_code"], "policy_deny");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Sign out

/// The value of the `name` attribute's sibling `value` in the first
/// `<input ... name="{name}" ... value="...">` of `html`.
fn hidden_input(html: &str, name: &str) -> Option<String> {
    let at = html.find(&format!("name=\"{name}\""))?;
    let tag_start = html[..at].rfind('<')?;
    let tag_end = at + html[at..].find('>')?;
    let tag = &html[tag_start..tag_end];
    let v = tag.find("value=\"")? + "value=\"".len();
    Some(tag[v..v + tag[v..].find('"')?].to_string())
}

#[tokio::test]
async fn sign_out_is_a_post_form_with_the_session_csrf_token() {
    let hub = common::TestHub::new(common::config());
    let cookie = hub.sign_in("operator").await;
    let page = hub.send(common::get("/ui/inbox", Some(&cookie), None)).await;
    assert_eq!(page.status(), StatusCode::OK);
    let html = common::text_body(page).await;

    // No GET link to /logout (the route is POST-only), and no inline script.
    assert!(!html.contains("href=\"/logout\""), "sign out is still a GET link");
    assert!(!html.contains("onclick") && !html.contains("<script>"), "inline script in the layout");
    let form_at = html.find("action=\"/logout\"").expect("a sign-out form");
    let form = &html[html[..form_at].rfind("<form").unwrap()..];
    let form = &form[..form.find("</form>").unwrap()];
    assert!(form.contains("method=\"post\""), "{form}");
    assert!(form.contains("type=\"submit\""), "{form}");

    // The form carries the session's CSRF token, and submitting it ends the
    // session.
    let token = hidden_input(form, "csrf").expect("a csrf field");
    assert_eq!(token, hub.csrf(&cookie).await);
    let out = hub.send(common::form("/logout", &[("csrf", &token)], Some(&cookie))).await;
    assert!(out.status().is_redirection(), "{}", out.status());
    assert_eq!(common::location(&out), "/login");
    let after = hub.send(common::get("/api/whoami", Some(&cookie), None)).await;
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
}
