//! The native GitHub connector against a local mock of the REST API: CI
//! verification, webhook signatures and replays, close-on-merge, polling
//! with ETags, policy authorizations and the review-ready notification.
//! Nothing here reaches the real GitHub.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::families::github::{WebhookDelivery, WebhookError, poll_once, receive, signature_for};
use ua_tools::{Hub, Registry, builtin_registry};

const FULL: &str = "abcdef1234567abcdef1234567abcdef12345678";
const OTHER_FULL: &str = "1111111111111111111111111111111111111111";
const MERGE_SHA: &str = "fedcba9876543210fedcba9876543210fedcba98";
const SECRET: &str = "webhook-test-secret";
const REPO: &str = "example/repo";

// --- the mock GitHub ------------------------------------------------------------------

#[derive(Default)]
struct Mock {
    runs: HashMap<u64, Value>,
    jobs: HashMap<u64, Value>,
    check_runs: HashMap<u64, Value>,
    pulls: HashMap<u64, Value>,
    open: Vec<Value>,
    open_etag: String,
    /// (path and query, If-None-Match, status, had a bearer token)
    log: Vec<(String, Option<String>, u16, bool)>,
}

type Shared = Arc<Mutex<Mock>>;

async fn serve_mock(State(m): State<Shared>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let pq = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let h: &HeaderMap = req.headers();
    let inm = h.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()).map(str::to_string);
    let auth = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) == Some("Bearer test-token");
    let mut m = m.lock().unwrap();
    let rest = path.strip_prefix("/repos/example/repo/").unwrap_or("");
    let parts: Vec<&str> = rest.split('/').collect();
    let num = |i: usize| parts.get(i).and_then(|p| p.parse::<u64>().ok());
    let (status, body, etag): (u16, Value, Option<String>) = match parts.as_slice() {
        ["actions", "runs", _] => match num(2).and_then(|id| m.runs.get(&id).cloned()) {
            Some(v) => (200, v, None),
            None => (404, json!({ "message": "Not Found" }), None),
        },
        ["actions", "runs", _, "jobs"] => match num(2).and_then(|id| m.jobs.get(&id).cloned()) {
            Some(v) => (200, v, None),
            None => (404, json!({ "message": "Not Found" }), None),
        },
        ["check-runs", _] => match num(1).and_then(|id| m.check_runs.get(&id).cloned()) {
            Some(v) => (200, v, None),
            None => (404, json!({ "message": "Not Found" }), None),
        },
        ["pulls"] => {
            if inm.as_deref() == Some(m.open_etag.as_str()) {
                (304, Value::Null, Some(m.open_etag.clone()))
            } else {
                (200, json!(m.open), Some(m.open_etag.clone()))
            }
        }
        ["pulls", _] => match num(1).and_then(|n| m.pulls.get(&n).cloned()) {
            Some(v) => (200, v, None),
            None => (404, json!({ "message": "Not Found" }), None),
        },
        _ => (404, json!({ "message": "Not Found" }), None),
    };
    m.log.push((pq, inm, status, auth));
    let mut resp = if status == 304 {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (StatusCode::from_u16(status).unwrap(), axum::Json(body)).into_response()
    };
    resp.headers_mut().insert("x-ratelimit-remaining", "4999".parse().unwrap());
    if let Some(tag) = etag {
        resp.headers_mut().insert(header::ETAG, tag.parse().unwrap());
    }
    resp
}

async fn start_mock() -> (Shared, String) {
    let state: Shared = Arc::default();
    let app = Router::new().fallback(serve_mock).with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (state, format!("http://{addr}"))
}

fn run(head: &str, status: &str, conclusion: Option<&str>) -> Value {
    json!({ "head_sha": head, "status": status, "conclusion": conclusion, "name": "CI" })
}

fn job(name: &str, head: &str, conclusion: &str, attempt: u64) -> Value {
    json!({ "name": name, "head_sha": head, "status": "completed", "conclusion": conclusion, "run_attempt": attempt })
}

fn pull(number: u64, head: &str, merged: bool) -> Value {
    json!({
        "number": number,
        "merged": merged,
        "merged_at": if merged { json!("2026-11-20T10:00:00Z") } else { Value::Null },
        "merge_commit_sha": MERGE_SHA,
        "head": { "ref": format!("feature-{number}"), "sha": head },
        "html_url": format!("https://github.com/example/repo/pull/{number}"),
    })
}

// --- the hub --------------------------------------------------------------------------

fn caller(label: &str, kind: ActorKind, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
    }
}

fn builder() -> Caller {
    caller("builder-1", ActorKind::Agent, Profile::Developer)
}

fn lead() -> Caller {
    caller("lead-1", ActorKind::Agent, Profile::Coordinator)
}

fn human() -> Caller {
    Caller { enforce_profile: false, ..caller("operator", ActorKind::Human, Profile::Operator) }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

struct H {
    hub: Hub,
    reg: Registry,
    mock: Shared,
    _dir: tempfile::TempDir,
}

impl H {
    async fn new() -> Self {
        Self::with(|_| {}).await
    }

    async fn with(tweak: impl FnOnce(&mut Config)) -> Self {
        let (mock, base) = start_mock().await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        cfg.fetch_allow_loopback = true;
        cfg.github_api_url = base;
        cfg.github_token_value = Some("test-token".to_string().into());
        cfg.github_webhook_secret_value = Some(SECRET.to_string().into());
        tweak(&mut cfg);
        let hub = Hub::in_memory(cfg).unwrap();
        Self { hub, reg: builtin_registry(), mock, _dir: dir }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) failed: {e:?}"),
        }
    }

    async fn act(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
    }

    async fn act_ok(&self, who: &Caller, action: &str, params: Value) -> Value {
        match self.act(who, action, params.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{action}({params}) failed: {e:?}"),
        }
    }

    async fn bind(&self) {
        self.act_ok(&human(), "project_repo_bind", json!({ "project": "default", "repo": REPO })).await;
    }

    async fn task(&self, title: &str, evidence: Option<&str>) -> i64 {
        let id = self.ok(&builder(), "task_add", json!({ "title": title })).await["id"].as_i64().unwrap();
        if let Some(e) = evidence {
            self.ok(&builder(), "task_update", json!({ "id": id, "evidence_ref": e })).await;
        }
        id
    }

    async fn get_task(&self, id: i64) -> Value {
        self.hub
            .db()
            .read(move |c| {
                Ok(c.query_row("SELECT status, evidence_ref, notes FROM tasks WHERE id = ?1", [id], |r| {
                    Ok(json!({
                        "status": r.get::<_, String>(0)?,
                        "evidence_ref": r.get::<_, Option<String>>(1)?,
                        "notes": r.get::<_, Option<String>>(2)?,
                    }))
                })?)
            })
            .unwrap()
    }

    async fn events(&self, channel: &str) -> Vec<Value> {
        let out = self.ok(&human(), "event_log_query", json!({ "channels": [channel] })).await;
        out["events"].as_array().cloned().unwrap_or_default()
    }

    fn requests(&self) -> Vec<(String, Option<String>, u16, bool)> {
        self.mock.lock().unwrap().log.clone()
    }

    async fn deliver(&self, event: &str, id: &str, payload: &Value) -> Result<Value, WebhookError> {
        let body = serde_json::to_vec(payload).unwrap();
        let sig = signature_for(SECRET.as_bytes(), &body);
        receive(&self.hub, WebhookDelivery { event, delivery_id: id, signature: Some(&sig), body: &body })
            .await
    }
}

fn check<'a>(view: &'a Value, name: &str) -> &'a Value {
    view["checks"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("{view}"))
}

fn record(task: i64, name: &str, run_id: u64, job: Option<&str>) -> Value {
    let mut r = json!({ "kind": "ci_run", "ref": run_id.to_string() });
    if let Some(j) = job {
        r["job"] = json!(j);
    }
    json!({ "task_id": task, "name": name, "outcome": "pass", "head_sha": FULL, "ref": r })
}

// --- CI verification ------------------------------------------------------------------

#[tokio::test]
async fn checks_are_verified_or_contradicted_by_the_forge() {
    let h = H::new().await;
    {
        let mut m = h.mock.lock().unwrap();
        m.runs.insert(101, run(FULL, "completed", Some("success")));
        m.jobs.insert(
            101,
            json!({ "total_count": 4, "jobs": [
                job("unit", FULL, "success", 1), job("unit", FULL, "success", 2),
                job("lint", FULL, "skipped", 1), job("flaky", FULL, "failure", 1),
            ]}),
        );
        m.runs.insert(102, run(OTHER_FULL, "completed", Some("success")));
        m.runs.insert(103, run(FULL, "completed", Some("failure")));
        m.runs.insert(104, run(FULL, "in_progress", None));
        m.check_runs.insert(
            201,
            json!({ "head_sha": FULL, "status": "completed", "conclusion": "success", "name": "build" }),
        );
    }
    let t = h.task("verify me", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    h.bind().await;

    // The whole run.
    let v = h.act_ok(&builder(), "task_check_record", record(t, "ci", 101, None)).await;
    let c = check(&v, "ci");
    assert_eq!((c["grade"].as_str(), c["verified_scope"].as_str()), (Some("verified"), Some("run")), "{c}");
    assert_eq!(c["verification"]["observed"]["kind"], "workflow_run");
    // One job, run twice, agreeing both times.
    let v = h.act_ok(&builder(), "task_check_record", record(t, "tests", 101, Some("unit"))).await;
    let c = check(&v, "tests");
    assert_eq!((c["grade"].as_str(), c["verified_scope"].as_str()), (Some("verified"), Some("job")), "{c}");
    assert_eq!(c["verification"]["observed"]["attempts"].as_array().unwrap().len(), 2);
    // A skipped job, a failed job and a missing job contradict a pass.
    for (name, job_name) in [("lint", "lint"), ("flaky", "flaky"), ("ghost", "nope")] {
        let v = h.act_ok(&builder(), "task_check_record", record(t, name, 101, Some(job_name))).await;
        let c = check(&v, name);
        assert_eq!(
            (c["grade"].as_str(), c["verification"]["verdict"].as_str()),
            (Some("attested"), Some("mismatch")),
            "{c}"
        );
    }
    // Another head, another conclusion: contradicted. Still running: insufficient.
    let v = h.act_ok(&builder(), "task_check_record", record(t, "other-head", 102, None)).await;
    assert_eq!(check(&v, "other-head")["verification"]["verdict"], "mismatch");
    let v = h.act_ok(&builder(), "task_check_record", record(t, "failed", 103, None)).await;
    assert_eq!(check(&v, "failed")["verification"]["verdict"], "mismatch");
    assert!(v["summary"]["contradicted"].as_array().unwrap().iter().any(|n| n == "failed"), "{v}");
    let v = h.act_ok(&builder(), "task_check_record", record(t, "running", 104, None)).await;
    let c = check(&v, "running");
    assert_eq!(
        (c["grade"].as_str(), c["verification"]["verdict"].as_str()),
        (Some("attested"), Some("insufficient"))
    );
    // A check run id: verified as the run, and as the job only under its own name.
    let v = h.act_ok(&builder(), "task_check_record", record(t, "build", 201, Some("build"))).await;
    assert_eq!(check(&v, "build")["grade"], "verified", "{v}");
    assert_eq!(check(&v, "build")["verification"]["observed"]["kind"], "check_run");
    let v = h.act_ok(&builder(), "task_check_record", record(t, "build2", 201, Some("deploy"))).await;
    assert_eq!(check(&v, "build2")["verification"]["verdict"], "mismatch");

    // Every request carried the token and stayed in the bound repository.
    let log = h.requests();
    assert!(!log.is_empty());
    assert!(log.iter().all(|(p, _, _, auth)| *auth && p.starts_with("/repos/example/repo/")), "{log:?}");
}

#[tokio::test]
async fn without_a_token_nothing_is_looked_up() {
    let h = H::with(|c| c.github_token_value = None).await;
    h.mock.lock().unwrap().runs.insert(101, run(FULL, "completed", Some("success")));
    let t = h.task("no token", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    h.bind().await;
    let v = h.act_ok(&builder(), "task_check_record", record(t, "ci", 101, None)).await;
    let c = check(&v, "ci");
    assert_eq!(
        (c["grade"].as_str(), c["verification"]["verdict"].as_str()),
        (Some("attested"), Some("unverifiable"))
    );
    assert!(c["verification"]["detail"].as_str().unwrap().contains("github_token_env"), "{c}");
    assert!(h.requests().is_empty(), "no request without a token");
}

// --- webhooks -------------------------------------------------------------------------

fn merged_payload(number: u64) -> Value {
    json!({
        "action": "closed",
        "number": number,
        "pull_request": pull(number, FULL, true),
        "repository": { "full_name": "Example/Repo" },
    })
}

#[tokio::test]
async fn webhook_signatures_are_checked_and_replays_refused() {
    let h = H::new().await;
    h.bind().await;
    let body = serde_json::to_vec(&json!({ "zen": "hi", "repository": { "full_name": REPO } })).unwrap();
    let good = signature_for(SECRET.as_bytes(), &body);
    let bad = signature_for(b"not the secret", &body);
    let send = |sig: Option<String>, id: &str| {
        let body = body.clone();
        let hub = h.hub.clone();
        let id = id.to_string();
        async move {
            receive(
                &hub,
                WebhookDelivery { event: "ping", delivery_id: &id, signature: sig.as_deref(), body: &body },
            )
            .await
        }
    };
    assert_eq!(send(Some(bad), "d-1").await.unwrap_err(), WebhookError::BadSignature);
    assert_eq!(send(None, "d-1").await.unwrap_err(), WebhookError::BadSignature);
    let ok = send(Some(good.clone()), "d-1").await.unwrap();
    assert_eq!(ok["handled"], "ping");
    // The same delivery again is a replay; a bad signature never reaches the replay table.
    assert_eq!(send(Some(good.clone()), "d-1").await.unwrap_err(), WebhookError::Replayed);
    assert_eq!(
        send(Some(good.clone()), "D-1").await.unwrap_err(),
        WebhookError::Replayed,
        "ids are case-blind"
    );
    assert!(matches!(send(Some(good.clone()), "bad id!").await, Err(WebhookError::BadRequest(_))));
    assert_eq!(h.events("agent.github.webhook.received").await.len(), 1);

    // Without a secret, everything is refused.
    let h2 = H::with(|c| c.github_webhook_secret_value = None).await;
    let r = receive(
        &h2.hub,
        WebhookDelivery { event: "ping", delivery_id: "d-2", signature: Some(&good), body: &body },
    )
    .await;
    assert_eq!(r.unwrap_err(), WebhookError::NotConfigured);
}

#[tokio::test]
async fn a_merged_pull_request_closes_the_task_that_links_it() {
    let h = H::new().await;
    h.bind().await;
    let linked = h.task("ship the feature", Some("https://github.com/example/repo/pull/7")).await;
    let in_notes = h.task("noted", None).await;
    h.ok(&builder(), "task_update", json!({ "id": in_notes, "append_note": "work is in example/repo#7" }))
        .await;
    let ambiguous = h.task("two prs", Some("example/repo#7 and example/repo#8")).await;
    let claimed = h.task("still being worked", Some("example/repo#7")).await;
    h.ok(&builder(), "task_claim", json!({ "id": claimed })).await;
    let unrelated = h.task("other pr", Some("example/repo#9")).await;

    let out = h.deliver("pull_request", "merge-1", &merged_payload(7)).await.unwrap();
    assert_eq!(out["handled"], "closed_on_merge", "{out}");
    let closed: Vec<i64> =
        out["result"]["closed"].as_array().unwrap().iter().map(|c| c["task_id"].as_i64().unwrap()).collect();
    assert_eq!(closed, vec![linked, in_notes], "{out}");

    let t = h.get_task(linked).await;
    assert_eq!(t["status"], "done");
    assert_eq!(t["evidence_ref"], MERGE_SHA);
    assert!(t["notes"].as_str().unwrap().contains("[github: closed-on-merge"), "{t}");
    assert!(
        t["notes"].as_str().unwrap().contains("prior evidence_ref: https://github.com/example/repo/pull/7")
    );
    assert_eq!(h.get_task(ambiguous).await["status"], "open");
    assert_eq!(h.get_task(claimed).await["status"], "doing");
    assert_eq!(h.get_task(unrelated).await["status"], "open");
    assert_eq!(out["result"]["ambiguous"][0]["task_id"], ambiguous);
    assert!(out["result"]["blocked"][0]["reason"].as_str().unwrap().contains("live claim"), "{out}");

    let events = h.events("agent.github.closed_on_merge").await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["payload"]["merge_sha"], MERGE_SHA, "{events:?}");
    // The close went through task_update as the hub's GitHub identity.
    let updates = h.events("agent.task.completed").await;
    assert!(updates.iter().any(|e| e["originator"] == "hub-github"), "{updates:?}");

    // An unmerged close, or a repository no project is bound to, does nothing.
    let mut unmerged = merged_payload(9);
    unmerged["pull_request"]["merged"] = json!(false);
    assert_eq!(h.deliver("pull_request", "merge-2", &unmerged).await.unwrap()["handled"], false);
    let mut elsewhere = merged_payload(9);
    elsewhere["repository"]["full_name"] = json!("other/repo");
    let out = h.deliver("pull_request", "merge-3", &elsewhere).await.unwrap();
    assert_eq!(out["handled"], false);
    assert_eq!(h.get_task(unrelated).await["status"], "open");
}

#[tokio::test]
async fn a_completed_run_re_verifies_the_checks_at_its_head() {
    let h = H::new().await;
    h.mock.lock().unwrap().runs.insert(301, run(FULL, "in_progress", None));
    let t = h.task("waiting on ci", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    h.bind().await;
    let v = h.act_ok(&builder(), "task_check_record", record(t, "ci", 301, None)).await;
    assert_eq!(check(&v, "ci")["verification"]["verdict"], "insufficient");

    h.mock.lock().unwrap().runs.insert(301, run(FULL, "completed", Some("success")));
    let payload = json!({
        "action": "completed",
        "workflow_run": { "id": 301, "head_sha": FULL, "status": "completed", "conclusion": "success" },
        "repository": { "full_name": REPO },
    });
    let out = h.deliver("workflow_run", "run-1", &payload).await.unwrap();
    assert_eq!(out["handled"], "reverified");
    assert_eq!(out["checks"][0]["grade"], "verified", "{out}");
    let v = h.act_ok(&builder(), "task_workflow_get", json!({ "task_id": t, "head_sha": FULL })).await;
    assert_eq!(check(&v, "ci")["grade"], "verified");
    assert_eq!(h.events("agent.github.checks_reverified").await.len(), 1);
}

// --- polling --------------------------------------------------------------------------

#[tokio::test]
async fn polling_uses_etags_and_closes_merged_prs() {
    let h = H::new().await;
    h.bind().await;
    let t = h.task("polled", Some("example/repo#5")).await;
    {
        let mut m = h.mock.lock().unwrap();
        m.open = vec![pull(5, FULL, false), pull(6, FULL, false)];
        m.open_etag = "\"v1\"".into();
    }
    let first = poll_once(&h.hub).await.unwrap();
    assert_eq!(first["repos"][0]["open"], 2, "{first}");
    let second = poll_once(&h.hub).await.unwrap();
    assert_eq!(second["repos"][0]["not_modified"], true, "{second}");
    let lists: Vec<_> =
        h.requests().into_iter().filter(|r| r.0.starts_with("/repos/example/repo/pulls?")).collect();
    assert_eq!(lists.len(), 2);
    assert_eq!((lists[0].1.as_deref(), lists[0].2), (None, 200));
    assert_eq!((lists[1].1.as_deref(), lists[1].2), (Some("\"v1\""), 304), "the second poll revalidates");
    assert_eq!(h.get_task(t).await["status"], "open");

    // PR 5 merges: it leaves the open list, the lookup says merged, the task closes.
    {
        let mut m = h.mock.lock().unwrap();
        m.open = vec![pull(6, FULL, false)];
        m.open_etag = "\"v2\"".into();
        m.pulls.insert(5, pull(5, FULL, true));
    }
    let third = poll_once(&h.hub).await.unwrap();
    assert_eq!(third["repos"][0]["merged"], json!([5]), "{third}");
    let task = h.get_task(t).await;
    assert_eq!((task["status"].as_str(), task["evidence_ref"].as_str()), (Some("done"), Some(MERGE_SHA)));
    assert_eq!(h.events("agent.github.polled").await.len(), 1);
}

#[tokio::test]
async fn queue_close_merged_is_a_dry_run_by_default() {
    let h = H::new().await;
    h.bind().await;
    let t = h.task("on demand", Some("https://github.com/example/repo/pull/11")).await;
    let open_pr = h.task("not merged yet", Some("example/repo#12")).await;
    {
        let mut m = h.mock.lock().unwrap();
        m.pulls.insert(11, pull(11, FULL, true));
        m.pulls.insert(12, pull(12, FULL, false));
    }
    let dry = h.act_ok(&lead(), "queue_close_merged", json!({})).await;
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["would_close"][0]["task_id"], t, "{dry}");
    assert_eq!(h.get_task(t).await["status"], "open", "a dry run writes nothing");

    let e = h
        .act(
            &caller("research-1", ActorKind::Agent, Profile::Research),
            "queue_close_merged",
            json!({ "dry_run": false }),
        )
        .await
        .unwrap_err();
    assert!(["action_denied", "profile_denied"].contains(&reason(&e).as_str()), "{e:?}");
    let real = h.act_ok(&lead(), "queue_close_merged", json!({ "dry_run": false })).await;
    assert_eq!(real["closed"][0]["task_id"], t, "{real}");
    assert_eq!(h.get_task(t).await["status"], "done");
    assert_eq!(h.get_task(open_pr).await["status"], "open");
}

// --- review-ready notification and the review queue -----------------------------------

#[tokio::test]
async fn review_ready_notifies_once_when_every_expected_check_is_verified() {
    let h = H::new().await;
    h.mock.lock().unwrap().runs.insert(101, run(FULL, "completed", Some("success")));
    let t = h.task("review me", None).await;
    let other = h.task("still implementing", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    h.ok(&builder(), "task_claim", json!({ "id": other })).await;
    h.bind().await;
    h.act_ok(
        &builder(),
        "task_workflow_set",
        json!({ "task_id": t, "stage": "review", "head_sha": FULL, "expected_checks": ["ci", "lint"] }),
    )
    .await;
    h.act_ok(&builder(), "task_workflow_set", json!({ "task_id": other, "stage": "implement" })).await;

    let outbox = |hub: &Hub| {
        hub.db()
            .read(|c| {
                let mut s = c.prepare("SELECT category, message FROM notify_outbox ORDER BY id")?;
                let rows = s
                    .query_map([], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .unwrap()
    };
    // One of two expected checks verified: not ready.
    h.act_ok(&builder(), "task_check_record", record(t, "ci", 101, None)).await;
    assert!(outbox(&h.hub).is_empty());
    h.act_ok(&builder(), "task_check_record", record(t, "lint", 101, None)).await;
    let rows = outbox(&h.hub);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0.as_deref(), Some("review_ready"));
    assert!(rows[0].1.as_deref().unwrap().contains(&format!("Task #{t} is ready for review")), "{rows:?}");
    // Verifying again at the same head does not notify twice.
    h.act_ok(&builder(), "task_check_verify", json!({ "task_id": t, "name": "ci", "head_sha": FULL })).await;
    assert_eq!(outbox(&h.hub).len(), 1);

    // The review queue is a task_list filter.
    let list = h.ok(&builder(), "task_list", json!({ "stage": "review" })).await;
    let ids: Vec<i64> = list["tasks"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
    assert_eq!(ids, vec![t]);
    assert_eq!(
        h.call(&builder(), "task_list", json!({ "stage": "shipping" })).await.unwrap_err().code(),
        "invalid_argument"
    );
}

// --- policy authorizations ------------------------------------------------------------

fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A workspace repository with branch `task-7` one commit ahead of main.
fn workspace_with_branch(ws: &Path) -> String {
    git(ws, &["init", "-q", "-b", "main"]);
    for (k, v) in [
        ("user.name", "builder-1"),
        ("user.email", "builder-1@example.com"),
        ("commit.gpgsign", "false"),
        ("core.hooksPath", "/dev/null"),
    ] {
        git(ws, &["config", k, v]);
    }
    std::fs::write(ws.join("README.md"), "readme\n").unwrap();
    git(ws, &["add", "README.md"]);
    git(ws, &["commit", "-q", "-m", "chore: initial commit"]);
    git(ws, &["checkout", "-q", "-b", "task-7"]);
    std::fs::write(ws.join("feature.txt"), "feature\n").unwrap();
    git(ws, &["add", "feature.txt"]);
    git(ws, &["commit", "-q", "-m", "feat: add feature"]);
    let head = git(ws, &["rev-parse", "HEAD"]);
    git(ws, &["checkout", "-q", "main"]);
    head
}

#[tokio::test]
async fn policy_authorizations_are_recorded_consumed_and_expire() {
    if !have_git() {
        eprintln!("git not installed; skipping");
        return;
    }
    let ws_dir = tempfile::tempdir().unwrap();
    let ws = ws_dir.path().canonicalize().unwrap();
    let h = H::with(|c| c.workspace = Some(ws.clone())).await;
    let head = workspace_with_branch(&ws);
    h.bind().await;
    let t = h.task("merge me", None).await;
    h.hub
        .db()
        .write(move |tx| {
            Ok(tx.execute("UPDATE tasks SET status = 'done', branch = 'task-7' WHERE id = ?1", [t])?)
        })
        .unwrap();
    let open_task = h.task("authorize me", None).await;
    let rec = |task: i64, sha: &str| json!({ "repo": REPO, "pr": 7, "head_sha": sha, "task_id": task, "policy_ref": "release-policy-2026-11" });

    // Only a human records one, never for a closed task, an unbound repo or its own claim.
    let e = h.call(&lead(), "policy_authorization_record", rec(open_task, &head)).await.unwrap_err();
    assert_eq!(reason(&e), "not_human");
    let e = h.call(&builder(), "policy_authorization_record", rec(open_task, &head)).await.unwrap_err();
    assert_eq!(reason(&e), "profile_denied");
    let e = h.call(&human(), "policy_authorization_record", rec(t, &head)).await.unwrap_err();
    assert_eq!(e.code(), "conflict", "a closed task: {e:?}");
    let mut short = rec(open_task, &head);
    short["head_sha"] = json!(&head[..12]);
    assert_eq!(
        h.call(&human(), "policy_authorization_record", short).await.unwrap_err().code(),
        "invalid_argument"
    );
    let mut elsewhere = rec(open_task, &head);
    elsewhere["repo"] = json!("other/repo");
    assert_eq!(
        reason(&h.call(&human(), "policy_authorization_record", elsewhere).await.unwrap_err()),
        "repo_not_bound"
    );
    h.ok(&human(), "task_update", json!({ "id": open_task, "next_owner": "operator" })).await;
    let e = h.call(&human(), "policy_authorization_record", rec(open_task, &head)).await.unwrap_err();
    assert_eq!(reason(&e), "self_authorization");

    // Record one for the task while it is open, then let the task finish.
    h.hub
        .db()
        .write(move |tx| Ok(tx.execute("UPDATE tasks SET status = 'doing' WHERE id = ?1", [t])?))
        .unwrap();
    let auth = h.ok(&human(), "policy_authorization_record", rec(t, &head)).await;
    let auth_id = auth["authorization"]["id"].as_i64().unwrap();
    assert_eq!(auth["authorization"]["valid"], true);
    let wrong =
        h.ok(&human(), "policy_authorization_record", rec(t, OTHER_FULL)).await["authorization"]["id"]
            .as_i64()
            .unwrap();
    h.hub
        .db()
        .write(move |tx| Ok(tx.execute("UPDATE tasks SET status = 'done' WHERE id = ?1", [t])?))
        .unwrap();
    let listed = h.ok(&lead(), "policy_authorization_list", json!({ "task_id": t, "head_sha": head })).await;
    assert_eq!(listed["count"], 1, "{listed}");

    // Expiry: a lapsed authorization is listed as expired and covers nothing.
    let t2 = h.task("expires", None).await;
    let auth2 = h.ok(&human(), "policy_authorization_record", rec(t2, &head)).await["authorization"]["id"]
        .as_i64()
        .unwrap();
    h.hub
        .db()
        .write(move |tx| {
            tx.execute("UPDATE tasks SET status = 'done', branch = 'task-7' WHERE id = ?1", [t2])?;
            Ok(tx.execute(
                "UPDATE policy_authorizations SET expires_at = '2020-01-01T00:00:00+00:00' WHERE id = ?1",
                [auth2],
            )?)
        })
        .unwrap();
    let listed =
        h.ok(&lead(), "policy_authorization_list", json!({ "task_id": t2, "include_inactive": true })).await;
    assert_eq!(
        (listed["authorizations"][0]["state"].as_str(), listed["authorizations"][0]["valid"].as_bool()),
        (Some("expired"), Some(false))
    );
    assert_eq!(h.ok(&lead(), "policy_authorization_list", json!({ "task_id": t2 })).await["count"], 0);
    let e = h
        .call(&lead(), "git_merge_task", json!({ "task_id": t2, "policy_authorization_id": auth2 }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "policy_authorization_mismatch", "{e:?}");
    // Nor does one recorded for another task.
    let e = h
        .call(
            &lead(),
            "git_merge_task",
            json!({ "task_id": t2, "dry_run": true, "policy_authorization_id": auth_id }),
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "policy_authorization_mismatch", "{e:?}");

    // An authorization for another head does not cover this merge.
    let e = h
        .call(&lead(), "git_merge_task", json!({ "task_id": t, "policy_authorization_id": wrong }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "policy_authorization_mismatch");
    // A dry run reports coverage and spends nothing; without the id the approval gate applies.
    let dry = h
        .ok(
            &lead(),
            "git_merge_task",
            json!({ "task_id": t, "dry_run": true, "policy_authorization_id": auth_id }),
        )
        .await;
    assert_eq!(dry["policy_authorization_id"], auth_id);
    assert_eq!(
        h.call(&lead(), "git_merge_task", json!({ "task_id": t })).await.unwrap_err().code(),
        "approval_required"
    );
    // The real merge spends it, with no approval.
    let merged =
        h.ok(&lead(), "git_merge_task", json!({ "task_id": t, "policy_authorization_id": auth_id })).await;
    assert_eq!(merged["success"], true, "{merged}");
    assert!(ws.join("feature.txt").exists());
    let e = h
        .call(&lead(), "git_merge_task", json!({ "task_id": t, "policy_authorization_id": auth_id }))
        .await
        .unwrap_err();
    assert!(["policy_authorization_mismatch", "not_found"].contains(&reason(&e).as_str()), "{e:?}");
    assert_eq!(h.events("agent.github.policy_authorization.consumed").await.len(), 1);
    let all =
        h.ok(&lead(), "policy_authorization_list", json!({ "task_id": t, "include_inactive": true })).await;
    let states: Vec<&str> =
        all["authorizations"].as_array().unwrap().iter().map(|a| a["state"].as_str().unwrap()).collect();
    assert_eq!(states, vec!["active", "consumed"], "{all}");
}
