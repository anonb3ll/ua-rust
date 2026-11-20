//! The TypeScript SDK's platform routes over HTTP: `/api/runs`,
//! `/api/platform/*` and `/api/evidence`, called the way
//! `ControlCenterClient` calls them (bearer header, JSON bodies), with the
//! response keys its Zod schemas require.

mod common;

use axum::http::{StatusCode, header};
use common::{TestHub, get, json_body, post_json};
use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::Config;
use ua_store::{EventInput, ledger};

const BUILDER: &str = "builder-1-test-token-0001";
const OTHER: &str = "builder-2-test-token-0002";
const OPERATOR: &str = "operator-test-token-0003";
const PUBLIC: &str = "public-test-token-0004";

fn config() -> Config {
    let mut cfg = common::config();
    cfg.oauth_enabled = false;
    cfg.agent_tokens = Some(SecretString::from(format!(
        "builder-1:{BUILDER},builder-2:{OTHER},operator:{OPERATOR},viewer-1:{PUBLIC}"
    )));
    cfg.profiles.insert("viewer-1".into(), "public".into());
    // The human operator runs the operator allow-list profile.
    cfg.profiles.insert("operator".into(), "operator".into());
    cfg
}

async fn read(hub: &TestHub, path: &str, token: &str) -> (StatusCode, Value) {
    let resp = hub.send(get(path, None, Some(token))).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

async fn post(hub: &TestHub, path: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
    let auth = token.map(|t| format!("Bearer {t}"));
    let headers: Vec<(&str, &str)> = auth.as_deref().map(|a| vec![("authorization", a)]).unwrap_or_default();
    let resp = hub.send(post_json(path, &body, &headers)).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

/// The keys the SDK's `Run` schema requires, with their types.
fn assert_sdk_run(run: &Value) {
    assert!(run["run_id"].as_str().is_some_and(|s| !s.is_empty()), "{run}");
    assert!(["dispatch", "selfpickup", "session"].contains(&run["kind"].as_str().unwrap()), "{run}");
    assert!(run["task_id"].is_i64() || run["task_id"].is_null(), "{run}");
    assert!(run["agent"].is_string() || run["agent"].is_null(), "{run}");
    assert!(run["status"].as_str().is_some_and(|s| !s.is_empty()), "{run}");
    for k in ["outcome", "started_at", "ended_at", "lease_expires_at", "abandon_reason"] {
        assert!(run[k].is_string() || run[k].is_null(), "{k}: {run}");
    }
    assert!(run["abandoned"].is_boolean(), "{run}");
    let links = &run["links"];
    for k in ["self", "task"] {
        assert!(links.get(k).is_some(), "links.{k}: {run}");
        if !links[k].is_null() {
            for f in ["kind", "id", "uri"] {
                assert!(links[k][f].as_str().is_some_and(|s| !s.is_empty()), "links.{k}.{f}: {run}");
            }
        }
    }
    assert!(links["evidence"].is_array(), "{run}");
}

/// One task plus a run in every store, with ledger events that name them.
async fn seed(hub: &TestHub) -> i64 {
    let (status, task) = post(hub, "/api/tasks", Some(BUILDER), json!({ "title": "seeded" })).await;
    assert_eq!(status, StatusCode::CREATED, "{task}");
    let tid = task["id"].as_i64().unwrap();
    hub.state
        .hub
        .db()
        .write(move |tx| {
            for (run, state, lease, created) in [
                ("run-1-aa", "running", Some("2026-01-01T00:00:00+00:00"), "2026-11-01T10:00:00+00:00"),
                ("run-1-bb", "finished", None, "2026-11-01T08:00:00+00:00"),
            ] {
                tx.execute(
                    "INSERT INTO dispatch_runs (run_id, task_id, agent_label, state, actor, lease_expires_at, \
                     created_at, updated_at) VALUES (?1, ?2, 'builder-1', ?3, 'builder-1', ?4, ?5, ?5)",
                    rusqlite::params![run, tid, state, lease, created],
                )?;
            }
            tx.execute(
                "INSERT INTO agent_sessions (id, agent, kind, status, started_at, last_heartbeat_at, task_id, \
                 external_session_id) VALUES ('01SESSION', 'builder-2', 'node', 'running', \
                 '2026-11-01T11:00:00+00:00', '2026-11-01T11:00:00+00:00', ?1, 'acp-1')",
                [tid],
            )?;
            tx.execute(
                "INSERT INTO workflow_runs (run_id, kind, name, definition_digest, definition, task_id, owner, \
                 owner_profile, status, created_at, updated_at, completed_at) VALUES ('wf-1', 'workflow', \
                 'smoke', 'd', '{}', ?1, 'builder-1', 'developer', 'done', '2026-11-01T09:00:00+00:00', \
                 '2026-11-01T09:05:00+00:00', '2026-11-01T09:05:00+00:00')",
                [tid],
            )?;
            tx.execute(
                "INSERT INTO node_dispatch (id, node, agent, backend, prompt, cwd, timeout_s, run_id, task_id, \
                 status, created_by, created_at, updated_at, session_id) VALUES ('nd-0123456789abcdef', \
                 'node-a', 'builder-2', 'codex', 'do it', '/srv', 600, 'run-1-aa', ?1, 'queued', 'builder-2', \
                 '2026-11-01T12:00:00+00:00', '2026-11-01T12:00:00+00:00', 'acp-1')",
                [tid],
            )?;
            ledger::append(
                tx,
                EventInput::new("agent.dispatch.transition", json!({ "run_id": "run-1-aa", "state": "running" }))
                    .by("builder-1"),
            )?;
            ledger::append(
                tx,
                EventInput::new("agent.node", json!({ "kind": "enqueue", "item_id": "nd-0123456789abcdef" }))
                    .by("builder-2"),
            )?;
            Ok(())
        })
        .unwrap();
    tid
}

#[tokio::test]
async fn runs_list_the_sdk_kinds_by_default_and_page_with_a_cursor() {
    let hub = TestHub::new(config());
    let tid = seed(&hub).await;

    let (status, v) = read(&hub, "/api/runs", BUILDER).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let runs = v["runs"].as_array().unwrap();
    let ids: Vec<&str> = runs.iter().map(|r| r["run_id"].as_str().unwrap()).collect();
    // Newest first; workflow and node rows are opt-in, the SDK rejects their kinds.
    assert_eq!(ids, ["01SESSION", "run-1-aa", "run-1-bb"]);
    runs.iter().for_each(assert_sdk_run);
    assert_eq!(v["count"], 3);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["next_cursor"], Value::Null);
    assert_eq!(v["limit"], 100);

    let live = &runs[1];
    assert_eq!(live["kind"], "dispatch");
    assert_eq!(live["task_id"], tid);
    assert_eq!(live["agent"], "builder-1");
    assert_eq!(live["abandoned"], true, "a lapsed lease reads as abandoned");
    assert_eq!(live["abandon_reason"], "lease_expired");
    assert_eq!(live["outcome"], Value::Null);
    assert_eq!(live["links"]["self"]["uri"], "unified-agent://runs/run-1-aa");
    assert_eq!(live["links"]["task"]["uri"], format!("unified-agent://tasks/{tid}"));
    assert_eq!(live["links"]["evidence"].as_array().unwrap().len(), 1);
    assert_eq!(runs[2]["outcome"], "finished");
    assert!(runs[2]["ended_at"].is_string());

    let session = &runs[0];
    assert_eq!(session["status"], "abandoned", "a stale heartbeat reads as abandoned");
    assert_eq!(session["abandon_reason"], "stale_heartbeat");
    assert_eq!(session["links"]["self"]["kind"], "session");
    assert_eq!(session["links"]["dispatch_run"]["id"], "run-1-aa", "bound through the node item");
    assert_eq!(session["links"]["evidence"].as_array().unwrap().len(), 1);

    // A page of one, then the rest from the cursor.
    let (_, p1) = read(&hub, "/api/runs?limit=1", BUILDER).await;
    assert_eq!(p1["runs"][0]["run_id"], "01SESSION");
    assert_eq!(p1["truncated"], true);
    let cursor = p1["next_cursor"].as_str().unwrap().to_string();
    let q = url::form_urlencoded::Serializer::new(String::new()).append_pair("cursor", &cursor).finish();
    let (_, p2) = read(&hub, &format!("/api/runs?limit=5&{q}"), BUILDER).await;
    let ids: Vec<&str> =
        p2["runs"].as_array().unwrap().iter().map(|r| r["run_id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["run-1-aa", "run-1-bb"]);

    // Filters.
    let (_, v) = read(&hub, "/api/runs?kind=session", BUILDER).await;
    assert_eq!(v["count"], 1);
    let (_, v) = read(&hub, "/api/runs?agent=builder-1", BUILDER).await;
    assert_eq!(v["count"], 2);
    let (_, v) = read(&hub, &format!("/api/runs?task_id={tid}&kind=dispatch"), BUILDER).await;
    assert_eq!(v["count"], 2);
    let (_, v) = read(&hub, "/api/runs?kind=selfpickup", BUILDER).await;
    assert_eq!(v["count"], 0, "the SDK's selfpickup kind is an empty store here");
    for bad in ["/api/runs?kind=bogus", "/api/runs?task_id=abc", "/api/runs?limit=0", "/api/runs?cursor=nope"]
    {
        let (status, v) = read(&hub, bad, BUILDER).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
}

#[tokio::test]
async fn workflow_and_node_runs_are_opt_in_and_node_items_stay_private() {
    let hub = TestHub::new(config());
    seed(&hub).await;

    let (_, v) = read(&hub, "/api/runs?kind=workflow", BUILDER).await;
    let wf = &v["runs"][0];
    assert_eq!(wf["kind"], "workflow");
    assert_eq!(wf["status"], "done");
    assert_eq!(wf["outcome"], "done");
    assert_eq!(wf["agent"], "builder-1");

    // builder-1 neither queued the item nor owns the node: not visible.
    let (_, v) = read(&hub, "/api/runs?kind=node", BUILDER).await;
    assert_eq!(v["count"], 0, "{v}");
    let (status, _) = read(&hub, "/api/runs/nd-0123456789abcdef?kind=node", BUILDER).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The requester and the operator see it.
    for token in [OTHER, OPERATOR] {
        let (_, v) = read(&hub, "/api/runs?kind=node", token).await;
        assert_eq!(v["count"], 1, "{v}");
        let item = &v["runs"][0];
        assert_eq!(item["status"], "queued");
        assert_eq!(item["links"]["dispatch_run"]["id"], "run-1-aa");
        assert_eq!(item["evidence_ref"], "node:node-a:nd-0123456789abcdef");
    }
    let (_, v) = read(&hub, "/api/runs?kind=all", OPERATOR).await;
    assert_eq!(v["count"], 5);
    assert_eq!(v["runs"][0]["run_id"], "nd-0123456789abcdef");
}

#[tokio::test]
async fn one_run_reads_by_id_and_unknown_ids_are_404() {
    let hub = TestHub::new(config());
    seed(&hub).await;
    for id in ["run-1-aa", "01SESSION"] {
        let (status, v) = read(&hub, &format!("/api/runs/{id}"), BUILDER).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["run"]["run_id"], id);
        assert_sdk_run(&v["run"]);
    }
    // getRun only ever receives a kind its schema accepts: a workflow run or
    // node item is 404 unless the caller names its kind.
    let (status, v) = read(&hub, "/api/runs/wf-1", BUILDER).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{v}");
    let (status, _) = read(&hub, "/api/runs/nd-0123456789abcdef", OTHER).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for q in ["kind=workflow", "kind=all"] {
        let (status, v) = read(&hub, &format!("/api/runs/wf-1?{q}"), BUILDER).await;
        assert_eq!(status, StatusCode::OK, "{q}: {v}");
        assert_eq!(v["run"]["kind"], "workflow");
    }
    let (status, v) = read(&hub, "/api/runs/nd-0123456789abcdef?kind=node", OTHER).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["run"]["kind"], "node");
    // A kind filter that excludes the run's store is 404 too.
    let (status, _) = read(&hub, "/api/runs/run-1-aa?kind=session", BUILDER).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = read(&hub, "/api/runs/run-1-aa?kind=bogus", BUILDER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The platform run object still resolves every kind.
    let (status, v) = read(&hub, "/api/platform/objects/run/wf-1", BUILDER).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["run"]["kind"], "workflow");
    let (status, v) = read(&hub, "/api/runs/run-404", BUILDER).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error"], "unknown run");
    // The public profile has no run_get.
    let (status, _) = read(&hub, "/api/runs", PUBLIC).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_platform_manifest_and_objects_follow_the_object_model() {
    let hub = TestHub::new(config());
    let tid = seed(&hub).await;

    let (status, m) = read(&hub, "/api/platform/manifest", BUILDER).await;
    assert_eq!(status, StatusCode::OK, "{m}");
    assert_eq!(m["schema_version"], "1.0");
    assert!(m["product"].is_string());
    let types = m["object_types"].as_array().unwrap();
    for t in types {
        for k in ["kind", "uri", "name", "title", "mime_type", "table", "profile_tool"] {
            assert!(t[k].as_str().is_some_and(|s| !s.is_empty()), "{k}: {t}");
        }
        assert!(t["description"].is_string() && t["collection"].is_boolean() && t["served"].is_boolean());
        assert!(t["id_param"].is_string() || t["id_param"].is_null());
        assert!(t["id_pattern"].is_string() || t["id_pattern"].is_null());
        for k in ["lifecycle", "terminal_states", "event_kinds"] {
            assert!(t[k].is_array(), "{k}: {t}");
        }
    }
    let wp = types.iter().find(|t| t["kind"] == "work_product").unwrap();
    assert_eq!(wp["served"], false);

    let (status, v) = read(&hub, &format!("/api/platform/objects/task/{tid}"), BUILDER).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["uri"], format!("unified-agent://tasks/{tid}"));
    assert_eq!(v["task"]["id"], tid);
    assert_eq!(v["task"]["title"], "seeded");

    let (status, v) = read(&hub, "/api/platform/objects/board", BUILDER).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["uri"], "unified-agent://board");
    assert_eq!(v["tasks"][0]["platform"]["uri"], format!("unified-agent://tasks/{tid}"));

    let (_, v) = read(&hub, "/api/platform/objects/run/run-1-aa", BUILDER).await;
    assert_eq!(v["run"]["run_id"], "run-1-aa");
    let (_, v) = read(&hub, "/api/platform/objects/session/01SESSION", BUILDER).await;
    assert_eq!(v["session"]["agent"], "builder-2");

    // An encoded id with a slash is one path segment and simply not found.
    for (path, want) in [
        ("/api/platform/objects/task/999", StatusCode::NOT_FOUND),
        ("/api/platform/objects/task/a%2Fb", StatusCode::NOT_FOUND),
        ("/api/platform/objects/nope/1", StatusCode::NOT_FOUND),
        ("/api/platform/objects/work_product/1", StatusCode::NOT_FOUND),
        ("/api/platform/objects/task", StatusCode::BAD_REQUEST),
        ("/api/platform/objects/board/1", StatusCode::BAD_REQUEST),
    ] {
        let (status, v) = read(&hub, path, BUILDER).await;
        assert_eq!(status, want, "{path}: {v}");
    }

    // The public profile cannot call platform_object_get at all.
    let (status, _) = read(&hub, &format!("/api/platform/objects/task/{tid}"), PUBLIC).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "public has no platform_object_get");
    // Each kind is gated by its own profile tool: the operator profile reads
    // tasks (task_list) but not delegations (delegate_list).
    let (status, _) = read(&hub, &format!("/api/platform/objects/task/{tid}"), OPERATOR).await;
    assert_eq!(status, StatusCode::OK);
    let (status, v) = read(&hub, "/api/platform/objects/delegation/1", OPERATOR).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["reason_code"], "profile_denied");
}

#[tokio::test]
async fn evidence_appends_attributed_and_deduplicated_per_caller() {
    let hub = TestHub::new(config());
    let body = json!({ "channel": "sdk.conformance", "payload": { "fixture": true }, "dedupe_key": "k-1" });

    let (status, first) = post(&hub, "/api/evidence", Some(BUILDER), body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    assert_eq!(first["inserted"], true);
    let ulid = first["event_ulid"].as_str().unwrap().to_string();

    let (status, again) = post(&hub, "/api/evidence", Some(BUILDER), body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["inserted"], false);
    assert_eq!(again["event_ulid"], ulid.as_str());

    // Another identity's identical key is its own event.
    let (status, other) = post(&hub, "/api/evidence", Some(OTHER), body.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ne!(other["event_ulid"], ulid.as_str());

    // The event is attributed to the verified caller and readable as an object.
    let (status, v) = read(&hub, &format!("/api/platform/objects/evidence_event/{ulid}"), BUILDER).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["evidence_event"]["originator"], "builder-1");
    assert_eq!(v["evidence_event"]["channel"], "sdk.conformance");
    assert_eq!(v["evidence_event"]["payload_parsed"]["fixture"], true);
    assert_eq!(v["evidence_event"]["trust"]["level"], "untrusted", "a client payload is labelled");
    assert!(v["evidence_event"]["entry_hash"].is_string());

    for (bad, why) in [
        (json!({ "channel": "agent.task.created", "payload": {} }), "hub channel"),
        (json!({ "channel": "sdk.x", "payload": [] }), "array payload"),
        (json!({ "channel": "sdk.x", "payload": {}, "originator": "someone" }), "unknown field"),
        (json!({ "channel": "sdk.x", "payload": {}, "dedupe_key": "" }), "empty key"),
        (json!({ "channel": "sdk.", "payload": {} }), "bare prefix"),
    ] {
        let (status, v) = post(&hub, "/api/evidence", Some(BUILDER), bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{why}: {v}");
    }
    let (status, _) = post(&hub, "/api/evidence", None, body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = post(&hub, "/api/evidence", Some(PUBLIC), body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "public has no evidence_append");

    // The report reads the ledger as JSON only.
    let (status, v) = read(&hub, "/api/evidence?limit=5", BUILDER).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["chain_integrity"].is_object(), "{v}");
    for bad in ["/api/evidence?format=csv", "/api/evidence?task_id=x", "/api/evidence?cursor=2"] {
        let (status, _) = read(&hub, bad, BUILDER).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn a_gated_evidence_write_parks_until_a_human_approves() {
    let mut cfg = config();
    cfg.approval_tools = vec!["evidence_append".into()];
    let hub = TestHub::new(cfg);
    let body = json!({ "channel": "sdk.gated", "payload": { "n": 1 } });

    let (status, v) = post(&hub, "/api/evidence", Some(BUILDER), body.clone()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["status"], "pending");
    assert_eq!(v["tool"], "evidence_append");
    assert_eq!(v["payload"]["channel"], "sdk.gated");
    let approval = v["approval_id"].as_i64().unwrap();

    let (status, r) = post(
        &hub,
        "/api/action/approval",
        Some(OPERATOR),
        json!({ "id": approval, "decision": "approve", "reason": "ok" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    let (status, v) = post(&hub, "/api/evidence", Some(BUILDER), body).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["inserted"], true);
}

#[tokio::test]
async fn cookie_writes_need_csrf_and_unported_routes_say_so() {
    let hub = TestHub::new(config());
    let cookie = hub.sign_in("operator").await;
    let body = json!({ "channel": "sdk.ui", "payload": {} });
    let resp = hub.send(post_json("/api/evidence", &body, &[("cookie", cookie.as_str())])).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "no CSRF token");
    let csrf = hub.csrf(&cookie).await;
    let resp = hub
        .send(post_json(
            "/api/evidence",
            &body,
            &[("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())],
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Cross-site writes are refused before any handler runs.
    let resp = hub
        .send(post_json(
            "/api/evidence",
            &body,
            &[("authorization", &format!("Bearer {BUILDER}")), ("sec-fetch-site", "cross-site")],
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Reads need a credential.
    let resp = hub.send(get("/api/runs", None, None)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_some());

    let (status, v) = post(&hub, "/api/work-products", Some(BUILDER), json!({ "source_path": "/x" })).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(v["capability"], "work_products");
    assert!(v["message"].as_str().unwrap().contains("not ported"), "{v}");
    let (status, _) = post(&hub, "/api/work-products/3/release", Some(BUILDER), json!({})).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    for path in ["/api/platform/provenance-graph", "/api/evidence/export"] {
        let (status, v) = read(&hub, path, BUILDER).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{path}: {v}");
        assert_eq!(v["error"], "not_implemented");
    }
}

#[tokio::test]
async fn the_evidence_budget_refuses_appends_past_it() {
    let mut cfg = config();
    cfg.evidence_append_max_per_hour = 2;
    let hub = TestHub::new(cfg);
    let body = json!({ "channel": "sdk.burst", "payload": { "n": 1 } });
    for _ in 0..2 {
        let (status, v) = post(&hub, "/api/evidence", Some(BUILDER), body.clone()).await;
        assert_eq!(status, StatusCode::CREATED, "{v}");
    }
    let (status, v) = post(&hub, "/api/evidence", Some(BUILDER), body.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["reason_code"], "rate_limited");
    let (status, _) = post(&hub, "/api/evidence", Some(OTHER), body).await;
    assert_eq!(status, StatusCode::CREATED, "another identity has its own budget");
}
