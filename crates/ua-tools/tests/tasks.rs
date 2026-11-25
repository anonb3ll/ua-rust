//! The tasks family through the governed registry path.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

struct H {
    hub: Hub,
    reg: Registry,
}

impl H {
    fn new() -> Self {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry() }
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.reg.call(&self.hub, who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) failed: {e}"),
        }
    }

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> ua_core::UaError {
        match self.reg.call(&self.hub, who, tool, args.clone()).await {
            Ok(v) => panic!("{tool}({args}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    async fn add(&self, who: &Caller, args: Value) -> i64 {
        self.ok(who, "task_add", args).await["id"].as_i64().unwrap()
    }

    async fn events(&self, channel: &str) -> Vec<Value> {
        let r = self.ok(&human(), "event_log_query", json!({ "channels": [channel] })).await;
        r["events"].as_array().unwrap().clone()
    }

    /// Push a claim's lease into the past.
    fn expire_lease(&self, id: i64) {
        self.hub
            .db()
            .write(|tx| {
                tx.execute(
                    "UPDATE tasks SET lock_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?1",
                    [id],
                )?;
                Ok(())
            })
            .unwrap();
    }
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn reviewer(label: &str) -> Caller {
    Caller { profile: Profile::Reviewer, ..agent(label) }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Operator, enforce_profile: false, ..agent("operator") }
}

fn local() -> Caller {
    Caller::local("local-dev", Transport::Cli)
}

fn ids(list: &Value) -> Vec<i64> {
    list["tasks"].as_array().unwrap().iter().map(|t| t["id"].as_i64().unwrap()).collect()
}

#[tokio::test]
async fn create_update_and_list() {
    let h = H::new();
    let b = agent("builder-1");

    let parent = h
        .add(&b, json!({ "title": "Parent", "notes": "spec", "priority": "high", "project": "alpha" }))
        .await;
    let child = h.add(&b, json!({ "title": "Child", "parent_id": parent, "lane": "dispatch-ready" })).await;
    let grandchild = h.add(&b, json!({ "title": "Grandchild", "parent_id": child })).await;

    // Subtasks inherit project and lane; lineage is root-first.
    let row = h.ok(&b, "task_update", json!({ "id": grandchild, "priority": "low" })).await;
    assert_eq!(row["project"], "alpha");
    assert_eq!(row["lane"], "dispatch-ready");
    assert_eq!(row["lineage"], json!([parent, child]));
    assert_eq!(row["urgency_rank"], 1);

    // Bad input is refused.
    for bad in [
        json!({ "title": "  " }),
        json!({ "title": "# Heading" }),
        json!({ "title": "x", "priority": "urgent" }),
    ] {
        assert_eq!(h.err(&b, "task_add", bad).await.code(), "invalid_argument");
    }
    let e = h.err(&b, "task_add", json!({ "title": "x", "parent_id": 999 })).await;
    assert!(e.to_string().contains("no task with id 999"), "{e}");

    // Idempotent create.
    let k1 = h.add(&b, json!({ "title": "Keyed", "idempotency_key": "k-1" })).await;
    let k2 = h.add(&b, json!({ "title": "Keyed again", "idempotency_key": "k-1" })).await;
    assert_eq!(k1, k2);

    // append_note appends once; a verbatim retry is not duplicated.
    h.ok(&b, "task_update", json!({ "id": parent, "append_note": "[event: e-1]" })).await;
    let row = h.ok(&b, "task_update", json!({ "id": parent, "append_note": "[event: e-1]" })).await;
    assert_eq!(row["notes"], "spec\n[event: e-1]");
    assert!(
        h.err(&b, "task_update", json!({ "id": parent, "notes": "a", "append_note": "b" })).await.code()
            == "invalid_argument"
    );

    // Status transitions stamp and clear completed_at.
    let row = h.ok(&b, "task_update", json!({ "id": grandchild, "status": "done" })).await;
    assert!(row["completed_at"].is_string());
    let row = h.ok(&b, "task_update", json!({ "id": grandchild, "status": "open" })).await;
    assert!(row["completed_at"].is_null());

    // Guards.
    let e = h
        .err(&b, "task_update", json!({ "id": parent, "status": "blocked", "expected_project": "beta" }))
        .await;
    assert!(e.to_string().contains("belongs to project"), "{e}");
    let stale = row["updated_at"].as_str().unwrap().to_string();
    assert!(
        stale.len() == 32 && stale.ends_with("+00:00") && stale.contains('.'),
        "microsecond revision: {stale}"
    );
    h.ok(&b, "task_update", json!({ "id": grandchild, "priority": "med" })).await;
    let e = h
        .err(&b, "task_update", json!({ "id": grandchild, "title": "T", "expected_updated_at": stale }))
        .await;
    assert_eq!(e.code(), "conflict");
    let e = h.err(&b, "task_update", json!({ "id": child, "parent_id": grandchild })).await;
    assert!(e.to_string().contains("cycle"), "{e}");

    // Listing: status filter, priority order, parent filter, project filter.
    let open = h.ok(&b, "task_list", json!({})).await;
    assert_eq!(ids(&open)[0], parent, "high priority first");
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "parent_id": parent })).await), vec![child]);
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "project": "alpha" })).await).len(), 3);
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "notes_contain": "event: e-1" })).await), vec![parent]);
    h.ok(&b, "task_update", json!({ "id": k1, "status": "cancelled" })).await;
    assert!(!ids(&h.ok(&b, "task_list", json!({})).await).contains(&k1));
    assert!(ids(&h.ok(&b, "task_list", json!({ "status": "all" })).await).contains(&k1));
    assert_eq!(h.err(&b, "task_list", json!({ "status": "nope" })).await.code(), "invalid_argument");

    // Archive hides from the default view; archived=true shows only archived.
    h.ok(&b, "task_update", json!({ "id": child, "archived": true })).await;
    assert!(!ids(&h.ok(&b, "task_list", json!({})).await).contains(&child));
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "archived": true })).await), vec![child]);
    h.ok(&b, "task_update", json!({ "id": child, "archived": false })).await;
    assert!(ids(&h.ok(&b, "task_list", json!({})).await).contains(&child));

    // Keyset pagination.
    let page1 = h.ok(&b, "task_list", json!({ "limit": 2 })).await;
    assert_eq!(page1["truncated"], true);
    let cursor = page1["next_cursor"].as_str().unwrap();
    let page2 = h.ok(&b, "task_list", json!({ "limit": 2, "cursor": cursor })).await;
    assert_eq!(page2["truncated"], false);
    let mut all = ids(&page1);
    all.extend(ids(&page2));
    assert_eq!(all, ids(&h.ok(&b, "task_list", json!({})).await));
    assert_eq!(h.err(&b, "task_list", json!({ "cursor": "not-a-cursor" })).await.code(), "invalid_argument");

    // Compact rows drop notes bodies.
    let compact = h.ok(&b, "task_list", json!({ "fields": "compact", "parent_id": parent })).await;
    let c0 = &compact["tasks"][0];
    assert!(c0.get("notes").is_none());
    assert_eq!(c0["notes_chars"], 0);
    assert_eq!(c0["waiting_for_review"], false);

    // Time filters need an offset.
    assert_eq!(
        h.err(&b, "task_list", json!({ "created_since": "2026-01-01T00:00:00" })).await.code(),
        "invalid_argument"
    );
    assert_eq!(
        ids(&h.ok(&b, "task_list", json!({ "created_since": "2000-01-01T00:00:00Z" })).await).len(),
        3
    );
    assert!(ids(&h.ok(&b, "task_list", json!({ "created_since": "2999-01-01T00:00:00Z" })).await).is_empty());

    // Ledger.
    assert_eq!(h.events("agent.task.created").await.len(), 4);
    assert!(!h.events("agent.task.updated").await.is_empty());
    assert_eq!(h.events("agent.task.completed").await.len(), 1);
}

#[tokio::test]
async fn urgency_and_project_spec_rollup() {
    let h = H::new();
    let b = agent("builder-1");
    let root = h.add(&b, json!({ "title": "Root", "notes": "[project-spec] [urgency: now]" })).await;
    let step =
        h.add(&b, json!({ "title": "Step", "parent_id": root, "notes": "see `[project-spec]`" })).await;

    let list = h.ok(&b, "task_list", json!({})).await;
    let rows = list["tasks"].as_array().unwrap();
    let r = rows.iter().find(|t| t["id"] == root).unwrap();
    assert_eq!(r["urgency"], "now");
    assert_eq!(r["urgency_rank"], 0);
    assert_eq!(r["rollup"]["complete"], false);
    assert_eq!(r["rollup"]["derived_status"], "open");
    let s = rows.iter().find(|t| t["id"] == step).unwrap();
    assert!(s.get("rollup").is_none(), "a backticked marker is a quotation");

    let e = h.err(&b, "task_update", json!({ "id": root, "status": "done" })).await;
    assert!(e.to_string().contains("active descendants"), "{e}");
    h.ok(&b, "task_update", json!({ "id": step, "status": "done" })).await;
    let row = h.ok(&b, "task_update", json!({ "id": root, "status": "done" })).await;
    assert_eq!(row["rollup"]["complete"], true);
}

#[tokio::test]
async fn ranked_search_stays_in_sync() {
    let h = H::new();
    let b = agent("builder-1");
    let login =
        h.add(&b, json!({ "title": "Fix login crash", "notes": "the login page crashes on submit" })).await;
    let docs = h.add(&b, json!({ "title": "Write docs", "notes": "mention login once" })).await;
    let other = h.add(&b, json!({ "title": "Unrelated chore", "notes": "rotate the logs" })).await;

    let r = h.ok(&b, "task_list", json!({ "query": "login crash" })).await;
    assert_eq!(r["ranked"], true);
    assert_eq!(ids(&r), vec![login, docs]);
    let top = &r["tasks"][0];
    assert!(top["combined_score"].as_f64().unwrap() > r["tasks"][1]["combined_score"].as_f64().unwrap());
    assert_eq!(top["explanation"]["why"], json!(["lexical"]));
    assert!(top["explanation"]["snippet"].as_str().unwrap().contains("[login]"));

    // FTS syntax in the query is neutralized, not an error.
    h.ok(&b, "task_list", json!({ "query": "login AND (\"crash" })).await;

    // Filters still apply in ranked mode.
    h.ok(&b, "task_update", json!({ "id": docs, "status": "blocked" })).await;
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "query": "login" })).await), vec![login]);
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "query": "login", "status": "all" })).await).len(), 2);

    // Triggers keep the index in sync on update and delete.
    h.ok(&b, "task_update", json!({ "id": other, "title": "Kubernetes upgrade" })).await;
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "query": "kubernetes" })).await), vec![other]);
    assert!(ids(&h.ok(&b, "task_list", json!({ "query": "chore" })).await).is_empty());
    h.ok(&b, "task_update", json!({ "id": login, "append_note": "zebra stripes" })).await;
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "query": "zebra" })).await), vec![login]);
    h.ok(&local(), "task_delete", json!({ "id": login })).await;
    assert!(ids(&h.ok(&b, "task_list", json!({ "query": "zebra", "status": "all" })).await).is_empty());

    // Mode conflicts.
    for bad in [
        json!({ "query": "x", "notes_contain": "y" }),
        json!({ "query": "x", "cursor": "00" }),
        json!({ "query": "  " }),
    ] {
        assert_eq!(h.err(&b, "task_list", bad).await.code(), "invalid_argument");
    }
}

#[tokio::test]
async fn claims_conflicts_and_expiry() {
    let h = H::new();
    let (b1, b2) = (agent("builder-1"), agent("builder-2"));
    let t = h.add(&b1, json!({ "title": "Claimable", "notes": "spec" })).await;

    let row = h
        .ok(
            &b1,
            "task_claim",
            json!({ "id": t, "agent": "builder-1", "worktree_path": "/work/t", "branch": "task-1" }),
        )
        .await;
    assert_eq!(row["claimed"], true);
    assert_eq!(row["renewal"], false);
    assert_eq!(row["status"], "doing");
    assert_eq!(row["claimed_by"], "builder-1");
    assert_eq!(row["worktree_path"], "/work/t");
    assert_eq!(row["branch"], "task-1");
    assert!(row["lock_expires_at"].is_string());
    assert_eq!(row["notes"], "spec\n\nclaimed-by: builder-1");

    // Another agent gets a safe_wait and nothing is written.
    let wait = h.ok(&b2, "task_claim", json!({ "id": t })).await;
    assert_eq!(wait["claimed"], false);
    assert_eq!(wait["safe_wait"]["claimed_by"], "builder-1");
    assert_eq!(wait["safe_wait"]["owner"], "builder-1");

    // A verified caller cannot claim as someone else.
    assert_eq!(h.err(&b2, "task_claim", json!({ "id": t, "agent": "builder-1" })).await.code(), "denied");

    // Renewal by the holder; the notes marker is not repeated.
    let row = h.ok(&b1, "task_claim", json!({ "id": t, "timeout_seconds": 60 })).await;
    assert_eq!(row["renewal"], true);
    assert_eq!(row["notes"], "spec\n\nclaimed-by: builder-1");
    assert_eq!(
        h.err(&b1, "task_claim", json!({ "id": t, "timeout_seconds": 0 })).await.code(),
        "invalid_argument"
    );

    // Releasing someone else's live claim is refused.
    let e = h.err(&b2, "task_update", json!({ "id": t, "release_claim": true })).await;
    assert_eq!(e.code(), "conflict");

    // After the lease lapses another agent may claim.
    h.expire_lease(t);
    let row = h.ok(&b2, "task_claim", json!({ "id": t })).await;
    assert_eq!(row["claimed_by"], "builder-2");
    assert!(row["notes"].as_str().unwrap().ends_with("claimed-by: builder-2"));
    let claimed = h.events("agent.task.claimed").await;
    assert_eq!(claimed.len(), 3);
    assert_eq!(claimed[2]["payload"]["replaced_expired_claim"], "builder-1");

    // An expired claim may be released by anyone; status is unchanged.
    h.expire_lease(t);
    let row = h.ok(&b1, "task_update", json!({ "id": t, "release_claim": true })).await;
    assert!(row["claimed_by"].is_null());
    assert_eq!(row["status"], "doing");
    assert_eq!(h.events("agent.task.claim_released").await.len(), 1);

    // Terminal tasks are not claimable; reopening clears the claim.
    h.ok(&b1, "task_claim", json!({ "id": t })).await;
    h.ok(&b1, "task_update", json!({ "id": t, "status": "done" })).await;
    assert!(h.err(&b1, "task_claim", json!({ "id": t })).await.to_string().contains("already done"));
    let row = h.ok(&b1, "task_update", json!({ "id": t, "status": "open" })).await;
    assert!(row["claimed_by"].is_null());

    // Lanes.
    let tracking = h.add(&b1, json!({ "title": "Umbrella", "lane": "tracking" })).await;
    assert!(
        h.err(&b1, "task_claim", json!({ "id": tracking })).await.to_string().contains("never claimable")
    );
    let scoped = h.add(&b1, json!({ "title": "Review lane", "lane": "review-lane" })).await;
    assert_eq!(h.err(&b1, "task_claim", json!({ "id": scoped })).await.code(), "invalid_argument");
    h.ok(&b1, "task_claim", json!({ "id": scoped, "expected_lane": "review-lane" })).await;
    let mine = h.add(&b1, json!({ "title": "Mine", "lane": "builder-2" })).await;
    h.ok(&b2, "task_claim", json!({ "id": mine })).await;
    let other = h.add(&b1, json!({ "title": "Other project", "project": "beta" })).await;
    let e = h.err(&b1, "task_claim", json!({ "id": other, "expected_project": "alpha" })).await;
    assert!(e.to_string().contains("belongs to project"), "{e}");

    // A cancelled ancestor blocks claims of its subtree.
    let p = h.add(&b1, json!({ "title": "Cancelled parent" })).await;
    let c = h.add(&b1, json!({ "title": "Orphaned child", "parent_id": p })).await;
    h.ok(&b1, "task_update", json!({ "id": p, "status": "cancelled" })).await;
    assert!(h.err(&b1, "task_claim", json!({ "id": c })).await.to_string().contains("cancelled ancestor"));
}

#[tokio::test]
async fn reviewer_cannot_update_another_agents_claim() {
    let h = H::new();
    let (b1, st) = (agent("builder-1"), reviewer("reviewer-1"));
    let claimed = h.add(&b1, json!({ "title": "Claimed" })).await;
    let free = h.add(&b1, json!({ "title": "Free" })).await;
    h.ok(&b1, "task_claim", json!({ "id": claimed })).await;

    let e = h.err(&st, "task_update", json!({ "id": claimed, "priority": "high" })).await;
    assert_eq!(e.code(), "denied");
    h.ok(&st, "task_update", json!({ "id": free, "priority": "high" })).await;
    // Reviewer may not claim at all (profile), but may release an expired claim.
    assert_eq!(h.err(&st, "task_claim", json!({ "id": free })).await.code(), "denied");
    h.expire_lease(claimed);
    let row = h.ok(&st, "task_update", json!({ "id": claimed, "release_claim": true })).await;
    assert!(row["claimed_by"].is_null());
    // A developer is unaffected by the reviewer rule.
    h.ok(&b1, "task_claim", json!({ "id": claimed })).await;
    h.ok(&agent("builder-2"), "task_update", json!({ "id": claimed, "append_note": "fyi" })).await;
}

#[tokio::test]
async fn untrusted_quarantine_needs_a_human_to_clear() {
    let h = H::new();
    let b = agent("builder-1");
    let parent = h.add(&b, json!({ "title": "Imported", "untrusted": true })).await;
    let child = h.add(&b, json!({ "title": "Child of imported", "parent_id": parent })).await;
    let row = h.ok(&b, "task_update", json!({ "id": child, "priority": "low" })).await;
    assert_eq!(row["untrusted"], 1, "quarantine is inherited");
    assert_eq!(h.err(&b, "task_update", json!({ "id": parent, "untrusted": false })).await.code(), "denied");
    // A routine running unattended under the human's label is an agent.
    let e = h.err(&agent("operator"), "task_update", json!({ "id": parent, "untrusted": false })).await;
    assert_eq!(e.reason_code(), Some("untrusted_clear_needs_human"), "{e:?}");
    assert_eq!(h.events("agent.task.untrusted_cleared").await.len(), 0);
    let row = h.ok(&human(), "task_update", json!({ "id": parent, "untrusted": false })).await;
    assert_eq!(row["untrusted"], 0);
    assert_eq!(h.events("agent.task.untrusted_cleared").await.len(), 1);
}

#[tokio::test]
async fn dependencies_refuse_cycles() {
    let h = H::new();
    let b = agent("builder-1");
    let a = h.add(&b, json!({ "title": "A" })).await;
    let bb = h.add(&b, json!({ "title": "B" })).await;
    let c = h.add(&b, json!({ "title": "C" })).await;

    let d1 = h.ok(&b, "dependency_add", json!({ "task_id": a, "depends_on_task_id": bb })).await;
    assert_eq!(d1["dependency"]["created_by"], "builder-1");
    h.ok(&b, "dependency_add", json!({ "task_id": bb, "depends_on_task_id": c })).await;

    let e = h.err(&b, "dependency_add", json!({ "task_id": c, "depends_on_task_id": a })).await;
    assert!(e.to_string().contains("cycle"), "{e}");
    let e = h.err(&b, "dependency_add", json!({ "task_id": a, "depends_on_task_id": a })).await;
    assert!(e.to_string().contains("itself"), "{e}");
    assert_eq!(
        h.err(&b, "dependency_add", json!({ "task_id": a, "depends_on_task_id": bb })).await.code(),
        "conflict"
    );
    assert_eq!(
        h.err(&b, "dependency_add", json!({ "task_id": a, "depends_on_task_id": 999 })).await.code(),
        "not_found"
    );

    let all = h.ok(&b, "dependency_list", json!({})).await;
    assert_eq!(all["dependencies"].as_array().unwrap().len(), 2);
    assert_eq!(all["truncated"], false);
    let one = h.ok(&b, "dependency_list", json!({ "task_id": a, "limit": 1 })).await;
    assert_eq!(one["dependencies"][0]["depends_on_task_id"], bb);

    // Frontier: only tasks whose prerequisites are finished.
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "frontier": true })).await), vec![c]);
    h.ok(&b, "task_update", json!({ "id": c, "status": "done" })).await;
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "frontier": true })).await), vec![bb]);

    // Only the creator removes an edge.
    let dep_id = d1["dependency"]["id"].as_i64().unwrap();
    let e = h.err(&agent("builder-2"), "dependency_remove", json!({ "dependency_id": dep_id })).await;
    assert_eq!(e.code(), "denied");
    let r = h.ok(&b, "dependency_remove", json!({ "dependency_id": dep_id })).await;
    assert_eq!(r, json!({ "removed": true, "dependency_id": dep_id }));
    assert_eq!(h.events("agent.task.dependency_added").await.len(), 2);
    assert_eq!(h.events("agent.task.dependency_removed").await.len(), 1);
}

#[tokio::test]
async fn comments_are_append_only() {
    let h = H::new();
    let b = agent("builder-1");
    let t = h.add(&b, json!({ "title": "Discuss" })).await;
    let t2 = h.add(&b, json!({ "title": "Elsewhere" })).await;

    let c1 = h
        .ok(&b, "task_comment", json!({ "action": "append", "params": {
            "task_id": t, "body": "first", "mentions": ["reviewer-1", "reviewer-1"], "refs": { "plan_id": "p-1" },
            "idempotency_key": "c-1" } }))
        .await;
    assert_eq!(c1["idempotent_replay"], false);
    assert_eq!(c1["comment"]["author"], "builder-1");
    assert_eq!(c1["comment"]["mentions"], json!(["reviewer-1"]));
    assert_eq!(c1["comment"]["participants"], json!(["builder-1", "reviewer-1"]));
    assert_eq!(c1["comment"]["refs"], json!({ "plan_id": "p-1" }));
    let cid = c1["comment"]["id"].as_i64().unwrap();

    let replay = h
        .ok(&b, "task_comment", json!({ "action": "append", "params": { "task_id": t, "body": "again", "idempotency_key": "c-1" } }))
        .await;
    assert_eq!(replay["idempotent_replay"], true);
    assert_eq!(replay["comment"]["id"], cid);

    let reply = h
        .ok(
            &agent("reviewer-1"),
            "task_comment",
            json!({ "action": "append", "params": {
            "task_id": t, "body": "token uas_ABCDEFGHIJKLMNOPQRSTUV here", "parent_comment_id": cid } }),
        )
        .await;
    assert!(reply["warning"].is_string());
    assert_eq!(reply["comment"]["body"], "token [redacted-credential] here");

    let listed = h.ok(&b, "task_comment", json!({ "action": "list", "params": { "task_id": t } })).await;
    assert_eq!(listed["revision"], 2);
    assert_eq!(listed["comments"].as_array().unwrap().len(), 2);
    assert_eq!(listed["notes_are_spec"], true);
    let got = h.ok(&b, "task_comment", json!({ "action": "get", "params": { "comment_id": cid } })).await;
    assert_eq!(got["comment"]["body"], "first");

    for (args, code) in [
        (json!({ "action": "delete", "params": { "comment_id": cid } }), "invalid_argument"),
        (
            json!({ "action": "append", "params": { "task_id": t2, "body": "x", "parent_comment_id": cid } }),
            "invalid_argument",
        ),
        (json!({ "action": "append", "params": { "task_id": t, "body": "   " } }), "invalid_argument"),
        (
            json!({ "action": "append", "params": { "task_id": t, "body": "x", "refs": { "pr": 1 } } }),
            "invalid_argument",
        ),
        (
            json!({ "action": "append", "params": { "task_id": t, "body": "x", "bogus": 1 } }),
            "invalid_argument",
        ),
        (json!({ "action": "append", "params": { "task_id": 999, "body": "x" } }), "not_found"),
        (json!({ "action": "get", "params": { "comment_id": 999 } }), "not_found"),
    ] {
        assert_eq!(h.err(&b, "task_comment", args).await.code(), code);
    }
    assert_eq!(h.events("agent.task.commented").await.len(), 2);

    // Deleting the task removes its thread.
    h.ok(&local(), "task_delete", json!({ "id": t })).await;
    assert_eq!(
        h.err(&b, "task_comment", json!({ "action": "get", "params": { "comment_id": cid } })).await.code(),
        "not_found"
    );
}

#[tokio::test]
async fn goals_form_a_why_chain() {
    let h = H::new();
    let b = agent("builder-1");
    let g = |v: Value| json!({ "action": v["a"], "params": v["p"] });

    let root = h
        .ok(&b, "goal_manage", g(json!({ "a": "add", "p": { "title": "Ship v1", "project": "alpha" } })))
        .await;
    let root_id = root["goal"]["id"].as_i64().unwrap();
    assert_eq!(root["goal"]["revision"], 1);
    let sub = h
        .ok(&b, "goal_manage", g(json!({ "a": "add", "p": { "title": "Search works", "parent_goal_id": root_id, "project": "alpha" } })))
        .await;
    let sub_id = sub["goal"]["id"].as_i64().unwrap();
    let e = h
        .err(
            &b,
            "goal_manage",
            g(json!({ "a": "add", "p": { "title": "Other", "parent_goal_id": root_id, "project": "beta" } })),
        )
        .await;
    assert!(e.to_string().contains("same project"), "{e}");

    let got = h.ok(&b, "goal_manage", g(json!({ "a": "get", "p": { "goal_id": sub_id } }))).await;
    let chain: Vec<i64> =
        got["ancestry"].as_array().unwrap().iter().map(|x| x["id"].as_i64().unwrap()).collect();
    assert_eq!(chain, vec![root_id, sub_id]);
    let tree = h.ok(&b, "goal_manage", g(json!({ "a": "tree", "p": { "project": "alpha" } }))).await;
    assert_eq!(tree["tree"][0]["children"][0]["id"], sub_id);
    assert_eq!(
        h.ok(&b, "goal_manage", g(json!({ "a": "list", "p": {} }))).await["goals"].as_array().unwrap().len(),
        2
    );

    // Link a task; one goal per task; the link is not a dependency.
    let t = h.add(&b, json!({ "title": "Index tasks", "project": "alpha" })).await;
    let linked =
        h.ok(&b, "goal_manage", g(json!({ "a": "link", "p": { "task_id": t, "goal_id": sub_id } }))).await;
    assert_eq!(linked["why_chain"]["goal_id"], sub_id);
    assert_eq!(linked["why_chain"]["chain"].as_array().unwrap().len(), 2);
    let e =
        h.err(&b, "goal_manage", g(json!({ "a": "link", "p": { "task_id": t, "goal_id": root_id } }))).await;
    assert!(e.to_string().contains("single-valued"), "{e}");
    assert!(h.ok(&b, "dependency_list", json!({})).await["dependencies"].as_array().unwrap().is_empty());
    let other = h.add(&b, json!({ "title": "Beta task", "project": "beta" })).await;
    let e = h
        .err(&b, "goal_manage", g(json!({ "a": "link", "p": { "task_id": other, "goal_id": root_id } })))
        .await;
    assert!(e.to_string().contains("same project"), "{e}");

    // A linked task cannot drift to another project.
    let e = h.err(&b, "task_update", json!({ "id": t, "project": "beta" })).await;
    assert!(e.to_string().contains("serves a goal"), "{e}");

    let anc = h.ok(&b, "goal_manage", g(json!({ "a": "ancestry", "p": { "task_id": t } }))).await;
    assert_eq!(anc["goal_id"], sub_id);

    // Edit with revisions; close and reopen.
    let edited = h
        .ok(&b, "goal_manage", g(json!({ "a": "edit", "p": { "goal_id": sub_id, "title": "Ranked search works", "expected_revision": 1 } })))
        .await;
    assert_eq!(edited["goal"]["revision"], 2);
    let e = h
        .err(
            &b,
            "goal_manage",
            g(json!({ "a": "edit", "p": { "goal_id": sub_id, "statement": "x", "expected_revision": 1 } })),
        )
        .await;
    assert_eq!(e.code(), "conflict");
    let closed = h
        .ok(&b, "goal_manage", g(json!({ "a": "close", "p": { "goal_id": sub_id, "reason": "shipped" } })))
        .await;
    assert_eq!(closed["goal"]["status"], "achieved");
    let e = h
        .err(&b, "goal_manage", g(json!({ "a": "close", "p": { "goal_id": sub_id, "status": "abandoned" } })))
        .await;
    assert_eq!(e.code(), "conflict");
    let reopened = h.ok(&b, "goal_manage", g(json!({ "a": "reopen", "p": { "goal_id": sub_id } }))).await;
    assert_eq!(reopened["goal"]["status"], "open");

    // Unlink must name the goal the task serves.
    let e = h
        .err(&b, "goal_manage", g(json!({ "a": "unlink", "p": { "task_id": t, "goal_id": root_id } })))
        .await;
    assert!(e.to_string().contains("not goal"), "{e}");
    let un =
        h.ok(&b, "goal_manage", g(json!({ "a": "unlink", "p": { "task_id": t, "goal_id": sub_id } }))).await;
    assert_eq!(un["unlinked"], true);
    let anc = h.ok(&b, "goal_manage", g(json!({ "a": "ancestry", "p": { "task_id": t } }))).await;
    assert!(anc["goal_id"].is_null());

    assert_eq!(
        h.err(&b, "goal_manage", g(json!({ "a": "decompose", "p": {} }))).await.code(),
        "invalid_argument"
    );
    assert_eq!(
        h.err(&b, "goal_manage", g(json!({ "a": "get", "p": { "goal_id": 999 } }))).await.code(),
        "not_found"
    );
    assert_eq!(h.events("agent.goal.created").await.len(), 2);
    assert_eq!(h.events("agent.goal.linked").await.len(), 1);
}

#[tokio::test]
async fn delete_lineage_and_project_build() {
    let h = H::new();
    let b = agent("builder-1");
    let root = h.add(&b, json!({ "title": "Spec root", "notes": "[project-spec] build it", "evidence_ref": "https://example.com/pr/1" })).await;
    let child = h.add(&b, json!({ "title": "Step", "parent_id": root })).await;
    h.add(&b, json!({ "title": "Sub-step", "parent_id": child })).await;
    let plain = h.add(&b, json!({ "title": "Plain" })).await;

    // lineage: refs from the row; unknown task is empty, not an error.
    let l = h.ok(&b, "lineage", json!({ "task_id": root })).await;
    assert_eq!(l["lineage"]["refs"]["pr_url"], "https://example.com/pr/1");
    assert_eq!(l["empty"], false);
    assert_eq!(h.ok(&b, "lineage", json!({ "task_id": 999 })).await["empty"], true);

    // project_build.
    let built = h.ok(&b, "project_build", json!({ "parent_task_id": root })).await;
    assert_eq!(built["project_id"], root);
    assert_eq!(built["identity"], "builder-1");
    assert!(built["event_ulid"].is_string());
    assert_eq!(h.events("agent.project.built").await.len(), 1);
    assert!(
        h.err(&b, "project_build", json!({ "parent_task_id": plain }))
            .await
            .to_string()
            .contains("[project-spec]")
    );
    assert_eq!(h.err(&local(), "project_build", json!({ "parent_task_id": root })).await.code(), "denied");
    h.ok(&agent("builder-2"), "task_claim", json!({ "id": root })).await;
    assert_eq!(h.err(&b, "project_build", json!({ "parent_task_id": root })).await.code(), "conflict");

    // task_delete cascades the subtree.
    let d = h.ok(&local(), "task_delete", json!({ "id": root })).await;
    assert_eq!(d, json!({ "deleted": true, "children_deleted": 2, "worktrees": {} }));
    assert_eq!(ids(&h.ok(&b, "task_list", json!({ "status": "all" })).await), vec![plain]);
    assert_eq!(h.ok(&local(), "task_delete", json!({ "id": root })).await["deleted"], false);
    assert_eq!(h.events("agent.task.deleted").await.len(), 1);
}

#[tokio::test]
async fn unknown_arguments_are_refused() {
    let h = H::new();
    let b = agent("builder-1");
    for (tool, args) in [
        ("task_add", json!({ "title": "x", "bogus": 1 })),
        ("task_update", json!({ "id": 1, "worktree": true })),
        ("task_list", json!({ "office": "eng" })),
        ("task_claim", json!({ "id": 1, "usage_only": true })),
        ("task_delete", json!({ "id": 1, "force": true })),
        ("dependency_add", json!({ "task_id": 1, "depends_on_task_id": 2, "x": 1 })),
        ("goal_manage", json!({ "action": "list", "params": { "project": "a", "org_id": "t" } })),
        ("task_comment", json!({ "action": "list", "extra": 1 })),
    ] {
        let e = h.err(&b, tool, args).await;
        assert_eq!(e.code(), "invalid_argument", "{tool}: {e}");
    }
    // A missing task is not_found, not a panic.
    assert_eq!(h.err(&b, "task_update", json!({ "id": 42, "priority": "low" })).await.code(), "not_found");
    assert_eq!(h.err(&b, "task_claim", json!({ "id": 42 })).await.code(), "not_found");
}
