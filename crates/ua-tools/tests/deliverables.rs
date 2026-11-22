//! Deliverables through the governed registry: a task's commit deliverable,
//! its immutable and ordered revisions, the task's workflow head moving with
//! them, who may write, the refusals, the ledger events, and reads scoped to
//! the caller's organization.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const REPO: &str = "example/widgets";

fn caller(label: &str, kind: ActorKind, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn builder() -> Caller {
    caller("builder-1", ActorKind::Agent, Profile::Developer)
}

fn other() -> Caller {
    caller("builder-2", ActorKind::Agent, Profile::Developer)
}

fn reviewer() -> Caller {
    caller("review-1", ActorKind::Agent, Profile::Reviewer)
}

fn human() -> Caller {
    Caller { enforce_profile: false, ..caller("operator", ActorKind::Human, Profile::Operator) }
}

/// A caller of an organization that does not exist.
fn stranger() -> Caller {
    Caller { org_id: "org-nowhere".into(), ..builder() }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

struct H {
    hub: Hub,
    reg: Registry,
}

impl H {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry() }
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

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> UaError {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => panic!("{tool}({args}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    async fn act(&self, who: &Caller, action: &str, params: Value) -> Value {
        self.ok(who, "coordination_manage", json!({ "action": action, "params": params })).await
    }

    /// A task claimed by builder-1, in the default project.
    async fn claimed_task(&self) -> i64 {
        let id = self.ok(&builder(), "task_add", json!({ "title": "Ship the parser" })).await["id"]
            .as_i64()
            .unwrap();
        self.ok(&builder(), "task_claim", json!({ "id": id })).await;
        id
    }

    async fn bind(&self, repo: &str) {
        self.act(&human(), "project_repo_bind", json!({ "project": "default", "repo": repo })).await;
    }

    fn n(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    fn sql_err(&self, sql: &str) -> String {
        let sql = sql.to_string();
        self.hub.db().write(move |tx| Ok(tx.execute_batch(&sql)?)).unwrap_err().to_string()
    }

    fn events(&self, channel: &str) -> Vec<Value> {
        let channel = channel.to_string();
        self.hub
            .db()
            .read(move |c| {
                let mut stmt = c.prepare(
                    "SELECT payload, org_id, originator FROM event_log WHERE channel = ?1 ORDER BY seq",
                )?;
                let rows = stmt
                    .query_map([channel], |r| {
                        let mut p: Value = serde_json::from_str(&r.get::<_, String>(0)?).unwrap();
                        p["_org"] = json!(r.get::<_, String>(1)?);
                        p["_by"] = json!(r.get::<_, Option<String>>(2)?);
                        Ok(p)
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .unwrap()
    }
}

#[tokio::test]
async fn a_commit_deliverable_records_ordered_revisions_and_moves_the_workflow_head() {
    let h = H::new();
    let t = h.claimed_task().await;
    h.bind(REPO).await;

    let made = h.ok(&builder(), "deliverable_create", json!({ "task_id": t, "title": "parser" })).await;
    assert_eq!(made["created"], true);
    let d = made["deliverable"]["id"].as_i64().unwrap();
    assert_eq!(made["deliverable"]["kind"], "commit");
    assert_eq!(made["deliverable"]["repo"], REPO);
    assert_eq!(made["revision_count"], 0);
    // Creating it again is the same deliverable.
    let again = h
        .ok(&builder(), "deliverable_create", json!({ "task_id": t, "title": "parser", "kind": "commit" }))
        .await;
    assert_eq!((again["created"].as_bool(), again["deliverable"]["id"].as_i64()), (Some(false), Some(d)));

    let r1 = h.ok(&builder(), "deliverable_revise", json!({ "deliverable_id": d, "commit": A })).await;
    assert_eq!((r1["recorded"].as_bool(), r1["revision"]["rev_no"].as_i64()), (Some(true), Some(1)));
    assert_eq!(r1["revision"]["commit"], A);
    assert_eq!(r1["revision"]["producer"], "builder-1");
    assert_eq!(r1["workflow_head"], A);
    assert_eq!(r1["latest_is_workflow_head"], true);
    // The task's workflow record is at the revision: checks are graded there.
    let wf = h.act(&builder(), "task_workflow_get", json!({ "task_id": t })).await;
    assert_eq!((wf["head_sha"].as_str(), wf["revision"].as_i64()), (Some(A), Some(1)));

    let r2 = h
        .ok(
            &builder(),
            "deliverable_revise",
            json!({ "deliverable_id": d, "commit": B.to_uppercase(), "summary": "review fixes" }),
        )
        .await;
    assert_eq!((r2["revision"]["rev_no"].as_i64(), r2["revision"]["commit"].as_str()), (Some(2), Some(B)));
    // The same commit and summary again: idempotent, nothing new.
    let same = h
        .ok(
            &builder(),
            "deliverable_revise",
            json!({ "deliverable_id": d, "commit": B, "summary": "review fixes" }),
        )
        .await;
    assert_eq!(
        (same["recorded"].as_bool(), same["revision"]["id"].clone()),
        (Some(false), r2["revision"]["id"].clone())
    );
    let wf = h.act(&builder(), "task_workflow_get", json!({ "task_id": t })).await;
    assert_eq!(
        (wf["head_sha"].as_str(), wf["revision"].as_i64()),
        (Some(B), Some(2)),
        "one capsule write per new head"
    );

    // Reads: get and list.
    let got = h.ok(&other(), "deliverable_get", json!({ "id": d })).await;
    assert_eq!(got["revision_count"], 2);
    let nos: Vec<i64> =
        got["revisions"].as_array().unwrap().iter().map(|r| r["rev_no"].as_i64().unwrap()).collect();
    assert_eq!(nos, [2, 1], "newest first");
    assert_eq!(got["latest_revision"]["commit"], B);
    let listed = h.ok(&other(), "deliverable_list", json!({ "task_id": t })).await;
    assert_eq!(listed["deliverables"].as_array().unwrap().len(), 1);
    assert_eq!(listed["deliverables"][0]["revision_count"], 2);
    assert_eq!(listed["workflow_head"], B);

    // A head set some other way is shown as not the latest revision.
    h.act(&builder(), "task_workflow_set", json!({ "task_id": t, "head_sha": "cccccccccccc" })).await;
    let got = h.ok(&other(), "deliverable_get", json!({ "id": d })).await;
    assert_eq!(got["latest_is_workflow_head"], false);
    // Re-recording the latest revision puts the head back on it.
    let back = h
        .ok(
            &builder(),
            "deliverable_revise",
            json!({ "deliverable_id": d, "commit": B, "summary": "review fixes" }),
        )
        .await;
    assert_eq!((back["recorded"].as_bool(), back["workflow_head"].as_str()), (Some(false), Some(B)));

    // One event per state change, in the row's organization, with ids and
    // the identity but no content.
    let created = h.events("agent.deliverable.created");
    assert_eq!(created.len(), 1);
    assert_eq!(created[0]["deliverable_id"], d);
    assert_eq!(created[0]["task_id"], t);
    assert_eq!(
        (created[0]["org_id"].as_str(), created[0]["_org"].as_str()),
        (Some("default"), Some("default"))
    );
    assert_eq!(created[0]["_by"], "builder-1");
    let revised = h.events("agent.deliverable.revised");
    assert_eq!(revised.len(), 2);
    assert_eq!(
        (revised[1]["rev_no"].as_i64(), revised[1]["identity"].as_str(), revised[1]["repo"].as_str()),
        (Some(2), Some(B), Some(REPO))
    );
    assert_eq!(revised[1]["revision_id"], r2["revision"]["id"]);
    for e in created.iter().chain(&revised) {
        let text = e.to_string();
        assert!(!text.contains("parser") && !text.contains("review fixes"), "{text}");
    }
    // The capsule moved through the workflow record's own write and event.
    let capsule: Vec<Value> =
        h.events("agent.task.workflow").into_iter().filter(|e| e["fields"] == json!(["head_sha"])).collect();
    assert_eq!(capsule.len(), 4, "A, B, the manual head, and B again");
}

#[tokio::test]
async fn only_a_writer_of_the_task_may_create_or_revise() {
    let h = H::new();
    let t = h.claimed_task().await;
    h.bind(REPO).await;
    for who in [other(), Caller::local("builder-2", Transport::Mcp)] {
        let e = h.err(&who, "deliverable_create", json!({ "task_id": t, "title": "x" })).await;
        assert_eq!(reason(&e), "not_task_owner", "{}", who.label);
    }
    // The reviewer profile does not see the write tools at all.
    let e = h.err(&reviewer(), "deliverable_create", json!({ "task_id": t, "title": "x" })).await;
    assert_ne!(reason(&e), "not_task_owner", "refused by the profile, before the handler: {e}");
    let d = h.ok(&builder(), "deliverable_create", json!({ "task_id": t, "title": "x" })).await["deliverable"]["id"]
        .as_i64()
        .unwrap();
    let e = h.err(&other(), "deliverable_revise", json!({ "deliverable_id": d, "commit": A })).await;
    assert_eq!(reason(&e), "not_task_owner");
    // The next owner and a human may; an unverified caller naming the
    // claimant writes as it, as every unverified workflow write does.
    h.ok(&builder(), "task_update", json!({ "id": t, "next_owner": "builder-2" })).await;
    h.ok(&other(), "deliverable_revise", json!({ "deliverable_id": d, "commit": A })).await;
    let by_human = h.ok(&human(), "deliverable_revise", json!({ "deliverable_id": d, "commit": B })).await;
    assert_eq!(by_human["revision"]["producer"], "operator");
    // The reviewer may read.
    assert_eq!(h.ok(&reviewer(), "deliverable_get", json!({ "id": d })).await["revision_count"], 2);
    assert_eq!(h.n("SELECT COUNT(*) FROM deliverables"), 1);
}

#[tokio::test]
async fn refusals_fail_closed_with_a_reason() {
    let h = H::new();
    let t = h.claimed_task().await;
    // No repository binding: nothing to name a commit in.
    let e = h.err(&builder(), "deliverable_create", json!({ "task_id": t, "title": "x" })).await;
    assert_eq!(reason(&e), "repo_unbound", "{e}");
    h.bind(REPO).await;
    // Unknown task, unknown kind, the planned file kind, bad titles.
    assert_eq!(
        h.err(&builder(), "deliverable_create", json!({ "task_id": 999, "title": "x" })).await.code(),
        "not_found"
    );
    for bad in [
        json!({ "task_id": t, "title": "x", "kind": "file" }),
        json!({ "task_id": t, "title": "x", "kind": "doc" }),
        json!({ "task_id": t, "title": " " }),
        json!({ "task_id": t, "title": "x".repeat(201) }),
        json!({ "task_id": 0, "title": "x" }),
    ] {
        assert_eq!(
            h.err(&builder(), "deliverable_create", bad.clone()).await.code(),
            "invalid_argument",
            "{bad}"
        );
    }
    // Unknown fields are refused by the schema.
    assert!(
        h.call(&builder(), "deliverable_create", json!({ "task_id": t, "title": "x", "repo": "a/b" }))
            .await
            .is_err()
    );
    let d = h.ok(&builder(), "deliverable_create", json!({ "task_id": t, "title": "x" })).await["deliverable"]["id"]
        .as_i64()
        .unwrap();
    // A second commit deliverable on the task.
    let e = h.err(&builder(), "deliverable_create", json!({ "task_id": t, "title": "y" })).await;
    assert_eq!(reason(&e), "deliverable_exists", "{e}");

    // Not a full SHA.
    for bad in ["aaaaaaa", &A[..39], "z".repeat(40).as_str(), ""] {
        let e = h.err(&builder(), "deliverable_revise", json!({ "deliverable_id": d, "commit": bad })).await;
        assert_eq!(e.code(), "invalid_argument", "{bad}: {e}");
    }
    let e = h.err(&builder(), "deliverable_revise", json!({ "deliverable_id": d + 50, "commit": A })).await;
    assert_eq!(e.code(), "not_found");
    h.ok(&builder(), "deliverable_revise", json!({ "deliverable_id": d, "commit": A, "summary": "one" }))
        .await;
    // The same commit with other content, and an earlier commit again.
    let e = h
        .err(&builder(), "deliverable_revise", json!({ "deliverable_id": d, "commit": A, "summary": "two" }))
        .await;
    assert_eq!(reason(&e), "revision_conflict", "{e}");
    h.ok(&builder(), "deliverable_revise", json!({ "deliverable_id": d, "commit": B })).await;
    let e = h
        .err(&builder(), "deliverable_revise", json!({ "deliverable_id": d, "commit": A, "summary": "one" }))
        .await;
    assert_eq!(reason(&e), "revision_not_latest", "{e}");
    // The project rebound to another repository.
    h.bind("example/other").await;
    let c = "c".repeat(40);
    let e = h.err(&builder(), "deliverable_revise", json!({ "deliverable_id": d, "commit": c })).await;
    assert_eq!(reason(&e), "repo_mismatch", "{e}");
    h.act(&human(), "project_repo_unbind", json!({ "project": "default" })).await;
    let e = h.err(&builder(), "deliverable_revise", json!({ "deliverable_id": d, "commit": c })).await;
    assert_eq!(reason(&e), "repo_unbound", "{e}");
    // An unknown organization.
    for (tool, args) in [
        ("deliverable_create", json!({ "task_id": t, "title": "x" })),
        ("deliverable_revise", json!({ "deliverable_id": d, "commit": c })),
        ("deliverable_get", json!({ "id": d })),
        ("deliverable_list", json!({ "task_id": t })),
    ] {
        let e = h.err(&stranger(), tool, args).await;
        assert_eq!(reason(&e), "unknown_organization", "{tool}: {e}");
    }
    assert_eq!(h.err(&builder(), "deliverable_list", json!({ "task_id": 999 })).await.code(), "not_found");

    // Refusals changed nothing: two revisions, the head at the second.
    assert_eq!(h.n("SELECT COUNT(*) FROM deliverable_revisions"), 2);
    assert_eq!(h.events("agent.deliverable.revised").len(), 2);
    let wf = h.act(&builder(), "task_workflow_get", json!({ "task_id": t })).await;
    assert_eq!(wf["head_sha"], B);
}

#[tokio::test]
async fn revisions_cannot_be_edited_or_removed_and_survive_their_task() {
    let h = H::new();
    let t = h.claimed_task().await;
    h.bind(REPO).await;
    let d = h.ok(&builder(), "deliverable_create", json!({ "task_id": t, "title": "x" })).await["deliverable"]["id"]
        .as_i64()
        .unwrap();
    h.ok(&builder(), "deliverable_revise", json!({ "deliverable_id": d, "commit": A })).await;
    assert!(h.sql_err(&format!("UPDATE deliverable_revisions SET identity = '{B}'")).contains("immutable"));
    assert!(h.sql_err("DELETE FROM deliverable_revisions").contains("immutable"));
    assert!(h.sql_err("UPDATE deliverables SET task_id = task_id + 1").contains("never change"));
    assert!(h.sql_err("DELETE FROM deliverables").contains("never deleted"));
    // Deleting the task (a human-approved delete) keeps the record.
    h.hub.db().write(move |tx| Ok(tx.execute("DELETE FROM tasks WHERE id = ?1", [t])?)).unwrap();
    let got = h.ok(&builder(), "deliverable_get", json!({ "id": d })).await;
    assert_eq!((got["deliverable"]["task_id"].as_i64(), got["revision_count"].as_i64()), (Some(t), Some(1)));
    let e = h.err(&builder(), "deliverable_revise", json!({ "deliverable_id": d, "commit": B })).await;
    assert_eq!(e.code(), "not_found", "no task, no new revision: {e}");
}
