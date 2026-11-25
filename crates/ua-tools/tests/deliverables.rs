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

#[cfg(unix)]
mod file_releases {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    struct Files {
        h: H,
        _home: tempfile::TempDir,
        source: PathBuf,
        destination: PathBuf,
        task_id: i64,
    }

    impl Files {
        async fn new() -> Self {
            Self::configured(|_, _| {}).await
        }

        async fn configured(configure: impl FnOnce(&mut Config, &std::path::Path)) -> Self {
            let home = tempfile::tempdir().unwrap();
            let root = home.path().canonicalize().unwrap();
            let workspace = root.join("workspace");
            let worktree = workspace.join("work");
            let destination = root.join("release");
            fs::create_dir_all(&worktree).unwrap();
            fs::create_dir(&destination).unwrap();
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
            let source = worktree.join("report.txt");
            fs::write(&source, b"reviewed report").unwrap();
            let mut cfg = Config::for_home(root.join("hub"));
            cfg.workspace = Some(workspace);
            cfg.deliverable_release_root = Some(destination.clone());
            cfg.human_identities = vec!["operator".into(), "editor".into()];
            configure(&mut cfg, &destination);
            let h = H { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry() };
            h.hub
                .db()
                .write(|tx| {
                    Ok(tx.execute_batch(
                        "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                 VALUES ('org-other', 'org-other', 'Other', '[\"developer\"]', '2026-01-01T00:00:00Z');",
                    )?)
                })
                .unwrap();
            let t = h.ok(&builder(), "task_add", json!({"title":"Release the report"})).await;
            let task_id = t["id"].as_i64().unwrap();
            h.ok(&builder(), "task_claim", json!({"id": task_id, "worktree_path":"work"})).await;
            Self { h, _home: home, source, destination, task_id }
        }

        async fn submit(&self, who: &Caller) -> Value {
            self.h.ok(who, "deliverable_submit", self.submission("report.txt")).await
        }

        fn submission(&self, path: &str) -> Value {
            json!({"task_id": self.task_id, "title":"report", "path":path})
        }

        async fn review(&self) {
            self.h
                .act(&builder(), "task_workflow_set", json!({"task_id":self.task_id, "stage":"review"}))
                .await;
        }

        async fn approval(&self, who: &Caller, args: Value) -> i64 {
            match self.h.err(who, "deliverable_release", args).await {
                UaError::ApprovalRequired { approval_id, .. } => approval_id,
                e => panic!("expected a pending release, got {e:?}"),
            }
        }

        async fn approve(&self, id: i64) {
            self.h.ok(&human(), "approval_resolve", json!({"id": id, "decision":"approve"})).await;
        }
    }

    #[tokio::test]
    async fn releases_the_approved_bytes_once_and_verifies_the_result() {
        let f = Files::new().await;
        let first = f.submit(&builder()).await;
        let rev = first["revision"]["id"].as_i64().unwrap();
        assert_eq!(first["revision"]["sha256"].as_str().unwrap().len(), 64);
        assert!(first["revision"].get("commit").is_none());
        assert_eq!(first["workflow_head"], Value::Null);
        assert_eq!(f.submit(&builder()).await["recorded"], false);

        let requester = other();
        f.h.ok(&builder(), "task_update", json!({"id": f.task_id, "next_owner": requester.label})).await;
        let args = json!({"revision_id":rev, "destination":"report.txt"});
        assert_eq!(
            reason(&f.h.err(&requester, "deliverable_release", args.clone()).await),
            "review_required"
        );
        f.review().await;
        let id = f.approval(&requester, args.clone()).await;
        let approvals = f.h.ok(&human(), "approval_pending", json!({"tool":"deliverable_release"})).await;
        let payload = &approvals["pending"][0]["payload"];
        assert_eq!(payload["revision_id"], rev);
        assert_eq!(payload["sha256"], first["revision"]["sha256"]);
        assert_eq!(payload["destination"], "report.txt");
        assert_eq!(payload["producer"], "builder-1");
        assert!(!approvals.to_string().contains("reviewed report"));
        f.approve(id).await;
        let other = json!({"revision_id":rev, "destination":"other.txt"});
        assert_ne!(f.approval(&requester, other).await, id);
        let (a, b) = tokio::join!(
            f.h.ok(&requester, "deliverable_release", args.clone()),
            f.h.ok(&requester, "deliverable_release", args.clone())
        );
        assert_ne!(a["created"], b["created"]);
        assert_eq!(a["approval_id"], id);
        let dest = f.destination.join("report.txt");
        assert_eq!(fs::read(&dest).unwrap(), b"reviewed report");
        assert_eq!(fs::read_dir(&f.destination).unwrap().count(), 1);
        assert_eq!(f.h.n("SELECT COUNT(*) FROM deliverable_releases WHERE payload IS NULL"), 1);
        let events = f.h.events("agent.deliverable.released");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["approval_id"], id);
        let workflow = f.h.act(&builder(), "task_workflow_get", json!({"task_id":f.task_id})).await;
        assert_eq!(workflow["stage"], "done");
        assert_eq!(f.h.n("SELECT COUNT(*) FROM tasks WHERE status = 'done'"), 1);
        let verify = json!({"revision_id":rev});
        assert_eq!(f.h.ok(&requester, "deliverable_verify", verify.clone()).await["matches"], true);
        fs::write(&dest, b"changed release").unwrap();
        assert_eq!(f.h.ok(&requester, "deliverable_verify", verify).await["matches"], false);
        assert_eq!(reason(&f.h.err(&requester, "deliverable_release", args).await), "deliverable_tampered");
    }

    #[tokio::test]
    async fn refuses_self_approval_for_a_producer_and_refuses_changed_source_without_spending() {
        let f = Files::new().await;
        let editor = Caller { label: "editor".into(), ..human() };
        let rev = f.submit(&editor).await["revision"]["id"].as_i64().unwrap();
        f.review().await;
        let args = json!({"revision_id": rev, "destination":"report.txt"});
        let id = f.approval(&builder(), args.clone()).await;
        let approve = json!({"id":id, "decision":"approve"});
        assert_eq!(reason(&f.h.err(&editor, "approval_resolve", approve).await), "self_approval");
        f.approve(id).await;

        fs::write(&f.source, b"edited after approval").unwrap();
        assert_eq!(
            reason(&f.h.err(&builder(), "deliverable_release", args.clone()).await),
            "deliverable_tampered"
        );
        assert_eq!(f.h.events("agent.deliverable.tampered").len(), 1);
        assert_eq!(f.h.n("SELECT COUNT(*) FROM approvals WHERE status = 'approved'"), 1);
        assert_eq!(fs::read_dir(&f.destination).unwrap().count(), 0);

        let next = f.submit(&builder()).await;
        assert_eq!(next["revision"]["rev_no"], 2);
        assert_eq!(reason(&f.h.err(&builder(), "deliverable_release", args).await), "revision_not_latest");
    }

    #[tokio::test]
    async fn refuses_cross_org_access_and_unsafe_source_and_destination_paths() {
        let f = Files::new().await;
        let src_dir = f.source.parent().unwrap();
        let symlink_path = src_dir.join("linked.txt");
        symlink(&f.source, &symlink_path).unwrap();
        assert_eq!(
            reason(&f.h.err(&builder(), "deliverable_submit", f.submission("linked.txt")).await),
            "unsafe_deliverable_file"
        );
        fs::remove_file(&symlink_path).unwrap();
        fs::hard_link(&f.source, &symlink_path).unwrap();
        assert_eq!(
            reason(&f.h.err(&builder(), "deliverable_submit", f.submission("linked.txt")).await),
            "unsafe_deliverable_file"
        );
        fs::remove_file(&symlink_path).unwrap();
        assert_eq!(
            reason(&f.h.err(&builder(), "deliverable_submit", f.submission("../report.txt")).await),
            "invalid_argument"
        );
        fs::write(src_dir.join(".env"), b"fixture").unwrap();
        assert_eq!(
            reason(&f.h.err(&builder(), "deliverable_submit", f.submission(".env")).await),
            "secret_file"
        );
        let rev = f.submit(&builder()).await["revision"]["id"].as_i64().unwrap();
        f.review().await;
        let args = json!({"revision_id":rev, "destination":"report.txt"});
        let foreign = Caller { org_id: "org-other".into(), ..builder() };
        assert_eq!(reason(&f.h.err(&foreign, "deliverable_release", args.clone()).await), "org_unsupported");
        let anon = Caller { kind: ActorKind::Anonymous, ..builder() };
        assert_eq!(
            reason(&f.h.err(&anon, "deliverable_release", args.clone()).await),
            "anonymous_prod_action"
        );
        assert_eq!(
            reason(
                &f.h.err(
                    &builder(),
                    "deliverable_release",
                    json!({"revision_id":rev, "destination":"../report.txt"})
                )
                .await
            ),
            "invalid_argument"
        );
        let existing = f.destination.join("report.txt");
        symlink(&f.source, &existing).unwrap();
        assert_eq!(
            reason(&f.h.err(&builder(), "deliverable_release", args).await),
            "release_destination_exists"
        );
        assert!(existing.is_symlink());
        assert_eq!(f.h.n("SELECT COUNT(*) FROM approvals"), 0);
    }

    async fn pending_intent(f: &Files) -> (i64, Value, PathBuf) {
        let rev = f.submit(&builder()).await["revision"]["id"].as_i64().unwrap();
        f.review().await;
        let args = json!({"revision_id":rev, "destination":"report.txt"});
        let (id, stage) = authorize_without_publishing(f, &args).await;
        (id, args, stage)
    }

    async fn authorize_without_publishing(f: &Files, args: &Value) -> (i64, PathBuf) {
        let id = f.approval(&builder(), args.clone()).await;
        f.approve(id).await;
        f.h.hub
            .db()
            .write(|tx| {
                Ok(tx.execute_batch(
                    "CREATE TRIGGER fail_release_event BEFORE INSERT ON event_log
             WHEN NEW.channel = 'agent.deliverable.released'
             BEGIN SELECT RAISE(ABORT, 'simulated ledger write failure'); END;",
                )?)
            })
            .unwrap();
        assert!(f.h.call(&builder(), "deliverable_release", args.clone()).await.is_err());
        assert_eq!(f.h.n("SELECT COUNT(*) FROM approvals WHERE status = 'consumed'"), 1);
        assert_eq!(f.h.n("SELECT COUNT(*) FROM deliverable_releases WHERE released_at IS NULL"), 1);
        assert!(!f.destination.join("report.txt").exists());
        assert_eq!(f.h.events("agent.deliverable.released").len(), 0);

        let stage_id: String =
            f.h.hub
                .db()
                .read(|conn| {
                    Ok(conn.query_row("SELECT staging_id FROM deliverable_releases", [], |row| row.get(0))?)
                })
                .unwrap();
        let stage = f.destination.join(format!(".ua-release-{stage_id}"));
        f.h.hub.db().write(|tx| Ok(tx.execute_batch("DROP TRIGGER fail_release_event")?)).unwrap();
        (id, stage)
    }

    #[tokio::test]
    async fn durable_intent_recovers_a_published_receipt_after_the_task_moves_on() {
        let f = Files::new().await;
        let (id, args, stage) = pending_intent(&f).await;
        fs::write(&f.source, b"changed after the approved bytes were recorded").unwrap();

        // Simulate a crash after the filesystem link but before the SQL commit.
        fs::write(&stage, b"reviewed report").unwrap();
        let dest = f.destination.join("report.txt");
        fs::hard_link(&stage, &dest).unwrap();

        // Even identical bytes at a different inode are a collision.
        fs::remove_file(&dest).unwrap();
        fs::write(&dest, b"reviewed report").unwrap();
        assert_eq!(
            reason(&f.h.err(&builder(), "deliverable_release", args.clone()).await),
            "release_destination_exists"
        );
        assert_eq!(f.h.n("SELECT COUNT(*) FROM deliverable_releases WHERE released_at IS NULL"), 1);
        fs::remove_file(&dest).unwrap();
        fs::hard_link(&stage, &dest).unwrap();
        assert_eq!(f.submit(&builder()).await["revision"]["rev_no"], 2);
        f.h.act(&builder(), "task_workflow_set", json!({"task_id": f.task_id, "stage":"verify"})).await;
        f.h.ok(&builder(), "task_update", json!({"id": f.task_id, "release_claim": true})).await;

        let out = f.h.ok(&builder(), "deliverable_release", args.clone()).await;
        assert_eq!(out["approval_id"], id);
        assert_eq!(fs::read(dest).unwrap(), b"reviewed report");
        assert!(!stage.exists());
        assert_eq!(f.h.events("agent.deliverable.released").len(), 1);
        assert_eq!(f.h.n("SELECT COUNT(*) FROM deliverable_releases WHERE payload IS NULL"), 1);
        assert_eq!(f.h.n("SELECT COUNT(*) FROM tasks WHERE status = 'done'"), 0);
        let workflow = f.h.act(&builder(), "task_workflow_get", json!({"task_id": f.task_id})).await;
        assert_eq!(workflow["stage"], "verify");
        assert_eq!(f.h.ok(&builder(), "deliverable_release", args).await["created"], false);
        assert_eq!(f.h.events("agent.deliverable.released").len(), 1);
    }

    #[tokio::test]
    async fn an_unpublished_intent_refuses_a_changed_review_revision() {
        let f = Files::new().await;
        let (_, args, _) = pending_intent(&f).await;
        // The task stays in review and the requester remains a writer. Only
        // the bound revision changes, so the comparison is what refuses it.
        f.h.act(
            &builder(),
            "task_workflow_set",
            json!({
                "task_id": f.task_id, "stage":"review", "focus":"review again",
            }),
        )
        .await;
        assert_eq!(reason(&f.h.err(&builder(), "deliverable_release", args).await), "release_review_changed");
        assert!(!f.destination.join("report.txt").exists());
        assert!(f.h.events("agent.deliverable.released").is_empty());
        assert_eq!(f.h.n("SELECT COUNT(*) FROM tasks WHERE status = 'done'"), 0);
    }

    const CANCEL: &str = "deliverable_release_cancel";
    const CANCELLED: &str = "agent.deliverable.release_cancelled";

    #[tokio::test]
    async fn operator_cancels_an_unpublished_intent_and_a_new_attempt_needs_fresh_approval() {
        let f = Files::new().await;
        let rev = f.submit(&builder()).await["revision"]["id"].as_i64().unwrap();
        f.review().await;
        let alternate = json!({"revision_id": rev, "destination": "alternate.txt"});
        let old_alternate = f.approval(&builder(), alternate.clone()).await;
        f.approve(old_alternate).await;
        let args = json!({"revision_id": rev, "destination": "report.txt"});
        let (id, stage) = authorize_without_publishing(&f, &args).await;
        let cancel = json!({"approval_id": id});
        let dest = f.destination.join("report.txt");
        // The same bytes at a different inode are an unrelated collision.
        fs::write(&stage, b"reviewed report").unwrap();
        fs::write(&dest, b"reviewed report").unwrap();
        assert_eq!(
            reason(&f.h.err(&builder(), "deliverable_release", args.clone()).await),
            "release_destination_exists"
        );
        for agent in [builder(), reviewer()] {
            let agent = Caller { enforce_profile: false, ..agent };
            assert_eq!(reason(&f.h.err(&agent, CANCEL, cancel.clone()).await), "authority_required");
        }
        let foreign = Caller { org_id: "org-other".into(), ..human() };
        assert_eq!(reason(&f.h.err(&foreign, CANCEL, cancel.clone()).await), "org_unsupported");

        let operator = Caller { enforce_profile: true, ..human() };
        let result = f.h.ok(&operator, CANCEL, cancel.clone()).await;
        assert_eq!(result["approval_id"], id);
        assert_eq!(result["revision_id"], rev);
        assert_eq!(result["cancelled"], true);
        assert!(!stage.exists());
        assert_eq!(fs::read(&dest).unwrap(), b"reviewed report");
        assert_eq!(f.h.n("SELECT COUNT(*) FROM approvals WHERE status = 'consumed'"), 1);
        assert_eq!(
            f.h.n("SELECT COUNT(*) FROM deliverable_releases WHERE payload IS NULL
                   AND cancelled_at IS NOT NULL AND cancelled_by = 'operator' AND released_at IS NULL"),
            1
        );
        assert_eq!(f.h.n("SELECT COUNT(*) FROM task_workflow WHERE stage = 'review'"), 1);
        assert!(f.h.events("agent.deliverable.released").is_empty());
        let events = f.h.events(CANCELLED);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["_by"], "operator");
        assert_eq!(events[0]["approval_id"], id);

        assert_ne!(f.approval(&builder(), alternate).await, old_alternate);
        fs::remove_file(&dest).unwrap();
        let fresh = f.approval(&builder(), args.clone()).await;
        assert_ne!(fresh, id);
        f.approve(fresh).await;
        let out = f.h.ok(&builder(), "deliverable_release", args).await;
        assert_eq!(out["approval_id"], fresh);
        let replay = f.h.ok(&operator, CANCEL, cancel).await;
        assert_eq!(replay["cancelled"], false);
        assert_eq!(replay["cancelled_at"], result["cancelled_at"]);
        assert_eq!(f.h.events(CANCELLED).len(), 1);
        assert_eq!(fs::read(&dest).unwrap(), b"reviewed report");
        assert_eq!(
            reason(&f.h.err(&operator, CANCEL, json!({"approval_id": fresh})).await),
            "release_already_published"
        );
    }

    #[tokio::test]
    async fn cancellation_refuses_an_already_linked_or_uncertain_intent() {
        let f = Files::new().await;
        let (id, args, stage) = pending_intent(&f).await;
        fs::write(&stage, b"reviewed report").unwrap();
        let dest = f.destination.join("report.txt");
        fs::hard_link(&stage, &dest).unwrap();
        let cancel = json!({"approval_id": id});
        assert_eq!(reason(&f.h.err(&human(), CANCEL, cancel.clone()).await), "release_already_published");
        fs::remove_file(&stage).unwrap();
        assert_eq!(reason(&f.h.err(&human(), CANCEL, cancel.clone()).await), "release_publication_uncertain");
        fs::hard_link(&dest, &stage).unwrap();
        let moved = f.destination.join("moved.txt");
        fs::rename(&dest, &moved).unwrap();
        assert_eq!(reason(&f.h.err(&human(), CANCEL, cancel).await), "release_publication_uncertain");
        assert!(f.h.events(CANCELLED).is_empty());
        assert_eq!(fs::read(&moved).unwrap(), b"reviewed report");
        fs::rename(moved, &dest).unwrap();
        assert_eq!(f.h.ok(&builder(), "deliverable_release", args).await["approval_id"], id);
        assert_eq!(fs::read(dest).unwrap(), b"reviewed report");
    }

    #[tokio::test]
    async fn failed_cancellation_preserves_pending_bytes_and_staging() {
        let f = Files::new().await;
        let (id, args, stage) = pending_intent(&f).await;
        fs::write(&stage, b"reviewed report").unwrap();
        f.h.hub
            .db()
            .write(|tx| {
                Ok(tx.execute_batch(
                    "CREATE TRIGGER fail_cancel_event BEFORE INSERT ON event_log
             WHEN NEW.channel = 'agent.deliverable.release_cancelled'
             BEGIN SELECT RAISE(ABORT, 'simulated cancellation ledger failure'); END;",
                )?)
            })
            .unwrap();
        assert!(f.h.call(&human(), CANCEL, json!({"approval_id": id})).await.is_err());
        assert_eq!(
            f.h.n("SELECT COUNT(*) FROM deliverable_releases WHERE payload IS NOT NULL
                         AND cancelled_at IS NULL AND released_at IS NULL"),
            1
        );
        assert_eq!(fs::read(&stage).unwrap(), b"reviewed report");
        assert!(f.h.events(CANCELLED).is_empty());
        assert_eq!(f.h.ok(&builder(), "deliverable_release", args).await["approval_id"], id);
        assert!(!stage.exists());
    }

    #[tokio::test]
    async fn cancellation_and_publication_cannot_both_succeed() {
        let f = Files::new().await;
        let (id, args, stage) = pending_intent(&f).await;
        let requester = builder();
        let operator = human();
        let (publish, cancel) = tokio::join!(
            f.h.call(&requester, "deliverable_release", args),
            f.h.call(&operator, CANCEL, json!({"approval_id": id})),
        );
        assert_ne!(publish.is_ok(), cancel.is_ok());
        assert_eq!(f.destination.join("report.txt").exists(), publish.is_ok());
        assert!(!stage.exists());
        assert_eq!(f.h.events(CANCELLED).len(), usize::from(cancel.is_ok()));
        assert_eq!(f.h.events("agent.deliverable.released").len(), usize::from(publish.is_ok()));
    }

    #[tokio::test]
    async fn release_root_rejects_symlinks_hub_home_and_read_roots() {
        for configure in [
            (|cfg: &mut Config, path: &std::path::Path| {
                let alias = path.with_file_name("alias");
                symlink(path, &alias).unwrap();
                cfg.deliverable_release_root = Some(alias);
            }) as fn(&mut Config, &std::path::Path),
            |cfg, path| cfg.home = path.to_path_buf(),
            |cfg, path| cfg.read_roots = vec![path.to_path_buf()],
        ] {
            let f = Files::configured(configure).await;
            let rev = f.submit(&builder()).await["revision"]["id"].as_i64().unwrap();
            f.review().await;
            let args = json!({"revision_id": rev, "destination": "report.txt"});
            assert_eq!(
                reason(&f.h.err(&builder(), "deliverable_release", args).await),
                "unsafe_release_root"
            );
            assert_eq!(f.h.n("SELECT COUNT(*) FROM approvals"), 0);
        }
    }
}
