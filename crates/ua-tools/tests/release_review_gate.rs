//! Review-at-head gate in `git_merge_task`: when `"review"` is in a task's
//! `expected_checks`, merging requires a passing, uncontradicted `review` check
//! at the exact commit being merged, and refuses a self-review by the commit
//! deliverable revision's producer.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::ci::{CiOutcome, CiRun, CiVerifier, Verdict, VerifyFuture};
use ua_tools::{Hub, Registry, builtin_registry};

const REPO: &str = "example/widgets";

struct Env {
    _home: tempfile::TempDir,
    _ws: tempfile::TempDir,
    ws: PathBuf,
    hub: Hub,
    reg: Registry,
}

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

fn init_repo(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main"]);
    for (k, v) in [
        ("user.name", "builder-1"),
        ("user.email", "builder-1@example.com"),
        ("commit.gpgsign", "false"),
        ("core.hooksPath", "/dev/null"),
    ] {
        git(dir, &["config", k, v]);
    }
    std::fs::write(dir.join(".gitignore"), ".worktrees/\n").unwrap();
    std::fs::write(dir.join("README.md"), "readme\n").unwrap();
    git(dir, &["add", ".gitignore", "README.md"]);
    git(dir, &["commit", "-q", "-m", "chore: initial commit"]);
}

fn commit_file(dir: &Path, name: &str, content: &str, msg: &str) -> String {
    std::fs::write(dir.join(name), content).unwrap();
    git(dir, &["add", name]);
    git(dir, &["commit", "-q", "-m", msg]);
    git(dir, &["rev-parse", "HEAD"])
}

fn agent(label: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some(format!("s-{label}")),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn builder1() -> Caller {
    agent("builder-1", Profile::Developer)
}

fn builder2() -> Caller {
    agent("builder-2", Profile::Developer)
}

fn lead() -> Caller {
    agent("lead-1", Profile::Coordinator)
}

fn human() -> Caller {
    Caller {
        kind: ActorKind::Human,
        profile: Profile::Coordinator,
        ..agent("operator", Profile::Coordinator)
    }
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    }
}

struct MismatchVerifier;

impl CiVerifier for MismatchVerifier {
    fn verify_run<'a>(&'a self, run: &'a CiRun) -> VerifyFuture<'a> {
        Box::pin(async move {
            CiOutcome::new(Verdict::Mismatch, format!("run {} concluded failure", run.run_id))
                .observed(json!({ "conclusion": "failure" }))
        })
    }

    fn verify_job<'a>(&'a self, run: &'a CiRun, job: &'a str) -> VerifyFuture<'a> {
        Box::pin(async move {
            CiOutcome::new(Verdict::Mismatch, format!("job {job} in run {} failed", run.run_id))
                .observed(json!({ "conclusion": "failure" }))
        })
    }
}

impl Env {
    fn new(verifier: Option<Arc<dyn CiVerifier>>) -> Self {
        let home = tempfile::tempdir().unwrap();
        let ws_dir = tempfile::tempdir().unwrap();
        let ws = ws_dir.path().canonicalize().unwrap();
        init_repo(&ws);
        let mut cfg = Config::for_home(home.path());
        cfg.workspace = Some(ws.clone());
        cfg.human_identities = vec!["operator".into()];
        let hub = Hub::in_memory(cfg).unwrap();
        let hub = match verifier {
            Some(v) => hub.with_ci_verifier(v),
            None => hub,
        };
        Self { _home: home, _ws: ws_dir, ws, hub, reg: builtin_registry() }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.call(who, tool, args.clone()).await.unwrap_or_else(|e| panic!("{tool} {args}: {e}"))
    }

    async fn act(&self, who: &Caller, action: &str, params: Value) -> Value {
        self.ok(who, "coordination_manage", json!({ "action": action, "params": params })).await
    }

    async fn bind_repo(&self) {
        self.act(&human(), "project_repo_bind", json!({ "project": "default", "repo": REPO })).await;
    }

    /// Create a task, worktree, branch, one commit and claim it as `builder-1`.
    async fn setup_task(&self, title: &str, file: &str) -> (i64, PathBuf, String) {
        let id = self.ok(&lead(), "task_add", json!({ "title": title })).await["id"].as_i64().unwrap();
        let branch = format!("task-{id}");
        let rel = format!(".worktrees/{branch}");
        self.ok(&builder1(), "git_worktree_add", json!({ "path": rel, "branch": branch })).await;
        let wt = self.ws.join(&rel);
        let head = commit_file(&wt, file, &format!("{title}\n"), &format!("feat: {title}"));
        self.ok(&builder1(), "task_claim", json!({ "id": id, "worktree_path": rel, "branch": branch })).await;
        (id, wt, head)
    }

    async fn authorize(&self, task_id: i64, head: &str) -> i64 {
        self.ok(
            &human(),
            "policy_authorization_record",
            json!({ "repo": REPO, "head_sha": head, "task_id": task_id, "policy_ref": "release-policy-1" }),
        )
        .await["authorization"]["id"]
            .as_i64()
            .unwrap()
    }

    fn auth_status(&self, auth_id: i64) -> String {
        self.hub
            .db()
            .read(move |c| {
                Ok(c.query_row("SELECT status FROM policy_authorizations WHERE id = ?1", [auth_id], |r| {
                    r.get::<_, String>(0)
                })?)
            })
            .unwrap()
    }

    async fn pending_approvals(&self) -> Vec<Value> {
        self.ok(&human(), "approval_pending", json!({ "tool": "git_merge_task" })).await["pending"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    async fn approve_pending(&self) {
        let pending = self.pending_approvals().await;
        let id = pending[0]["id"].as_i64().expect("a pending approval");
        self.ok(&human(), "approval_resolve", json!({ "id": id, "decision": "approve" })).await;
    }
}

#[tokio::test]
async fn merge_refused_when_review_missing_and_authz_stays_active() {
    if !have_git() {
        return;
    }
    let env = Env::new(None);
    env.bind_repo().await;
    let (t, _wt, head) = env.setup_task("add feature", "a.txt").await;
    env.act(
        &builder1(),
        "task_workflow_set",
        json!({ "task_id": t, "stage": "review", "head_sha": head, "expected_checks": ["review"] }),
    )
    .await;
    let auth = env.authorize(t, &head).await;
    env.ok(&builder1(), "task_update", json!({ "id": t, "status": "done" })).await;

    // Policy authorization path: refused with review_required, authorization NOT consumed.
    let e = env
        .call(&lead(), "git_merge_task", json!({ "task_id": t, "policy_authorization_id": auth }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "review_required", "{e:?}");
    assert!(e.to_string().contains("review") && e.to_string().contains(&head[..12]), "{e}");
    assert_eq!(env.auth_status(auth), "active", "unreviewed refusal must not burn the authorization");
    assert!(!env.ws.join("a.txt").exists(), "nothing was merged");

    // One-time approval path: refused before parking an approval, and force=true does not bypass it.
    for force in [false, true] {
        let e =
            env.call(&lead(), "git_merge_task", json!({ "task_id": t, "force": force })).await.unwrap_err();
        assert_eq!(reason(&e), "review_required", "force={force}: {e:?}");
        assert!(env.pending_approvals().await.is_empty(), "must not park an approval for an unreviewed head");
    }
}

#[tokio::test]
async fn merge_refused_when_review_is_stale_at_older_head() {
    if !have_git() {
        return;
    }
    let env = Env::new(None);
    env.bind_repo().await;
    let (t, wt, head1) = env.setup_task("stale review check", "b.txt").await;
    env.act(
        &builder1(),
        "task_workflow_set",
        json!({ "task_id": t, "stage": "review", "head_sha": head1, "expected_checks": ["review"] }),
    )
    .await;
    // Hand off to reviewer builder-2, who approves head1.
    env.ok(&builder1(), "task_update", json!({ "id": t, "next_owner": "builder-2" })).await;
    env.act(
        &builder2(),
        "task_check_record",
        json!({ "task_id": t, "name": "review", "outcome": "pass", "head_sha": head1 }),
    )
    .await;

    // A new commit lands on the branch after the review.
    let head2 = commit_file(&wt, "b2.txt", "extra\n", "feat: follow-up commit");
    let auth = env.authorize(t, &head2).await;
    env.ok(&builder1(), "task_update", json!({ "id": t, "status": "done" })).await;

    let e = env
        .call(&lead(), "git_merge_task", json!({ "task_id": t, "policy_authorization_id": auth }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "review_required", "{e:?}");
    let msg = e.to_string();
    assert!(msg.contains("review") && msg.contains(&head2[..12]) && msg.contains(&head1[..12]), "{msg}");
    assert_eq!(env.auth_status(auth), "active");
}

#[tokio::test]
async fn merge_refused_when_review_failed_or_contradicted() {
    if !have_git() {
        return;
    }
    let env = Env::new(Some(Arc::new(MismatchVerifier)));
    env.bind_repo().await;
    let (t, _wt, head) = env.setup_task("failed review", "c.txt").await;
    env.act(
        &builder1(),
        "task_workflow_set",
        json!({ "task_id": t, "stage": "review", "head_sha": head, "expected_checks": ["review"] }),
    )
    .await;
    env.ok(&builder1(), "task_update", json!({ "id": t, "next_owner": "builder-2" })).await;
    env.act(
        &builder2(),
        "task_check_record",
        json!({ "task_id": t, "name": "review", "outcome": "fail", "head_sha": head }),
    )
    .await;
    let auth = env.authorize(t, &head).await;
    env.ok(&builder1(), "task_update", json!({ "id": t, "status": "done" })).await;

    // Failing review is refused.
    let e = env
        .call(&lead(), "git_merge_task", json!({ "task_id": t, "policy_authorization_id": auth }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "review_required", "{e:?}");
    assert!(e.to_string().contains("review") && e.to_string().contains("fail"), "{e}");
    assert_eq!(env.auth_status(auth), "active");

    // Passing review contradicted by verification is also refused.
    env.ok(&builder2(), "task_update", json!({ "id": t, "status": "doing" })).await;
    env.ok(&builder2(), "task_claim", json!({ "id": t })).await;
    env.act(
        &builder2(),
        "task_check_record",
        json!({
            "task_id": t,
            "name": "review",
            "outcome": "pass",
            "head_sha": head,
            "ref": { "kind": "ci_run", "ref": "999" }
        }),
    )
    .await;
    env.ok(&builder2(), "task_update", json!({ "id": t, "status": "done" })).await;
    let e = env
        .call(&lead(), "git_merge_task", json!({ "task_id": t, "policy_authorization_id": auth }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "review_required", "{e:?}");
    assert!(e.to_string().contains("review") && e.to_string().contains("contradicted"), "{e}");
    assert_eq!(env.auth_status(auth), "active");
}

#[tokio::test]
async fn merge_refuses_self_review_by_deliverable_producer_and_allows_independent_reviewer() {
    if !have_git() {
        return;
    }
    let env = Env::new(None);
    env.bind_repo().await;
    let (t, _wt, head) = env.setup_task("separation of duties", "d.txt").await;
    env.act(
        &builder1(),
        "task_workflow_set",
        json!({ "task_id": t, "stage": "review", "head_sha": head, "expected_checks": ["review"] }),
    )
    .await;
    // builder-1 records the commit as a deliverable revision (producer = builder-1).
    let d_id = env
        .ok(&builder1(), "deliverable_create", json!({ "task_id": t, "title": "deliverable d" }))
        .await["deliverable"]["id"]
        .as_i64()
        .unwrap();
    env.ok(&builder1(), "deliverable_revise", json!({ "deliverable_id": d_id, "commit": head })).await;

    // builder-1 records a passing review on its own revision.
    env.act(
        &builder1(),
        "task_check_record",
        json!({ "task_id": t, "name": "review", "outcome": "pass", "head_sha": head }),
    )
    .await;
    let auth = env.authorize(t, &head).await;
    env.ok(&builder1(), "task_update", json!({ "id": t, "status": "done" })).await;

    // Self-review is refused and authorization stays active.
    let e = env
        .call(&lead(), "git_merge_task", json!({ "task_id": t, "policy_authorization_id": auth }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "self_review_refused", "{e:?}");
    assert!(e.to_string().contains("review") && e.to_string().contains("builder-1"), "{e}");
    assert_eq!(env.auth_status(auth), "active");

    // Independent reviewer builder-2 claims the task and records a passing review at head.
    env.ok(&builder2(), "task_update", json!({ "id": t, "status": "doing" })).await;
    env.ok(&builder2(), "task_claim", json!({ "id": t })).await;
    env.act(
        &builder2(),
        "task_check_record",
        json!({ "task_id": t, "name": "review", "outcome": "pass", "head_sha": head }),
    )
    .await;
    env.ok(&builder2(), "task_update", json!({ "id": t, "status": "done" })).await;

    // Now the merge succeeds, even though builder-2 is the task's current claimant.
    let merged =
        env.ok(&lead(), "git_merge_task", json!({ "task_id": t, "policy_authorization_id": auth })).await;
    assert_eq!(merged["success"], true, "{merged}");
    assert!(env.ws.join("d.txt").exists());
    assert_eq!(env.auth_status(auth), "consumed");
}

#[tokio::test]
async fn merge_succeeds_without_review_requirement() {
    if !have_git() {
        return;
    }
    let env = Env::new(None);
    env.bind_repo().await;

    // Task with expected_checks = ["tests"] (no "review") merges under policy authorization.
    let (t1, _wt1, head1) = env.setup_task("no review expected", "e1.txt").await;
    env.act(
        &builder1(),
        "task_workflow_set",
        json!({ "task_id": t1, "stage": "verify", "head_sha": head1, "expected_checks": ["tests"] }),
    )
    .await;
    let auth1 = env.authorize(t1, &head1).await;
    env.ok(&builder1(), "task_update", json!({ "id": t1, "status": "done" })).await;
    let merged1 =
        env.ok(&lead(), "git_merge_task", json!({ "task_id": t1, "policy_authorization_id": auth1 })).await;
    assert_eq!(merged1["success"], true);
    assert!(env.ws.join("e1.txt").exists());

    // Task with no workflow record at all merges under a one-time approval.
    let (t2, _wt2, _head2) = env.setup_task("no workflow row", "e2.txt").await;
    env.ok(&builder1(), "task_update", json!({ "id": t2, "status": "done" })).await;
    assert_eq!(
        env.call(&lead(), "git_merge_task", json!({ "task_id": t2 })).await.unwrap_err().code(),
        "approval_required"
    );
    env.approve_pending().await;
    let merged2 = env.ok(&lead(), "git_merge_task", json!({ "task_id": t2 })).await;
    assert_eq!(merged2["success"], true);
    assert!(env.ws.join("e2.txt").exists());
}

#[tokio::test]
async fn dry_run_enforces_review_gate() {
    if !have_git() {
        return;
    }
    let env = Env::new(None);
    env.bind_repo().await;
    let (t, _wt, head) = env.setup_task("dry run review check", "f.txt").await;
    env.act(
        &builder1(),
        "task_workflow_set",
        json!({ "task_id": t, "stage": "review", "head_sha": head, "expected_checks": ["review"] }),
    )
    .await;
    let auth = env.authorize(t, &head).await;
    env.ok(&builder1(), "task_update", json!({ "id": t, "status": "done" })).await;

    // dry_run under policy authorization refuses when review is missing.
    let e = env
        .call(
            &lead(),
            "git_merge_task",
            json!({ "task_id": t, "policy_authorization_id": auth, "dry_run": true }),
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "review_required", "{e:?}");
    assert_eq!(env.auth_status(auth), "active");

    // dry_run on one-time approval path refuses before parking an approval.
    let e = env.call(&lead(), "git_merge_task", json!({ "task_id": t, "dry_run": true })).await.unwrap_err();
    assert_eq!(reason(&e), "review_required", "{e:?}");
    assert!(env.pending_approvals().await.is_empty());

    // After an independent review passes, dry_run succeeds without consuming auth or merging.
    env.ok(&builder2(), "task_update", json!({ "id": t, "status": "doing" })).await;
    env.ok(&builder2(), "task_claim", json!({ "id": t })).await;
    env.act(
        &builder2(),
        "task_check_record",
        json!({ "task_id": t, "name": "review", "outcome": "pass", "head_sha": head }),
    )
    .await;
    env.ok(&builder2(), "task_update", json!({ "id": t, "status": "done" })).await;

    let dry = env
        .ok(
            &lead(),
            "git_merge_task",
            json!({ "task_id": t, "policy_authorization_id": auth, "dry_run": true }),
        )
        .await;
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["policy_authorization_id"], auth);
    assert_eq!(env.auth_status(auth), "active");
    assert!(!env.ws.join("f.txt").exists(), "dry run merges nothing");
}
