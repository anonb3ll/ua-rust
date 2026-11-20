//! config_revision_manage: capture, diff, show, gated commit and rollback.

use std::path::PathBuf;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

struct Env {
    _dir: tempfile::TempDir,
    path: PathBuf,
    hub: Hub,
    reg: Registry,
}

fn setup(initial: Option<&str>) -> Env {
    setup_lead_profile(initial, "coordinator")
}

/// `lead-1` is configured with `lead_profile` (a current or legacy name).
fn setup_lead_profile(initial: Option<&str>, lead_profile: &str) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into()];
    cfg.approval_tools = vec!["event_log_verify".into()];
    cfg.profiles.insert("lead-1".into(), lead_profile.into());
    let path = dir.path().join("conf").join("policy.yaml");
    cfg.policy_file = Some(path.clone());
    if let Some(text) = initial {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
    }
    let hub = Hub::in_memory(cfg).unwrap();
    Env { _dir: dir, path, hub, reg: builtin_registry() }
}

fn lead() -> Caller {
    Caller {
        label: "lead-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Coordinator,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

fn human() -> Caller {
    Caller { label: "operator".into(), kind: ActorKind::Human, profile: Profile::Operator, ..lead() }
}

impl Env {
    async fn manage(&self, who: &Caller, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, "config_revision_manage", args).await
    }

    async fn ok(&self, args: Value) -> Value {
        self.manage(&lead(), args).await.unwrap()
    }

    async fn approve(&self, id: i64) {
        self.reg
            .call(&self.hub, &human(), "approval_resolve", json!({ "id": id, "decision": "approve" }))
            .await
            .unwrap();
    }

    /// Run a gated action: park it, approve it as the human, retry it.
    async fn gated(&self, args: Value, gate: &str) -> Value {
        let err = self.manage(&lead(), args.clone()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, tool } = err else { panic!("expected approval: {err}") };
        assert_eq!(tool, gate);
        // The requester cannot approve their own change.
        let own = self
            .reg
            .call(&self.hub, &lead(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
            .await;
        assert!(own.is_err());
        self.approve(approval_id).await;
        let out = self.manage(&lead(), args).await.unwrap();
        assert_eq!(out["approval_id"], approval_id);
        out
    }

    fn file(&self) -> String {
        std::fs::read_to_string(&self.path).unwrap_or_default()
    }

    async fn events(&self, channel: &str) -> Vec<Value> {
        let out = self
            .reg
            .call(&self.hub, &human(), "event_log_query", json!({ "channels": [channel], "limit": 100 }))
            .await
            .unwrap();
        out["events"].as_array().cloned().unwrap_or_default()
    }
}

const V1: &str =
    "version: 1\nrules:\n  - name: no_verify\n    type: tool\n    tool: event_log_verify\n    action: deny\n";

#[tokio::test]
async fn capture_list_show_and_diff() {
    let env = setup(Some(V1));
    let listed = env.ok(json!({ "action": "list" })).await;
    assert_eq!(listed["drift"], true);
    assert_eq!(listed["count"], 0);

    let cap = env.ok(json!({ "action": "capture" })).await;
    assert_eq!(cap["revision"], 1);
    assert_eq!(cap["action"], "capture");
    // Capturing an unchanged file records nothing new.
    let again = env.ok(json!({ "action": "capture" })).await;
    assert_eq!(again["unchanged"], true);

    // A hand edit is drift until captured; a comment-only edit counts too.
    std::fs::write(&env.path, format!("# reviewed\n{V1}")).unwrap();
    let listed = env.ok(json!({ "action": "list" })).await;
    assert_eq!(listed["drift"], true);
    assert!(listed["latest_diff"].as_str().unwrap().contains("+# reviewed"), "{listed}");
    let cap2 = env.ok(json!({ "action": "capture", "kind": "policy" })).await;
    assert_eq!(cap2["revision"], 2);

    let shown = env.ok(json!({ "action": "show", "params": { "revision": 1 } })).await;
    assert_eq!(shown["document"]["rules"][0]["name"], "no_verify");
    assert_eq!(shown["raw"], V1);
    assert_eq!(shown["document_sha256"].as_str().unwrap().len(), 64);

    let d = env.ok(json!({ "action": "diff", "from_revision": 1, "to_revision": 2 })).await;
    assert!(d["diff"].as_str().unwrap().contains("+# reviewed"), "{d}");
    let listed = env.ok(json!({ "action": "list", "limit": 1 })).await;
    assert_eq!(listed["drift"], false);
    assert_eq!(listed["revisions"].as_array().unwrap().len(), 1);
    assert_eq!(listed["revisions"][0]["revision"], 2);

    assert_eq!(env.events("agent.config.revision").await.len(), 2);
    let missing = env.manage(&lead(), json!({ "action": "show", "revision": 9 })).await.unwrap_err();
    assert_eq!(missing.code(), "not_found");
}

#[tokio::test]
async fn commit_needs_a_human_approval_and_writes_atomically() {
    let env = setup(Some(V1));
    env.ok(json!({ "action": "capture" })).await;
    let document = json!({
        "version": 1,
        "rules": [{ "name": "verify_budget", "type": "rate_limit", "tool": "event_log_verify",
                    "max_calls": 3, "window_seconds": 60 }],
    });
    let out = env.gated(json!({ "action": "commit", "document": document }), "config_revision_commit").await;
    assert_eq!(out["revision"], 2);
    assert_eq!(out["action"], "commit");
    let text = env.file();
    assert!(text.contains("verify_budget") && !text.contains("no_verify"), "{text}");
    // No temporary siblings are left behind.
    let names: Vec<String> = std::fs::read_dir(env.path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(names, vec!["policy.yaml".to_string()]);

    // The gate reloaded the new policy: the deny rule is gone.
    let pending = env.reg.call(&env.hub, &lead(), "event_log_verify", json!({})).await.unwrap_err();
    assert_eq!(pending.code(), "approval_required");

    // Committing the live document again needs no approval.
    let doc = env.ok(json!({ "action": "show", "revision": 2 })).await["document"].clone();
    let same = env.ok(json!({ "action": "commit", "document": doc })).await;
    assert_eq!(same["unchanged"], true);
}

#[tokio::test]
async fn invalid_documents_are_refused_before_any_approval() {
    let env = setup(Some(V1));
    for bad in [
        json!({ "rules": [{ "name": "x", "type": "teleport" }] }),
        json!({ "rules": [{ "name": "r", "type": "rate_limit", "max_calls": 0, "window_seconds": 60 }] }),
        json!({ "rules": [], "api_key": "abc123" }),
        json!({ "rules": [], "notes": "token: abc123" }),
        json!("not a mapping"),
    ] {
        let err = env.manage(&lead(), json!({ "action": "commit", "document": bad })).await.unwrap_err();
        assert_eq!(err.code(), "invalid_argument", "{bad}: {err}");
    }
    let pending = env.reg.call(&env.hub, &human(), "approval_pending", json!({})).await.unwrap();
    assert_eq!(pending["pending"].as_array().unwrap().len(), 0);
    assert_eq!(env.file(), V1);
}

#[tokio::test]
async fn a_pass_is_bound_to_the_file_it_was_reviewed_against() {
    let env = setup(Some(V1));
    let doc = json!({ "rules": [] });
    let err = env.manage(&lead(), json!({ "action": "commit", "document": doc })).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = err else { panic!("{err}") };
    env.approve(approval_id).await;

    // Someone edits the file by hand before the commit is retried.
    std::fs::write(&env.path, format!("{V1}# edited\n")).unwrap();
    let err = env.manage(&lead(), json!({ "action": "commit", "document": doc })).await.unwrap_err();
    assert_eq!(err.code(), "approval_required", "a new base means a new request: {err}");
    assert!(env.file().ends_with("# edited\n"));
}

#[tokio::test]
async fn rollback_restores_a_prior_revision_as_a_new_revision() {
    let env = setup(Some(V1));
    env.ok(json!({ "action": "capture" })).await;
    env.gated(json!({ "action": "commit", "document": { "rules": [] } }), "config_revision_commit").await;
    assert!(!env.file().contains("no_verify"));

    let out = env.gated(json!({ "action": "rollback", "revision": 1 }), "config_revision_rollback").await;
    assert_eq!(out["revision"], 3);
    assert_eq!(out["restores_revision"], 1);
    assert_eq!(env.file(), V1, "policy rollback restores the stored file text");

    // Rolling back to what is already live spends nothing.
    let same = env.ok(json!({ "action": "rollback", "revision": 1 })).await;
    assert_eq!(same["unchanged"], true);

    let listed = env.ok(json!({ "action": "list" })).await;
    let actions: Vec<&str> =
        listed["revisions"].as_array().unwrap().iter().map(|r| r["action"].as_str().unwrap()).collect();
    assert_eq!(actions, vec!["rollback", "commit", "capture"]);
    assert_eq!(listed["drift"], false);

    // History is append-only.
    let res = env.hub.db().write(|tx| Ok(tx.execute("DELETE FROM config_revisions", [])?));
    assert!(res.is_err());
}

#[tokio::test]
async fn rollback_to_an_empty_policy_deletes_the_file() {
    let env = setup(None);
    let first = env.ok(json!({ "action": "capture" })).await;
    assert_eq!(first["revision"], 1);
    env.gated(
        json!({ "action": "commit", "document": { "rules": [] , "default_action": "allow" } }),
        "config_revision_commit",
    )
    .await;
    assert!(env.path.exists());
    env.gated(json!({ "action": "rollback", "revision": 1 }), "config_revision_rollback").await;
    assert!(!env.path.exists());
}

#[tokio::test]
async fn profile_overlay_commits_validate_privilege() {
    let env = setup(Some(V1));
    // Lowering a developer to research is allowed.
    let out = env
        .gated(
            json!({ "action": "commit", "kind": "profile", "document": { "overlay": { "builder-1": "research" } } }),
            "config_revision_commit",
        )
        .await;
    assert_eq!(out["kind"], "profile");
    assert!(env.file().contains("profile_defaults"), "{}", env.file());
    assert!(env.file().contains("no_verify"), "other policy content survives a profile commit");

    // The policy kind was captured alongside the profile write.
    let policy_list = env.ok(json!({ "action": "list", "kind": "policy" })).await;
    assert_eq!(policy_list["drift"], false);

    // operator grants approval_resolve, which developer refuses.
    let err = env
        .manage(&lead(), json!({ "action": "commit", "kind": "profile", "document": { "overlay": { "builder-1": "operator" } } }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "denied", "{err}");
    // Escalation above the configured default is refused too.
    let err = env
        .manage(&lead(), json!({ "action": "commit", "kind": "profile", "document": { "overlay": { "builder-1": "lead" } } }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "denied", "{err}");
    // The last identity holding config authority cannot be demoted.
    let err = env
        .manage(&lead(), json!({ "action": "commit", "kind": "profile", "document": { "overlay": { "lead-1": "developer" } } }))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("coordinator"), "{err}");

    let shown = env.ok(json!({ "action": "show", "kind": "profile", "revision": 1 })).await;
    assert_eq!(shown["document"]["overlay"]["builder-1"], "research");
    assert_eq!(shown["document"]["code_defaults"]["lead-1"], "coordinator");
}

#[tokio::test]
async fn legacy_profile_names_are_accepted_and_stored_under_current_names() {
    // A configuration written for the Python hub names the coordinator
    // profile by its old name; it still holds config authority.
    let env = setup_lead_profile(Some(V1), "chief-of-staff");
    let err = env
        .manage(&lead(), json!({ "action": "commit", "kind": "profile", "document": { "overlay": { "lead-1": "developer" } } }))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("config authority"), "{err}");

    // An overlay may use a legacy name; it is stored under the current one.
    env.gated(
        json!({ "action": "commit", "kind": "profile", "document": { "overlay": { "builder-1": "steward", "lead-1": "chief-of-staff" } } }),
        "config_revision_commit",
    )
    .await;
    let shown = env.ok(json!({ "action": "show", "kind": "profile", "revision": 1 })).await;
    assert_eq!(shown["document"]["overlay"]["builder-1"], "reviewer");
    assert_eq!(shown["document"]["overlay"]["lead-1"], "coordinator");
    assert!(!env.file().contains("steward"), "{}", env.file());
}

#[tokio::test]
async fn approval_rule_commits_patch_only_their_slice() {
    let env = setup(Some(V1));
    let rules = json!([{ "name": "gate_status", "type": "tool", "tool": "profile_status", "action": "require_approval" }]);
    env.gated(
        json!({ "action": "commit", "kind": "approval_rule", "document": { "rules": rules } }),
        "config_revision_commit",
    )
    .await;
    let text = env.file();
    assert!(text.contains("gate_status") && text.contains("no_verify"), "{text}");

    // approval_tools is observed, never written.
    let err = env
        .manage(
            &lead(),
            json!({ "action": "commit", "kind": "approval_rule",
                    "document": { "rules": [], "env_gated_tools": ["memory_save"] } }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    // Non-approval rules do not belong in this kind.
    let err = env
        .manage(
            &lead(),
            json!({ "action": "commit", "kind": "approval_rule",
                    "document": { "rules": [{ "name": "x", "type": "tool", "action": "deny" }] } }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");

    let shown = env.ok(json!({ "action": "show", "kind": "approval_rule", "revision": 1 })).await;
    assert_eq!(shown["document"]["env_gated_tools"], json!(["event_log_verify"]));
    assert_eq!(shown["document"]["rules"][0]["name"], "gate_status");
}

#[tokio::test]
async fn developers_cannot_reach_the_tool_and_bad_actions_are_refused() {
    let env = setup(Some(V1));
    let dev = Caller { label: "builder-1".into(), profile: Profile::Developer, ..lead() };
    let err = env.manage(&dev, json!({ "action": "list" })).await.unwrap_err();
    assert_eq!(err.code(), "denied");
    let err = env.manage(&lead(), json!({ "action": "explode" })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = env.manage(&lead(), json!({ "action": "list", "kind": "org" })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = env.manage(&lead(), json!({ "action": "rollback" })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}
