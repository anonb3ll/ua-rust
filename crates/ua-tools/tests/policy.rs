//! The policy gate: rule kinds, fail-closed loading, reload, overlay and the
//! prod-action identity checks.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

struct Env {
    _dir: tempfile::TempDir,
    path: PathBuf,
    hub: Hub,
    reg: Registry,
}

fn config(dir: &Path) -> Config {
    let mut cfg = Config::for_home(dir);
    cfg.human_identities = vec!["operator".into()];
    cfg.policy_file = Some(dir.join("policy.yaml"));
    cfg
}

fn setup_with(yaml: Option<&str>, tweak: impl FnOnce(&mut Config)) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    tweak(&mut cfg);
    let path = cfg.policy_file.clone().unwrap_or_else(|| dir.path().join("policy.yaml"));
    if let Some(y) = yaml {
        std::fs::write(&path, y).unwrap();
    }
    let hub = Hub::in_memory(cfg).unwrap();
    Env { _dir: dir, path, hub, reg: builtin_registry() }
}

fn setup(yaml: &str) -> Env {
    setup_with(Some(yaml), |_| {})
}

fn agent(label: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, ..agent("operator", Profile::Operator) }
}

fn dev(label: &str) -> Caller {
    agent(label, Profile::Developer)
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    }
}

impl Env {
    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn denied(&self, who: &Caller, tool: &str, args: Value) -> String {
        reason(&self.call(who, tool, args).await.expect_err("expected a refusal"))
    }

    async fn decisions(&self) -> Vec<Value> {
        let out = self
            .call(
                &human(),
                "event_log_query",
                json!({ "channels": ["agent.gateway.decision"], "limit": 100 }),
            )
            .await
            .unwrap();
        out["events"].as_array().cloned().unwrap_or_default()
    }

    /// Rewrite the policy and move its mtime forward so the cache reloads
    /// even on a coarse-timestamp filesystem.
    fn rewrite(&self, yaml: &str, bump_secs: u64) {
        std::fs::write(&self.path, yaml).unwrap();
        let f = std::fs::File::options().write(true).open(&self.path).unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(bump_secs)).unwrap();
    }
}

#[tokio::test]
async fn tool_rule_denies_by_glob_and_records_the_rule() {
    let env = setup(
        "rules:\n  - name: no_profile_tools\n    type: tool\n    tool: \"profile_*\"\n    action: deny\n    description: locked down\n",
    );
    let me = dev("builder-1");
    assert_eq!(env.denied(&me, "profile_status", json!({})).await, "policy_deny");
    // Unmatched tools still run.
    env.call(&me, "approval_pending", json!({})).await.unwrap();

    let events = env.decisions().await;
    let deny =
        events.iter().find(|e| e["payload"]["reason_code"] == "policy_deny").expect("a decision event");
    assert_eq!(deny["payload"]["rule"], "no_profile_tools");
    assert_eq!(deny["payload"]["tool"], "profile_status");
}

#[tokio::test]
async fn role_rule_is_an_allow_list() {
    let env = setup(
        "rules:\n  - name: ops_only\n    type: role\n    tool: approval_pending\n    roles: [operator, reviewer-1]\n",
    );
    assert_eq!(env.denied(&dev("builder-1"), "approval_pending", json!({})).await, "role_denied");
    // A profile name or an identity label satisfies the list.
    env.call(&human(), "approval_pending", json!({})).await.unwrap();
    env.call(&dev("reviewer-1"), "approval_pending", json!({})).await.unwrap();

    // An anonymous caller cannot borrow an identity label.
    let anon = Caller { kind: ActorKind::Anonymous, ..dev("reviewer-1") };
    assert_eq!(env.denied(&anon, "approval_pending", json!({})).await, "role_denied");
}

#[tokio::test]
async fn threshold_rule_denies_breaches_and_fails_closed_on_missing_values() {
    let env = setup(
        "rules:\n  - name: small_pages\n    type: threshold\n    tool: event_log_query\n    field: limit\n    max: 10\n",
    );
    let me = dev("builder-1");
    env.call(&me, "event_log_query", json!({ "limit": 5 })).await.unwrap();
    assert_eq!(env.denied(&me, "event_log_query", json!({ "limit": 50 })).await, "threshold_breached");
    assert_eq!(env.denied(&me, "event_log_query", json!({})).await, "threshold_invalid");
    assert_eq!(env.denied(&me, "event_log_query", json!({ "limit": "many" })).await, "threshold_invalid");
}

#[tokio::test]
async fn rate_limit_counts_completed_calls_per_caller() {
    let env = setup(
        "rules:\n  - name: status_budget\n    type: rate_limit\n    tool: profile_status\n    max_calls: 2\n    window_seconds: 60\n",
    );
    let a = dev("builder-1");
    env.call(&a, "profile_status", json!({})).await.unwrap();
    env.call(&a, "profile_status", json!({})).await.unwrap();
    assert_eq!(env.denied(&a, "profile_status", json!({})).await, "rate_limited");
    // Another caller has its own budget; the refusal did not use a slot.
    env.call(&dev("builder-2"), "profile_status", json!({})).await.unwrap();
    assert_eq!(env.denied(&a, "profile_status", json!({})).await, "rate_limited");

    let counted: i64 = env
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM tool_calls WHERE tool = 'profile_status'", [], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(counted, 3);
}

#[tokio::test]
async fn rate_limit_rules_are_validated() {
    for bad in [
        "rules:\n  - name: r\n    type: rate_limit\n    max_calls: 0\n    window_seconds: 60\n",
        "rules:\n  - name: r\n    type: rate_limit\n    max_calls: 5\n",
        "rules:\n  - name: r\n    type: rate_limit\n    max_calls: 5\n    window_seconds: 7200\n",
        "rules:\n  - name: r\n    type: rate_limit\n    max_calls: 5\n    window_seconds: 60\n    action: allow\n",
        "rules:\n  - {name: r, type: rate_limit, max_calls: 5, window_seconds: 60}\n  - {name: r, type: rate_limit, max_calls: 5, window_seconds: 60}\n",
    ] {
        let env = setup(bad);
        assert_eq!(
            env.denied(&dev("builder-1"), "profile_status", json!({})).await,
            "policy_unavailable",
            "{bad}"
        );
    }
}

#[tokio::test]
async fn bind_scopes_rules_to_agents_and_claims() {
    // Deny bound to one agent.
    let env = setup(
        "rules:\n  - name: not_you\n    type: tool\n    tool: profile_status\n    action: deny\n    bind: {agent: builder-1}\n",
    );
    assert_eq!(env.denied(&dev("builder-1"), "profile_status", json!({})).await, "policy_deny");
    env.call(&dev("builder-2"), "profile_status", json!({})).await.unwrap();

    // Allow bound to a project, under default deny: only a claimant of that
    // project gets through; an unclaimed caller is not treated as inside.
    let env = setup(
        "default_action: deny\nrules:\n  - name: alpha_only\n    type: tool\n    tool: profile_status\n    action: allow\n    bind: {project: alpha}\n",
    );
    let now = ua_core::time::now();
    env.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO tasks (title, status, created_at, updated_at, claimed_by, project) \
                 VALUES ('t', 'doing', ?1, ?1, 'builder-1', 'alpha'), ('u', 'doing', ?1, ?1, 'builder-3', 'beta')",
                [&now],
            )?;
            Ok(())
        })
        .unwrap();
    env.call(&dev("builder-1"), "profile_status", json!({})).await.unwrap();
    assert_eq!(env.denied(&dev("builder-2"), "profile_status", json!({})).await, "default_deny");
    assert_eq!(env.denied(&dev("builder-3"), "profile_status", json!({})).await, "default_deny");

    // A deny bound to a project matches unclaimed callers (restrictive), but
    // not a caller whose every claim is elsewhere.
    env.rewrite(
        "rules:\n  - name: alpha_locked\n    type: tool\n    tool: profile_status\n    action: deny\n    bind: {project: alpha}\n",
        5,
    );
    assert_eq!(env.denied(&dev("builder-1"), "profile_status", json!({})).await, "policy_deny");
    assert_eq!(env.denied(&dev("builder-2"), "profile_status", json!({})).await, "policy_deny");
    env.call(&dev("builder-3"), "profile_status", json!({})).await.unwrap();
}

#[tokio::test]
async fn deny_beats_allow_and_default_deny_applies() {
    let env = setup(
        "rules:\n  - {name: ok, type: tool, tool: \"*\", action: allow}\n  - {name: no, type: tool, tool: profile_status, action: deny}\n",
    );
    assert_eq!(env.denied(&dev("builder-1"), "profile_status", json!({})).await, "policy_deny");

    let env = setup(
        "default_action: deny\nrules:\n  - {name: ok, type: tool, tool: approval_pending, action: allow}\n",
    );
    env.call(&dev("builder-1"), "approval_pending", json!({})).await.unwrap();
    assert_eq!(env.denied(&dev("builder-1"), "profile_status", json!({})).await, "default_deny");

    let env = setup("enabled: false\ndefault_action: deny\nrules: []\n");
    env.call(&dev("builder-1"), "profile_status", json!({})).await.unwrap();
}

#[tokio::test]
async fn episode_rules_fail_closed_and_cooldown_spaces_calls() {
    let env =
        setup("rules:\n  - {name: once, type: max_calls_per_episode, tool: profile_status, max_calls: 1}\n");
    assert_eq!(env.denied(&dev("builder-1"), "profile_status", json!({})).await, "episode_limited");

    let env =
        setup("rules:\n  - {name: breathe, type: cooldown, tool: profile_status, cooldown_seconds: 600}\n");
    env.call(&dev("builder-1"), "profile_status", json!({})).await.unwrap();
    assert_eq!(env.denied(&dev("builder-2"), "profile_status", json!({})).await, "episode_limited");
}

#[tokio::test]
async fn unreadable_or_invalid_policy_fails_closed() {
    for bad in [
        "rules: [\n",                                                                     // broken YAML
        "",                                                                               // empty file
        "- just\n- a list\n",                                                             // not a mapping
        "rules:\n  - {name: x, type: teleport}\n",                                        // unknown rule type
        "default_action: maybe\n", // bad default action
        "rules:\n  - {name: t, type: threshold, tool: x, field: n, max: .nan, min: 0}\n", // non-finite bound
        "rules:\n  - {name: r, type: role, tool: x}\n", // role without roles
    ] {
        let env = setup(bad);
        let err = env.call(&dev("builder-1"), "profile_status", json!({})).await.unwrap_err();
        assert_eq!(reason(&err), "policy_unavailable", "{bad:?}");
        assert!(err.to_string().contains("failed closed"), "{err}");
    }

    // A missing file is the empty policy.
    let env = setup_with(None, |_| {});
    env.call(&dev("builder-1"), "profile_status", json!({})).await.unwrap();
    // No policy_file at all: no policy.
    let env = setup_with(None, |c| c.policy_file = None);
    env.call(&dev("builder-1"), "profile_status", json!({})).await.unwrap();
}

#[tokio::test]
async fn policy_reloads_when_the_file_changes() {
    let env = setup("rules: []\n");
    let me = dev("builder-1");
    env.call(&me, "profile_status", json!({})).await.unwrap();

    env.rewrite("rules:\n  - {name: off, type: tool, tool: profile_status, action: deny}\n", 5);
    assert_eq!(env.denied(&me, "profile_status", json!({})).await, "policy_deny");

    env.rewrite("rules: [oops\n", 10);
    assert_eq!(env.denied(&me, "profile_status", json!({})).await, "policy_unavailable");

    env.rewrite("rules: []\n", 15);
    env.call(&me, "profile_status", json!({})).await.unwrap();

    std::fs::remove_file(&env.path).unwrap();
    env.call(&me, "profile_status", json!({})).await.unwrap();
}

#[tokio::test]
async fn require_approval_forces_the_approval_gate() {
    let env = setup(
        "rules:\n  - {name: big_reads, type: threshold, tool: event_log_query, field: limit, max: 10, action: require_approval}\n",
    );
    let me = dev("builder-1");
    // Under the bound: no approval needed.
    env.call(&me, "event_log_query", json!({ "limit": 5 })).await.unwrap();

    let err = env.call(&me, "event_log_query", json!({ "limit": 50 })).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id, tool } = err else {
        panic!("expected a pending approval: {err}")
    };
    assert_eq!(tool, "event_log_query");

    // The requester cannot approve; a human can.
    assert!(
        env.call(&dev("builder-1"), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
            .await
            .is_err()
    );
    env.call(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
        .await
        .unwrap();
    env.call(&me, "event_log_query", json!({ "limit": 50 })).await.unwrap();
    // One pass, one call.
    assert_eq!(
        env.call(&me, "event_log_query", json!({ "limit": 50 })).await.unwrap_err().code(),
        "approval_required"
    );
}

#[tokio::test]
async fn rate_limit_is_checked_before_an_approval_is_parked() {
    let env = setup(
        "rules:\n  - {name: gate, type: tool, tool: profile_status, action: require_approval}\n  - {name: budget, type: rate_limit, tool: profile_status, max_calls: 1, window_seconds: 60}\n",
    );
    let me = dev("builder-1");
    let err = env.call(&me, "profile_status", json!({})).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = err else { panic!("{err}") };
    env.call(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
        .await
        .unwrap();
    env.call(&me, "profile_status", json!({})).await.unwrap();
    assert_eq!(env.denied(&me, "profile_status", json!({})).await, "rate_limited");
}

#[tokio::test]
async fn profile_overlay_lowers_but_never_widens() {
    let env = setup("profile_defaults:\n  builder-1: research\n  builder-2: operator\nrules: []\n");
    // builder-1 is clamped to research: approval_pending is outside it.
    let one = dev("builder-1");
    assert_eq!(env.denied(&one, "approval_pending", json!({})).await, "profile_denied");
    let status = env.call(&one, "profile_status", json!({})).await.unwrap();
    assert_eq!(status["profile"], "research");

    // operator would grant approval_resolve, which developer refuses: ignored.
    let two = dev("builder-2");
    let status = env.call(&two, "profile_status", json!({})).await.unwrap();
    assert_eq!(status["profile"], "developer");
    assert_eq!(
        env.denied(&two, "approval_resolve", json!({ "id": 1, "decision": "approve" })).await,
        "profile_denied"
    );

    // Humans are not clamped.
    let boss = Caller { kind: ActorKind::Human, ..dev("builder-1") };
    env.call(&boss, "approval_pending", json!({})).await.unwrap();
}

fn merge_args() -> Value {
    json!({ "task_id": 999 })
}

#[tokio::test]
async fn prod_actions_refuse_revoked_unscoped_and_anonymous_callers() {
    let lead = agent("lead-1", Profile::ChiefOfStaff);

    let env = setup_with(None, |c| c.revoked_agents = vec!["lead-1".into()]);
    assert_eq!(env.denied(&lead, "git_merge_task", merge_args()).await, "agent_revoked");
    // No approval row was parked for a refused identity.
    let pending = env.call(&human(), "approval_pending", json!({})).await.unwrap();
    assert_eq!(pending["pending"].as_array().unwrap().len(), 0);

    let env = setup_with(None, |c| {
        c.agent_scopes.insert("lead-1".into(), "delete".into());
        c.agent_scopes.insert("lead-2".into(), "merge|deploy".into());
    });
    assert_eq!(env.denied(&lead, "git_merge_task", merge_args()).await, "scope_denied");
    let lead2 = agent("lead-2", Profile::ChiefOfStaff);
    assert_eq!(
        env.call(&lead2, "git_merge_task", merge_args()).await.unwrap_err().code(),
        "approval_required"
    );

    let env = setup_with(None, |_| {});
    let anon = Caller {
        kind: ActorKind::Anonymous,
        enforce_profile: false,
        transport: Transport::Http,
        ..lead.clone()
    };
    assert_eq!(env.denied(&anon, "git_merge_task", merge_args()).await, "anonymous_prod_action");
    let local = Caller { transport: Transport::Stdio, ..anon };
    assert_eq!(
        env.call(&local, "git_merge_task", merge_args()).await.unwrap_err().code(),
        "approval_required"
    );
}

#[tokio::test]
async fn a_revoked_agent_cannot_spend_an_earlier_pass() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.db_path = Some(dir.path().join("ua.db"));
    let reg = builtin_registry();
    let lead = agent("lead-1", Profile::ChiefOfStaff);

    let id = {
        let hub = Hub::open(cfg.clone()).unwrap();
        let err = reg.call(&hub, &lead, "git_merge_task", merge_args()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, .. } = err else { panic!("{err}") };
        reg.call(&hub, &human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
            .await
            .unwrap();
        approval_id
    };

    // The same database, now with the agent revoked.
    cfg.revoked_agents = vec!["lead-1".into()];
    let hub = Hub::open(cfg).unwrap();
    let err = reg.call(&hub, &lead, "git_merge_task", merge_args()).await.unwrap_err();
    assert_eq!(reason(&err), "agent_revoked");
    let pending = reg.call(&hub, &human(), "approval_pending", json!({})).await.unwrap();
    let live = pending["approved_unconsumed"].as_array().unwrap();
    assert!(live.iter().any(|a| a["id"] == id), "the pass stays unspent: {pending}");
}
