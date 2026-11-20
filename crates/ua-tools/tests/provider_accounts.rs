//! Provider accounts through the governed registry: the operator registry,
//! dispatch refusals and fallback routing on account state, quota observed
//! from run outcomes, and a Pi harness run against a fake `pi` (unix only).

use std::time::Duration;

use serde_json::{Value, json};
use ua_core::config::HarnessConfig;
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

struct H {
    hub: Hub,
    reg: Registry,
    dir: tempfile::TempDir,
}

fn harness(argv: &[&str], account: Option<&str>) -> HarnessConfig {
    HarnessConfig {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        timeout_s: 20,
        provider_account: account.map(str::to_string),
        ..HarnessConfig::default()
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
    }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Operator, enforce_profile: true, ..agent("operator") }
}

fn code(e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, .. } | UaError::ConflictCode { reason_code, .. } => {
            reason_code.clone()
        }
        other => other.code().to_string(),
    }
}

impl H {
    fn with(f: impl FnOnce(&mut Config, &std::path::Path)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        f(&mut cfg, dir.path());
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), dir }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.call(who, tool, args.clone()).await.unwrap_or_else(|e| panic!("{tool}({args}) failed: {e}"))
    }

    async fn task(&self) -> i64 {
        let id = self.ok(&agent("lead-1"), "task_add", json!({ "title": "Port the widget" })).await["id"]
            .as_i64()
            .unwrap();
        let wt = self.dir.path().join(format!("wt-{id}"));
        std::fs::create_dir_all(&wt).unwrap();
        let stmt = format!("UPDATE tasks SET worktree_path = '{}' WHERE id = {id}", wt.display());
        self.hub
            .db()
            .write(move |tx| {
                tx.execute_batch(&stmt)?;
                Ok(())
            })
            .unwrap();
        id
    }

    /// `dispatch_task` for agent-1: refused, or parked, approved and retried.
    async fn dispatch(&self, args: Value) -> Result<Value, UaError> {
        let me = agent("agent-1");
        match self.call(&me, "dispatch_task", args.clone()).await {
            Err(UaError::ApprovalRequired { approval_id, .. }) => {
                self.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
                    .await;
                self.call(&me, "dispatch_task", args).await
            }
            other => other,
        }
    }

    async fn register(&self, label: &str, provider: &str) -> Value {
        self.ok(
            &human(),
            "provider_account_register",
            json!({ "provider": provider, "label": label, "billing": "subscription" }),
        )
        .await
    }

    async fn wait_terminal(&self, run_id: &str) -> Value {
        for _ in 0..200 {
            let r = self.ok(&human(), "dispatch_delivery_receipt", json!({ "run_id": run_id })).await;
            if r["terminal"] == true {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("run {run_id} never ended");
    }

    fn events(&self, kind: &str) -> i64 {
        let kind = kind.to_string();
        self.hub
            .db()
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM event_log WHERE channel = 'provider.account' \
                     AND json_extract(payload, '$.kind') = ?1",
                    [&kind],
                    |r| r.get(0),
                )?)
            })
            .unwrap()
    }
}

#[tokio::test]
async fn operators_manage_the_registry_and_no_secret_value_is_stored() {
    let h = H::with(|_, _| {});
    let e = h
        .call(
            &agent("agent-1"),
            "provider_account_register",
            json!({ "provider": "openai", "label": "a", "billing": "api" }),
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), "operator_required");

    let v = h
        .ok(
            &human(),
            "provider_account_register",
            json!({ "provider": "OpenAI", "label": "openai-main", "billing": "api",
                    "secret_name": "OPENAI_KEY_MAIN", "notes": "team key" }),
        )
        .await;
    assert_eq!(v["account"]["provider"], "openai", "provider is normalized");
    assert_eq!(v["account"]["enabled"], true);
    assert_eq!(v["account"]["cooldown_s"], 3600);
    let e = h
        .call(
            &human(),
            "provider_account_register",
            json!({ "provider": "openai", "label": "openai-main", "billing": "api" }),
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), "provider_account_exists");
    for bad in [
        json!({ "provider": "openai", "label": "x1", "billing": "api", "secret_name": "sk-abcdefghijklmnopqrst" }),
        json!({ "provider": "openai", "label": "x2", "billing": "api", "notes": "api_key=abc123" }),
        json!({ "provider": "openai", "label": "x3", "billing": "metered" }),
    ] {
        let e = h.call(&human(), "provider_account_register", bad.clone()).await.unwrap_err();
        assert_eq!(e.code(), "invalid_argument", "{bad}");
    }

    let v = h
        .ok(
            &human(),
            "provider_account_update",
            json!({ "label": "openai-main", "billing": "subscription", "secret_name": "" }),
        )
        .await;
    assert_eq!(v["changed"], json!(["billing", "secret_name"]));
    assert_eq!(v["account"]["secret_name"], Value::Null);
    let v = h
        .ok(&human(), "provider_account_disable", json!({ "label": "openai-main", "reason": "rotating" }))
        .await;
    assert_eq!((v["account"]["enabled"].clone(), v["changed"].clone()), (json!(false), json!(true)));
    assert_eq!(v["account"]["disabled_reason"], "rotating");

    let list = h.ok(&agent("agent-1"), "provider_account_list", json!({ "include_disabled": false })).await;
    assert_eq!(list["count"], 0);
    let list = h.ok(&agent("agent-1"), "provider_account_list", json!({})).await;
    assert_eq!(list["count"], 1);
    assert_eq!((h.events("registered"), h.events("updated"), h.events("disabled")), (1, 1, 1));

    let status = h.ok(&agent("agent-1"), "provider_quota_status", json!({ "label": "openai-main" })).await;
    assert_eq!(status["accounts"][0]["availability"], "disabled");
}

#[tokio::test]
async fn dispatch_refuses_an_unavailable_account_before_asking_for_approval() {
    let h = H::with(|c, _| {
        c.harnesses.insert("coder".into(), harness(&["/bin/true"], Some("acct-a")));
    });
    let tid = h.task().await;
    let args = json!({ "task_id": tid, "agent": "agent-1", "harness": "coder" });
    let pending = |h: &H| {
        h.hub
            .db()
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM approvals", [], |r| r.get::<_, i64>(0))?))
            .unwrap()
    };

    let e = h.dispatch(args.clone()).await.unwrap_err();
    assert_eq!(code(&e), "provider_account_unknown");
    h.register("acct-a", "anthropic").await;
    h.ok(&human(), "provider_account_disable", json!({ "label": "acct-a" })).await;
    let e = h.dispatch(args.clone()).await.unwrap_err();
    assert_eq!(code(&e), "provider_account_disabled");
    h.ok(
        &human(),
        "provider_account_update",
        json!({ "label": "acct-a", "enabled": true, "rate_limited_until": "2999-01-01T00:00:00Z" }),
    )
    .await;
    let e = h.dispatch(args.clone()).await.unwrap_err();
    assert_eq!(code(&e), "provider_rate_limited");
    assert!(e.to_string().contains("2999-01-01"), "{e}");
    assert_eq!(pending(&h), 0, "nobody was asked to approve a run that cannot start");

    let status = h.ok(&human(), "provider_quota_status", json!({})).await;
    let acct = &status["accounts"][0];
    assert_eq!(acct["availability"], "rate_limited");
    assert_eq!(acct["harnesses"], json!(["coder"]));
}

#[cfg(unix)]
mod spawn {
    use super::*;

    #[tokio::test]
    async fn fallback_routes_to_another_harness_of_the_same_provider() {
        let h = H::with(|c, _| {
            let mut a = harness(&["/bin/sh", "-c", "echo from-a"], Some("acct-a"));
            a.provider_fallback = true;
            c.harnesses.insert("coder-a".into(), a);
            c.harnesses.insert("coder-b".into(), harness(&["/bin/sh", "-c", "echo from-b"], Some("acct-b")));
            c.harnesses.insert("other".into(), harness(&["/bin/sh", "-c", "echo other"], Some("acct-c")));
        });
        h.register("acct-a", "anthropic").await;
        h.register("acct-b", "anthropic").await;
        h.register("acct-c", "openai").await;
        h.ok(&human(), "provider_account_disable", json!({ "label": "acct-a" })).await;
        // The other provider's account is never a fallback, even when it is first.
        h.ok(&human(), "provider_account_disable", json!({ "label": "acct-b" })).await;
        let tid = h.task().await;
        let args = json!({ "task_id": tid, "agent": "agent-1", "harness": "coder-a" });
        let e = h.dispatch(args.clone()).await.unwrap_err();
        assert_eq!(code(&e), "provider_account_disabled");
        assert!(e.to_string().contains("no other harness"), "{e}");

        h.ok(&human(), "provider_account_update", json!({ "label": "acct-b", "enabled": true })).await;
        let run = h.dispatch(args).await.unwrap();
        assert_eq!(run["rerouted_from"]["harness"], "coder-a", "{run}");
        assert_eq!(run["rerouted_from"]["reason"], "provider_account_disabled");
        let r = h.wait_terminal(run["run_id"].as_str().unwrap()).await;
        assert_eq!(r["harness"], "coder-b");
        let log = std::fs::read_to_string(r["log_path"].as_str().unwrap()).unwrap();
        assert!(log.contains("from-b"), "{log}");
        let status = h.ok(&human(), "provider_quota_status", json!({ "label": "acct-b" })).await;
        assert_eq!(status["accounts"][0]["availability"], "available");
        assert_eq!(status["accounts"][0]["recent"]["by_state"]["finished"], 1);
    }

    #[tokio::test]
    async fn a_quota_failure_rate_limits_the_account() {
        let h = H::with(|c, _| {
            c.harnesses.insert(
                "limited".into(),
                harness(
                    &["/bin/sh", "-c", "echo 'Error: 5-hour limit reached - resets 3am' >&2; exit 1"],
                    Some("acct-q"),
                ),
            );
        });
        h.register("acct-q", "anthropic").await;
        let tid = h.task().await;
        let args = json!({ "task_id": tid, "agent": "agent-1", "harness": "limited" });
        let run = h.dispatch(args).await.unwrap();
        let r = h.wait_terminal(run["run_id"].as_str().unwrap()).await;
        assert_eq!(r["run_state"], "failed");
        assert_eq!(r["failure_class"], "provider_quota_exhausted", "{r}");

        let status = h.ok(&human(), "provider_quota_status", json!({ "label": "acct-q" })).await;
        let acct = &status["accounts"][0];
        assert_eq!(acct["availability"], "rate_limited", "{acct}");
        assert_eq!(acct["last_error_class"], "provider_quota_exhausted");
        assert_eq!(acct["recent"]["quota_failures"], 1);
        assert_eq!(h.events("rate_limited_observed"), 1);

        // The task is free again, but the account is not.
        let tid = h.task().await;
        let e = h
            .dispatch(json!({ "task_id": tid, "agent": "agent-1", "harness": "limited" }))
            .await
            .unwrap_err();
        assert_eq!(code(&e), "provider_rate_limited");
        h.ok(
            &human(),
            "provider_account_update",
            json!({ "label": "acct-q", "rate_limited_until": "", "clear_error": true }),
        )
        .await;
        let status = h.ok(&human(), "provider_quota_status", json!({ "label": "acct-q" })).await;
        assert_eq!(status["accounts"][0]["last_error_class"], Value::Null);
    }

    /// A fake `pi` that reports how it was started.
    const FAKE_PI: &str = r#"#!/bin/sh
printf 'argv:%s\n' "$*"
printf 'fixed:%s\n' "${PI_SKIP_VERSION_CHECK:-unset}"
printf 'gemini:%s\n' "${GEMINI_API_KEY:-unset}"
printf 'label:%s\n' "${UA_AGENT_LABEL:-unset}"
printf 'stdin:'; cat; printf '\n'
printf '{"type":"agent_end"}\n'
"#;

    #[tokio::test]
    async fn a_pi_harness_runs_with_its_argv_env_and_stdin_conventions() {
        use std::os::unix::fs::PermissionsExt;
        let h = H::with(|c, dir| {
            let bin = dir.join("pi-bin");
            std::fs::create_dir_all(&bin).unwrap();
            let pi = bin.join("pi");
            std::fs::write(&pi, FAKE_PI).unwrap();
            std::fs::set_permissions(&pi, std::fs::Permissions::from_mode(0o755)).unwrap();
            let mut h = harness(
                &[
                    "pi",
                    "--print",
                    "--mode",
                    "json",
                    "--provider",
                    "openai-codex",
                    "--model",
                    "gpt-5.5",
                    "--no-session",
                ],
                Some("pi-sub"),
            );
            h.path_prepend = vec![bin];
            h.env = [
                ("PI_SKIP_VERSION_CHECK".to_string(), "1".to_string()),
                ("GEMINI_API_KEY".to_string(), "must-not-reach".to_string()),
            ]
            .into_iter()
            .collect();
            h.env_denylist = vec!["ANTHROPIC_API_KEY".into(), "GEMINI_API_KEY".into()];
            h.stdin = Some(r#"{"id":"req_1","type":"prompt","message":{prompt_json}}"#.into());
            c.harnesses.insert("pi".into(), h);
        });
        h.register("pi-sub", "openai-codex").await;
        let tid = h.task().await;
        let args = json!({ "task_id": tid, "agent": "agent-1", "harness": "pi", "prompt": "fix the \"quoted\" {run_id} bug" });
        let first = h.call(&agent("agent-1"), "dispatch_task", args.clone()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, .. } = first else { panic!("{first}") };
        let payload: Value = h
            .hub
            .db()
            .read(move |c| {
                let t: String =
                    c.query_row("SELECT payload FROM approvals WHERE id = ?1", [approval_id], |r| r.get(0))?;
                Ok(serde_json::from_str(&t).unwrap())
            })
            .unwrap();
        assert_eq!(payload["provider_account"], "pi-sub", "the approval binds the account: {payload}");
        assert_eq!(payload["env_denylist"], json!(["ANTHROPIC_API_KEY", "GEMINI_API_KEY"]));
        assert!(payload["stdin"].as_str().unwrap().contains("{prompt_json}"));

        let run = h.dispatch(args).await.unwrap();
        assert_eq!(run["spawned"], true, "pi is found on the prepended PATH: {run}");
        let r = h.wait_terminal(run["run_id"].as_str().unwrap()).await;
        assert_eq!(r["run_state"], "finished", "{r}");
        let log = std::fs::read_to_string(r["log_path"].as_str().unwrap()).unwrap();
        assert!(
            log.contains("argv:--print --mode json --provider openai-codex --model gpt-5.5 --no-session\n"),
            "{log}"
        );
        assert!(log.contains("fixed:1\n"), "{log}");
        assert!(log.contains("gemini:unset\n"), "a denied name never reaches the child: {log}");
        assert!(log.contains("label:agent-1\n"), "{log}");
        assert!(
            log.contains(
                r#"stdin:{"id":"req_1","type":"prompt","message":"fix the \"quoted\" {run_id} bug"}"#
            ),
            "the prompt goes to stdin as one JSON string, never re-expanded: {log}"
        );
        assert!(log.contains(r#"{"type":"agent_end"}"#), "{log}");
        let status = h.ok(&human(), "provider_quota_status", json!({ "label": "pi-sub" })).await;
        assert!(status["accounts"][0]["last_success_at"].is_string());
    }
}
