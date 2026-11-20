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
        self.register_billing(label, provider, "subscription").await
    }

    async fn register_billing(&self, label: &str, provider: &str, billing: &str) -> Value {
        self.ok(
            &human(),
            "provider_account_register",
            json!({ "provider": provider, "label": label, "billing": billing }),
        )
        .await
    }

    /// The payload of an approval.
    fn payload(&self, approval_id: i64) -> Value {
        self.hub
            .db()
            .read(move |c| {
                let t: String =
                    c.query_row("SELECT payload FROM approvals WHERE id = ?1", [approval_id], |r| r.get(0))?;
                Ok(serde_json::from_str(&t).unwrap())
            })
            .unwrap()
    }

    fn approvals(&self) -> i64 {
        self.hub
            .db()
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM approvals", [], |r| r.get::<_, i64>(0))?))
            .unwrap()
    }

    fn event_payloads(&self, kind: &str) -> Vec<Value> {
        let kind = kind.to_string();
        self.hub
            .db()
            .read(move |c| {
                let mut st = c.prepare(
                    "SELECT payload FROM event_log WHERE channel = 'provider.account' \
                     AND json_extract(payload, '$.kind') = ?1 ORDER BY seq",
                )?;
                let rows =
                    st.query_map([&kind], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
                Ok(rows.into_iter().map(|t| serde_json::from_str(&t).unwrap()).collect())
            })
            .unwrap()
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
            json!({ "provider": "OpenAI", "label": "openai-main", "billing": "api", "notes": "team key" }),
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
    // An account stores no secret and no secret name: the field is gone.
    for bad in [
        json!({ "provider": "openai", "label": "x1", "billing": "api", "secret_name": "OPENAI_KEY_MAIN" }),
        json!({ "provider": "openai", "label": "x2", "billing": "api", "notes": "api_key=abc123" }),
        json!({ "provider": "openai", "label": "x3", "billing": "metered" }),
    ] {
        let e = h.call(&human(), "provider_account_register", bad.clone()).await.unwrap_err();
        assert_eq!(e.code(), "invalid_argument", "{bad}");
    }

    let v = h
        .ok(&human(), "provider_account_update", json!({ "label": "openai-main", "billing": "subscription" }))
        .await;
    assert_eq!(v["changed"], json!(["billing"]));
    assert!(v["account"].get("secret_name").is_none(), "{v}");
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

/// Review finding: a subscription account's harness passed metered API keys
/// through its env_allowlist. Dispatch refuses it before any approval.
#[tokio::test]
async fn a_subscription_harness_passing_an_api_key_is_refused_before_approval() {
    let h = H::with(|c, _| {
        let mut a = harness(&["/bin/true"], Some("sub"));
        a.env_allowlist = vec!["OPENAI_API_KEY".into(), "PI_HOME".into()];
        c.harnesses.insert("leaky".into(), a);
        let mut b = harness(&["/bin/true"], Some("sub"));
        b.env_allowlist = vec!["OPENAI_API_KEY".into()];
        b.env_denylist = vec!["OPENAI_API_KEY".into()];
        c.harnesses.insert("tight".into(), b);
        let mut m = harness(&["/bin/true"], Some("metered"));
        m.env_allowlist = vec!["OPENAI_API_KEY".into()];
        c.harnesses.insert("metered".into(), m);
    });
    h.register("sub", "openai").await;
    h.register_billing("metered", "openai", "api").await;
    let tid = h.task().await;
    let e = h.dispatch(json!({ "task_id": tid, "agent": "agent-1", "harness": "leaky" })).await.unwrap_err();
    assert_eq!(code(&e), "subscription_api_key_passthrough");
    assert!(e.to_string().contains("OPENAI_API_KEY") && !e.to_string().contains("PI_HOME"), "{e}");
    assert_eq!(h.approvals(), 0, "nobody is asked to approve it");
    // Denied names, and an api account, pass the check and reach the approval.
    for name in ["tight", "metered"] {
        let me = agent("agent-1");
        let e = h
            .call(&me, "dispatch_task", json!({ "task_id": tid, "agent": "agent-1", "harness": name }))
            .await;
        assert!(matches!(e, Err(UaError::ApprovalRequired { .. })), "{name}: {e:?}");
    }
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
        assert_eq!(run["rerouted_from"]["billing"], "subscription");
        assert_eq!(run["rerouted_from"]["to_billing"], "subscription");
        let r = h.wait_terminal(run["run_id"].as_str().unwrap()).await;
        assert_eq!(r["harness"], "coder-b");
        let log = std::fs::read_to_string(r["log_path"].as_str().unwrap()).unwrap();
        assert!(log.contains("from-b"), "{log}");
        let status = h.ok(&human(), "provider_quota_status", json!({ "label": "acct-b" })).await;
        assert_eq!(status["accounts"][0]["availability"], "available");
        assert_eq!(status["accounts"][0]["recent"]["by_state"]["finished"], 1);
    }

    /// Review finding: fallback ignored billing, so a subscription harness
    /// could silently move onto a metered account. It stays within one
    /// billing type unless the harness opts in, and the approval shows both.
    #[tokio::test]
    async fn fallback_keeps_the_billing_type_unless_the_harness_opts_in() {
        let setup = |cross: bool| {
            H::with(move |c, _| {
                let mut a = harness(&["/bin/sh", "-c", "echo from-a"], Some("sub-a"));
                a.provider_fallback = true;
                a.provider_fallback_cross_billing = cross;
                c.harnesses.insert("coder-a".into(), a);
                c.harnesses
                    .insert("coder-m".into(), harness(&["/bin/sh", "-c", "echo metered"], Some("api-m")));
            })
        };
        for cross in [false, true] {
            let h = setup(cross);
            h.register("sub-a", "anthropic").await;
            h.register_billing("api-m", "anthropic", "api").await;
            h.ok(&human(), "provider_account_disable", json!({ "label": "sub-a" })).await;
            let tid = h.task().await;
            let args = json!({ "task_id": tid, "agent": "agent-1", "harness": "coder-a" });
            if !cross {
                let e = h.dispatch(args).await.unwrap_err();
                assert_eq!(code(&e), "provider_account_disabled");
                assert!(e.to_string().contains("subscription account"), "{e}");
                continue;
            }
            let first = h.call(&agent("agent-1"), "dispatch_task", args.clone()).await.unwrap_err();
            let UaError::ApprovalRequired { approval_id, .. } = first else { panic!("{first}") };
            let p = h.payload(approval_id);
            assert_eq!(p["harness"], "coder-m", "{p}");
            assert_eq!(p["rerouted_from"]["billing"], "subscription", "{p}");
            assert_eq!(p["rerouted_from"]["to_billing"], "api", "{p}");
            assert_eq!(p["rerouted_from"]["to_provider_account"], "api-m", "{p}");
        }
    }

    /// Review finding: a usage-limit phrase anywhere in the run log (the
    /// model's own stdout) or in a self-reported reason rate-limited a shared
    /// account. Only a harness-declared pattern on stderr, or a structured JSON
    /// error event, does; the ledger keeps the matched line and its source.
    #[tokio::test]
    async fn only_a_declared_quota_signal_rate_limits_the_account() {
        let h = H::with(|c, _| {
            let mut out =
                harness(&["/bin/sh", "-c", "echo 'Error: 5-hour limit reached'; exit 1"], Some("acct-o"));
            out.quota_patterns = vec!["limit reached".into()];
            c.harnesses.insert("stdout-only".into(), out);
            c.harnesses.insert(
                "undeclared".into(),
                harness(&["/bin/sh", "-c", "echo 'Error: 5-hour limit reached' >&2; exit 1"], Some("acct-o")),
            );
            c.harnesses.insert("sleeper".into(), harness(&["/bin/sh", "-c", "sleep 3"], Some("acct-o")));
            let mut pi = harness(
                &[
                    "/bin/sh",
                    "-c",
                    r#"echo '{"type":"message_end","message":{"stopReason":"error","errorMessage":"429 insufficient_quota"}}'; exit 1"#,
                ],
                Some("acct-j"),
            );
            pi.quota_patterns = vec!["insufficient_quota".into()];
            pi.quota_json_errors = true;
            c.harnesses.insert("pi-json".into(), pi);
        });
        h.register("acct-o", "anthropic").await;
        h.register("acct-j", "openai-codex").await;
        for name in ["stdout-only", "undeclared"] {
            let tid = h.task().await;
            let run =
                h.dispatch(json!({ "task_id": tid, "agent": "agent-1", "harness": name })).await.unwrap();
            let r = h.wait_terminal(run["run_id"].as_str().unwrap()).await;
            assert_eq!(r["failure_class"], "exit", "{name}: {r}");
        }
        // A self-report quoting a limit is advisory: recorded, not limiting.
        let tid = h.task().await;
        let run =
            h.dispatch(json!({ "task_id": tid, "agent": "agent-1", "harness": "sleeper" })).await.unwrap();
        let rid = run["run_id"].as_str().unwrap();
        h.ok(
            &agent("agent-1"),
            "dispatch_report_self",
            json!({ "run_id": rid, "state": "failed", "failure_reason": "usage limit reached" }),
        )
        .await;
        let r = h.wait_terminal(rid).await;
        assert_eq!(r["failure_class"], "provider_quota_reported", "{r}");
        assert_eq!(h.events("quota_reported"), 1);
        assert_eq!(h.events("rate_limited_observed"), 0);
        let status = h.ok(&human(), "provider_quota_status", json!({ "label": "acct-o" })).await;
        assert_ne!(status["accounts"][0]["availability"], "rate_limited", "{status}");

        // Pi's structured error event is a declared signal.
        let tid = h.task().await;
        let run =
            h.dispatch(json!({ "task_id": tid, "agent": "agent-1", "harness": "pi-json" })).await.unwrap();
        let r = h.wait_terminal(run["run_id"].as_str().unwrap()).await;
        assert_eq!(r["failure_class"], "provider_quota_exhausted", "{r}");
        let ev = h.event_payloads("rate_limited_observed");
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["signal"], json!({ "source": "json_error", "line": "429 insufficient_quota" }));
    }

    #[tokio::test]
    async fn a_quota_failure_rate_limits_the_account() {
        let h = H::with(|c, _| {
            let mut q = harness(
                &["/bin/sh", "-c", "echo 'Error: 5-hour limit reached - resets 3am' >&2; exit 1"],
                Some("acct-q"),
            );
            q.quota_patterns = vec!["limit reached".into()];
            c.harnesses.insert("limited".into(), q);
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
        let ev = &h.event_payloads("rate_limited_observed")[0];
        assert_eq!(ev["signal"]["source"], "stderr", "{ev}");
        assert_eq!(ev["signal"]["line"], "Error: 5-hour limit reached - resets 3am");

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
        // The operator's clear lifts the limit: dispatch reaches the approval again.
        assert_eq!(status["accounts"][0]["rate_limited_until"], Value::Null);
        assert_ne!(status["accounts"][0]["availability"], "rate_limited");
        let e = h
            .call(
                &agent("agent-1"),
                "dispatch_task",
                json!({ "task_id": tid, "agent": "agent-1", "harness": "limited" }),
            )
            .await;
        assert!(matches!(e, Err(UaError::ApprovalRequired { .. })), "{e:?}");
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
        // Review findings: env values are bound by hash, never shown raw, and
        // the approval binds the absolute program argv[0] resolves to.
        use sha2::{Digest, Sha256};
        let sha =
            |v: &str| Sha256::digest(v.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert!(payload.get("env").is_none(), "{payload}");
        assert_eq!(payload["env_sha256"]["PI_SKIP_VERSION_CHECK"], sha("1"));
        assert!(!payload.to_string().contains("must-not-reach"), "{payload}");
        let program = h.dir.path().join("pi-bin").join("pi");
        assert_eq!(payload["program"], program.display().to_string());
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
