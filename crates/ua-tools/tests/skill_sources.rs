//! Org-scoped Git skill source allowlist and hardened fetch tests (slice D2a).
//!
//! Exercises `source_add`, `source_revoke`, and `source_list` through
//! `builtin_registry().call(..)` as well as URL validation, DNS-pinning / SSRF
//! refusals, real-subprocess env scrubbing, exact git `-c` argv, terminal
//! revoke DB triggers, and (under `feature = "test-util"`) local `file://`
//! bare cache fetching. Runs completely offline.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use rusqlite::params;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::families::skill_sources::fetch::{
    DnsResolver, FetchOptions, build_git_command, build_git_command_with_host_env, classify_and_pin_ip,
    run_git, validate_source_url,
};
use ua_tools::{Hub, Registry, builtin_registry};

struct Harness {
    _home: tempfile::TempDir,
    hub: Hub,
    reg: Registry,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(home.path());
        cfg.human_identities = vec!["operator".into(), "reviewer".into()];
        cfg.lifecycle_operators = Some(vec!["ops-bot".into()]);
        let hub = Hub::in_memory(cfg).unwrap();
        Self { _home: home, hub, reg: builtin_registry() }
    }

    async fn call(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, "skill_registry", json!({ "action": action, "params": params })).await
    }

    async fn approve(&self, id: i64) {
        self.reg
            .call(&self.hub, &approver(), "approval_resolve", json!({ "id": id, "decision": "approve" }))
            .await
            .unwrap();
    }

    async fn gated(&self, who: &Caller, action: &str, params: Value) -> (i64, Value) {
        let approval_id = match self.call(who, action, params.clone()).await {
            Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
            other => panic!("expected approval_required for {action}, got {other:?}"),
        };
        self.approve(approval_id).await;
        let out = self.call(who, action, params).await.unwrap_or_else(|e| panic!("{action} failed: {e}"));
        (approval_id, out)
    }

    fn approval_payload(&self, id: i64) -> Value {
        self.hub
            .db()
            .read(move |c| {
                let raw: String =
                    c.query_row("SELECT payload FROM approvals WHERE id = ?1", [id], |r| r.get(0))?;
                Ok(serde_json::from_str(&raw)?)
            })
            .unwrap()
    }

    fn approval_count(&self) -> i64 {
        self.hub.db().read(|c| Ok(c.query_row("SELECT COUNT(*) FROM approvals", [], |r| r.get(0))?)).unwrap()
    }

    fn add_org(&self, id: &str) {
        self.hub
            .db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                     VALUES (?1, ?1, 'Org B', '[\"developer\", \"coordinator\", \"operator\"]', '2026-01-01T00:00:00+00:00')",
                    [id],
                )?;
                Ok(())
            })
            .unwrap();
    }
}

fn caller(label: &str, kind: ActorKind, profile: Profile, org: &str) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn human() -> Caller {
    caller("operator", ActorKind::Human, Profile::Coordinator, ua_core::DEFAULT_ORG)
}

fn approver() -> Caller {
    caller("reviewer", ActorKind::Human, Profile::Operator, ua_core::DEFAULT_ORG)
}

#[tokio::test]
async fn source_add_list_revoke_round_trip_and_terminal_revocation() {
    let h = Harness::new();
    let sha1 = "1".repeat(40);
    let sha2 = "2".repeat(40);

    // Add source with trailing .git: preserves .git in canonical_url so .git-only
    // remotes fetch the exact approved URL, and parks bound approval.
    let add_params = json!({
        "url": "https://GitHub.com/Example-Org/Agent-Skills.git/",
        "tracking_ref": "main",
        "pinned_sha": sha1,
        "allowed_subpaths": ["skills/ops/", "skills/core"],
    });
    let (approval_id, added) = h.gated(&human(), "source_add", add_params.clone()).await;
    assert_eq!(added["ok"], true, "{added}");
    assert_eq!(added["idempotent"], false, "{added}");
    let src = &added["source"];
    let src_id = src["id"].as_str().unwrap().to_string();
    assert_eq!(src["canonical_url"], "https://github.com/Example-Org/Agent-Skills.git");
    assert_eq!(src["host"], "github.com");
    assert_eq!(src["repo_path"], "Example-Org/Agent-Skills.git");
    assert_eq!(src["tracking_ref"], "main");
    assert_eq!(src["pinned_sha"], sha1);
    assert_eq!(src["allowed_subpaths"], json!(["skills/core", "skills/ops"]));
    assert_eq!(src["status"], "active");
    assert_eq!(src["approval_id"], approval_id);

    let bound = h.approval_payload(approval_id);
    assert_eq!(
        bound,
        json!({
            "action": "source_add",
            "org_id": "default",
            "canonical_url": "https://github.com/Example-Org/Agent-Skills.git",
            "tracking_ref": "main",
            "pinned_sha": sha1,
            "allowed_subpaths": ["skills/core", "skills/ops"],
        })
    );

    // Re-adding the exact same canonical URL and params is idempotent.
    let again = h.call(&human(), "source_add", add_params).await.unwrap();
    assert_eq!(again["idempotent"], true, "{again}");
    assert_eq!(again["source"]["id"], src_id);

    // Adding a case or .git variant while the original is active is refused (conflict).
    let variant_conflict = h
        .call(
            &human(),
            "source_add",
            json!({
                "url": "https://github.com/example-org/agent-skills",
                "tracking_ref": "main",
                "pinned_sha": sha1,
                "allowed_subpaths": ["skills/core", "skills/ops"],
            }),
        )
        .await
        .unwrap_err();
    assert!(matches!(variant_conflict, UaError::Conflict { .. }), "{variant_conflict:?}");

    // Adding a different pin for the same active URL (case-insensitive / without .git) is refused.
    let conflict = h
        .call(
            &human(),
            "source_add",
            json!({
                "url": "https://github.com/example-org/agent-skills",
                "tracking_ref": "main",
                "pinned_sha": sha2,
            }),
        )
        .await
        .unwrap_err();
    assert!(matches!(conflict, UaError::Conflict { .. }), "{conflict:?}");

    // source_list returns the active source.
    let listed = h.call(&human(), "source_list", json!({})).await.unwrap();
    assert_eq!(listed["sources"].as_array().unwrap().len(), 1);
    assert_eq!(listed["sources"][0]["id"], src_id);

    // Revoke requires approval, marks row revoked, and emits skill.source_revoked.
    let rev_params = json!({ "source_id": src_id, "reason": "upstream rotated" });
    let (rev_approval_id, revoked) = h.gated(&human(), "source_revoke", rev_params.clone()).await;
    assert_eq!(revoked["ok"], true, "{revoked}");
    assert_eq!(revoked["source"]["status"], "revoked");
    assert_eq!(revoked["source"]["revoked_by"], "operator");
    assert_eq!(revoked["source"]["revoke_reason"], "upstream rotated");
    let rev_bound = h.approval_payload(rev_approval_id);
    assert_eq!(rev_bound["action"], "source_revoke");
    assert_eq!(rev_bound["source_id"], src_id);
    assert_eq!(rev_bound["canonical_url"], "https://github.com/Example-Org/Agent-Skills.git");

    // Active list is now empty; revoked & all lists still show the historical row.
    assert_eq!(h.call(&human(), "source_list", json!({})).await.unwrap()["sources"], json!([]));
    assert_eq!(
        h.call(&human(), "source_list", json!({ "status": "revoked" })).await.unwrap()["sources"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        h.call(&human(), "source_list", json!({ "status": "all" })).await.unwrap()["sources"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Revocation is terminal at both tool and SQLite trigger layers (UPDATE and DELETE).
    let rev_again = h.call(&human(), "source_revoke", rev_params).await.unwrap_err();
    assert!(matches!(rev_again, UaError::Conflict { .. }), "{rev_again:?}");

    let sql_reactivate = h.hub.db().write({
        let id = src_id.clone();
        move |tx| {
            tx.execute("UPDATE skill_sources SET status = 'active' WHERE id = ?1", [id])?;
            Ok(())
        }
    });
    assert!(sql_reactivate.is_err(), "DB trigger must refuse modifying a revoked skill source");

    let sql_delete = h.hub.db().write({
        let id = src_id.clone();
        move |tx| {
            tx.execute("DELETE FROM skill_sources WHERE id = ?1", [id])?;
            Ok(())
        }
    });
    assert!(sql_delete.is_err(), "DB trigger must refuse deleting a revoked skill source");

    // Re-adding the same repo (even without .git / different case) with the previously
    // revoked pinned_sha is refused (§1 fresh pinned_sha).
    let same_revoked_sha = h
        .call(
            &human(),
            "source_add",
            json!({
                "url": "https://github.com/example-org/agent-skills",
                "tracking_ref": "main",
                "pinned_sha": sha1,
            }),
        )
        .await
        .unwrap_err();
    assert!(matches!(same_revoked_sha, UaError::Conflict { .. }), "{same_revoked_sha:?}");

    // Re-allowing the same URL with a fresh pinned_sha creates a fresh row with a fresh approval.
    let (new_approval_id, readded) = h
        .gated(
            &human(),
            "source_add",
            json!({
                "url": "https://github.com/Example-Org/Agent-Skills",
                "tracking_ref": "main",
                "pinned_sha": sha2,
            }),
        )
        .await;
    assert_eq!(readded["idempotent"], false);
    assert_ne!(readded["source"]["id"], src_id);
    assert_eq!(readded["source"]["canonical_url"], "https://github.com/Example-Org/Agent-Skills");
    assert_eq!(readded["source"]["approval_id"], new_approval_id);

    let channels: Vec<String> = h
        .hub
        .db()
        .read(|c| {
            let mut stmt =
                c.prepare("SELECT channel FROM event_log WHERE channel LIKE 'skill.source_%' ORDER BY seq")?;
            Ok(stmt.query_map([], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?)
        })
        .unwrap();
    assert_eq!(channels, vec!["skill.source_added", "skill.source_revoked", "skill.source_added"]);
}

#[tokio::test]
async fn non_human_and_non_operator_callers_are_refused() {
    let h = Harness::new();
    h.add_org("org-b");
    let sha = "a".repeat(40);
    let add_params = json!({
        "url": "https://github.com/example/skills",
        "pinned_sha": sha,
    });

    let (_, added) = h.gated(&human(), "source_add", add_params).await;
    let src_id = added["source"]["id"].as_str().unwrap().to_string();
    let approvals_before = h.approval_count();

    let unauthorized = [
        caller("builder-1", ActorKind::Agent, Profile::Developer, ua_core::DEFAULT_ORG),
        caller("ops-bot", ActorKind::Agent, Profile::Coordinator, ua_core::DEFAULT_ORG),
        caller("operator", ActorKind::Agent, Profile::Coordinator, ua_core::DEFAULT_ORG),
        caller("", ActorKind::Anonymous, Profile::Coordinator, ua_core::DEFAULT_ORG),
        caller("system", ActorKind::System, Profile::Coordinator, ua_core::DEFAULT_ORG),
        caller("operator", ActorKind::Human, Profile::Coordinator, "org-b"),
    ];

    for who in &unauthorized {
        let e_add = h
            .call(who, "source_add", json!({ "url": "https://github.com/example/other", "pinned_sha": sha }))
            .await
            .unwrap_err();
        assert!(matches!(e_add, UaError::Denied { .. }), "{who:?} add: {e_add:?}");
        assert_ne!(e_add.reason_code(), Some("profile_denied"), "{who:?} add hit profile instead of authz");

        let e_rev = h.call(who, "source_revoke", json!({ "source_id": src_id })).await.unwrap_err();
        assert!(matches!(e_rev, UaError::Denied { .. }), "{who:?} revoke: {e_rev:?}");
        assert_ne!(
            e_rev.reason_code(),
            Some("profile_denied"),
            "{who:?} revoke hit profile instead of authz"
        );
    }

    assert_eq!(h.approval_count(), approvals_before, "unauthorized callers must never park approvals");
}

#[tokio::test]
async fn another_org_gets_not_found_and_isolated_list() {
    let h = Harness::new();
    h.add_org("org-b");
    let sha = "b".repeat(40);

    let (_, added_a) = h
        .gated(&human(), "source_add", json!({ "url": "https://github.com/org-a/skills", "pinned_sha": sha }))
        .await;
    let id_a = added_a["source"]["id"].as_str().unwrap().to_string();

    let id_b = "src-orgb000000000001";
    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO skill_sources (org_id, id, canonical_url, host, repo_path, allowed_subpaths, \
                 tracking_ref, pinned_sha, status, added_by, added_at, approval_id) \
                 VALUES ('org-b', ?1, 'https://github.com/org-b/skills', 'github.com', 'org-b/skills', '[]', \
                 'main', ?2, 'active', 'operator', '2026-01-01T00:00:00+00:00', NULL)",
                params![id_b, sha],
            )?;
            Ok(())
        })
        .unwrap();

    let org_b_dev = caller("builder-b", ActorKind::Agent, Profile::Developer, "org-b");
    let list_b = h.call(&org_b_dev, "source_list", json!({})).await.unwrap();
    let arr_b = list_b["sources"].as_array().unwrap();
    assert_eq!(arr_b.len(), 1, "{list_b}");
    assert_eq!(arr_b[0]["id"], id_b);

    let list_a = h.call(&human(), "source_list", json!({})).await.unwrap();
    let arr_a = list_a["sources"].as_array().unwrap();
    assert_eq!(arr_a.len(), 1, "{list_a}");
    assert_eq!(arr_a[0]["id"], id_a);

    let err = h.call(&human(), "source_revoke", json!({ "source_id": id_b })).await.unwrap_err();
    assert!(matches!(err, UaError::NotFound(_)), "{err:?}");

    let still_active: String = h
        .hub
        .db()
        .read(|c| Ok(c.query_row("SELECT status FROM skill_sources WHERE id = ?1", [id_b], |r| r.get(0))?))
        .unwrap();
    assert_eq!(still_active, "active");
}

#[tokio::test]
async fn every_refused_url_shape_and_unported_source_action_is_rejected() {
    let h = Harness::new();
    let sha = "c".repeat(40);
    let bad_urls = [
        "",
        "http://example.com/org/repo",
        "git://example.com/org/repo",
        "ssh://git@example.com/org/repo",
        "git@example.com:org/repo",
        "ext::sh -c id",
        "file:///tmp/repo",
        "https://user:pass@example.com/org/repo",
        "https://user@example.com/org/repo",
        "https://example.com/org/repo?token=x",
        "https://example.com/org/repo#main",
        "https://127.0.0.1/org/repo",
        "https://10.0.0.1/org/repo",
        "https://169.254.169.254/org/repo",
        "https://93.184.215.14/org/repo",
        "https://[::1]/org/repo",
        "https://localhost/org/repo",
        "https://metadata/latest/meta-data",
        "https://example.com:22/org/repo",
        "https://example.com:8443/org/repo",
        "https:///evil.com/org/repo",
        "https://example.com/.git",
        "-https://example.com/org/repo",
        "https://example.com/org/repo\n",
        "https://example.com/org/re\x00po",
        "https://example.com/org/repo with space",
        "https://example.com/",
        "https://example.com/org/../secret",
    ];
    for url in bad_urls {
        let e = h.call(&human(), "source_add", json!({ "url": url, "pinned_sha": sha })).await.unwrap_err();
        assert_eq!(e.code(), "invalid_argument", "{url:?}: {e:?}");
    }

    for bad_sha in ["main", "HEAD", "1234", &"A".repeat(40), &"g".repeat(40)] {
        let e = h
            .call(
                &human(),
                "source_add",
                json!({ "url": "https://github.com/example/skills", "pinned_sha": bad_sha }),
            )
            .await
            .unwrap_err();
        assert_eq!(e.code(), "invalid_argument", "{bad_sha:?}: {e:?}");
    }
    for bad_subpath in
        ["../escape", "skills/.git", "a:b", "skills/bidi\u{202E}name", "skills/csi\u{009B}name"]
    {
        let e = h
            .call(
                &human(),
                "source_add",
                json!({
                    "url": "https://github.com/example/skills",
                    "pinned_sha": sha,
                    "allowed_subpaths": [bad_subpath],
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(e.code(), "invalid_argument", "{bad_subpath:?}: {e:?}");
    }
    assert_eq!(h.approval_count(), 0, "invalid inputs must never park approvals");

    for action in ["source_unknown", "catalog", "install"] {
        let e = h.call(&human(), action, json!({})).await.unwrap_err();
        assert_eq!(e.code(), "invalid_argument", "{action}: {e:?}");
        assert!(e.to_string().contains("not ported"), "{action}: {e}");
    }
}

struct FakeResolver(Vec<IpAddr>);
impl DnsResolver for FakeResolver {
    fn resolve(&self, _host: &str, _port: u16) -> ua_core::UaResult<Vec<IpAddr>> {
        Ok(self.0.clone())
    }
}

#[test]
fn fetch_module_enforces_dns_pinning_exact_argv_and_scrubbed_env() {
    let parsed = validate_source_url("https://github.com/example/skills").unwrap();
    let cloud_meta = IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200));

    for bad_ips in [
        vec!["127.0.0.1".parse().unwrap()],
        vec!["10.0.0.5".parse().unwrap()],
        vec!["169.254.169.254".parse().unwrap()],
        vec![cloud_meta],
        vec!["::1".parse().unwrap()],
        vec!["93.184.215.14".parse().unwrap(), "192.168.1.1".parse().unwrap()],
    ] {
        let e = classify_and_pin_ip(&parsed.host, parsed.port, &FakeResolver(bad_ips.clone())).unwrap_err();
        assert_eq!(e.reason_code(), Some("ssrf_blocked"), "{bad_ips:?}: {e:?}");
    }

    let pinned =
        classify_and_pin_ip(&parsed.host, parsed.port, &FakeResolver(vec!["93.184.215.14".parse().unwrap()]))
            .unwrap();
    let spec = build_git_command_with_host_env(
        Some(Path::new("/cache/x.git")),
        Some(&parsed),
        Some(pinned),
        &["fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head"],
        &FetchOptions::production(),
        vec![
            ("PATH", "/usr/bin"),
            ("HOME", "/nonexistent/home"),
            ("HTTPS_PROXY", "http://proxy.internal:3128"),
            ("http_proxy", "http://proxy.internal:3128"),
            ("SSH_AUTH_SOCK", "/tmp/agent.sock"),
            ("GIT_ASKPASS", "/bin/true"),
            ("GITHUB_TOKEN", "secret"),
        ],
    )
    .unwrap();
    for flag in [
        "core.hooksPath=/dev/null",
        "core.fsmonitor=false",
        "submodule.recurse=false",
        "fetch.recurseSubmodules=false",
        "credential.interactive=never",
        "credential.helper=",
        "http.proxy=",
        "http.followRedirects=false",
        "http.lowSpeedLimit=1000",
        "http.lowSpeedTime=30",
        "http.sslVerify=true",
        "http.curloptResolve=github.com:443:93.184.215.14",
    ] {
        assert!(spec.args.contains(&flag.to_string()), "missing {flag}: {:?}", spec.args);
    }
    assert!(!spec.env.contains_key("HOME"));
    assert!(!spec.env.contains_key("HTTPS_PROXY"));
    assert!(!spec.env.contains_key("http_proxy"));
    assert!(!spec.env.contains_key("SSH_AUTH_SOCK"));
    assert!(!spec.env.contains_key("GIT_ASKPASS"));
    assert!(!spec.env.contains_key("GITHUB_TOKEN"));
    assert_eq!(spec.env.get("GIT_ALLOW_PROTOCOL").map(String::as_str), Some("https"));
    assert_eq!(spec.env.get("GIT_LFS_SKIP_SMUDGE").map(String::as_str), Some("1"));
}

/// Real subprocess test for `.env_clear()` in `run_git` (M2): re-executes this
/// test binary with a poisoned parent OS environment (`GIT_CONFIG_COUNT` /
/// `KEY_0` / `VALUE_0` setting `url.file:///x.insteadOf`, `GIT_CONFIG_PARAMETERS`,
/// `HTTPS_PROXY`, `SSH_AUTH_SOCK`, and `HOME` pointing at a poisoned `.gitconfig`)
/// and asserts real `git` executed through `run_git` observes none of it.
/// Deleting `.env_clear()` in `run_git` deterministically fails this test.
#[test]
fn real_git_subprocess_ignores_poisoned_process_env_and_home_gitconfig() {
    const INNER_FLAG: &str = "UA_SKILL_SOURCES_ENV_SCRUB_INNER";
    if std::env::var(INNER_FLAG).ok().as_deref() == Some("1") {
        let opts = FetchOptions::production();
        let spec =
            build_git_command(None, None, None, &["config", "--list", "--show-origin"], &opts).unwrap();
        let out = run_git(&spec, Duration::from_secs(10), 65_536).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(
            !text.contains("insteadOf") && !text.contains("poisoned"),
            "poisoned GIT_CONFIG_COUNT or HOME/.gitconfig leaked into git:\n{text}"
        );
        assert!(!text.contains("proxy.invalid"), "poisoned proxy leaked into git config:\n{text}");
        assert!(
            text.contains("core.hookspath=/dev/null"),
            "hardened core.hooksPath override missing:\n{text}"
        );
        #[cfg(unix)]
        {
            use ua_tools::families::skill_sources::fetch::GitCommandSpec;
            let env_spec = GitCommandSpec { program: "env".into(), args: vec![], env: spec.env.clone() };
            let env_out = run_git(&env_spec, Duration::from_secs(10), 65_536).unwrap();
            let env_text = String::from_utf8_lossy(&env_out);
            for forbidden in [
                "HTTPS_PROXY=",
                "HTTP_PROXY=",
                "SSH_AUTH_SOCK=",
                "GIT_ASKPASS=",
                "GIT_CONFIG_COUNT=",
                "GIT_CONFIG_PARAMETERS=",
                "HOME=",
            ] {
                assert!(
                    !env_text.lines().any(|line| line.starts_with(forbidden)),
                    "child env leaked {forbidden}:\n{env_text}"
                );
            }
        }
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let fake_home = tmp.path().join("home");
    std::fs::create_dir_all(&fake_home).unwrap();
    std::fs::write(
        fake_home.join(".gitconfig"),
        "[url \"file:///poisoned-home\"]\n\tinsteadOf = https://example.com/\n\
         [http]\n\tproxy = http://proxy.invalid:8080\n",
    )
    .unwrap();

    let exe = std::env::current_exe().unwrap();
    let out = Command::new(exe)
        .args([
            "--exact",
            "real_git_subprocess_ignores_poisoned_process_env_and_home_gitconfig",
            "--nocapture",
        ])
        .env(INNER_FLAG, "1")
        .env("HOME", &fake_home)
        .env("XDG_CONFIG_HOME", &fake_home)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "url.file:///poisoned-env.insteadOf")
        .env("GIT_CONFIG_VALUE_0", "https://github.com/")
        .env("GIT_CONFIG_PARAMETERS", "'http.proxy=http://proxy.invalid:9090'")
        .env("HTTPS_PROXY", "http://proxy.invalid:8080")
        .env("HTTP_PROXY", "http://proxy.invalid:8080")
        .env("SSH_AUTH_SOCK", "/tmp/poisoned.sock")
        .env("GIT_ASKPASS", "/bin/false")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "inner env-scrub subprocess failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(feature = "test-util")]
#[test]
fn local_file_fixture_integration_fetches_into_bare_cache() {
    use ua_tools::families::skill_sources::fetch::{fetch_exact_sha, validate_file_source_url_for_test};

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("upstream");
    std::fs::create_dir_all(&repo).unwrap();
    let run = |args: &[&str]| -> String {
        let out = Command::new("git")
            .current_dir(&repo)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    run(&["init", "-b", "main"]);
    std::fs::write(repo.join("SKILL.md"), "---\nname: demo\n---\nhi\n").unwrap();
    run(&["add", "."]);
    run(&["commit", "-m", "init"]);
    let sha = run(&["rev-parse", "HEAD"]);

    let file_url = validate_file_source_url_for_test(&format!("file://{}", repo.display())).unwrap();
    let data = tmp.path().join("hub-data");
    let fetched = fetch_exact_sha(
        &data,
        "default",
        &file_url,
        &sha,
        Some("main"),
        &FakeResolver(vec![]),
        &FetchOptions::for_local_file_test(),
    )
    .unwrap();
    assert_eq!(fetched.commit_sha, sha);
    assert!(fetched.cache_dir.join("HEAD").is_file());
    assert!(!fetched.cache_dir.join("SKILL.md").exists());
}

#[tokio::test]
async fn revoked_source_and_other_org_refuse_refresh_discover_and_import() {
    let h = Harness::new();
    h.add_org("org-b");
    let sha = "d".repeat(40);
    let (_, added) = h
        .gated(
            &human(),
            "source_add",
            json!({ "url": "https://github.com/example/skills", "pinned_sha": sha }),
        )
        .await;
    let src_id = added["source"]["id"].as_str().unwrap().to_string();

    // Another organization gets NotFound on refresh, discover, and import.
    let org_b_dev = caller("builder-b", ActorKind::Agent, Profile::Developer, "org-b");
    for (action, params) in [
        ("source_refresh", json!({ "source_id": src_id })),
        ("source_discover", json!({ "source_id": src_id })),
    ] {
        let e = h.call(&org_b_dev, action, params).await.unwrap_err();
        assert!(matches!(e, UaError::NotFound(_)), "other org {action}: {e:?}");
    }
    // Non-operator agent in default org is refused source_import (operator_required).
    let dev = caller("builder-1", ActorKind::Agent, Profile::Developer, ua_core::DEFAULT_ORG);
    let e = h
        .call(&dev, "source_import", json!({ "source_id": src_id, "path": "skills/demo" }))
        .await
        .unwrap_err();
    assert_eq!(e.reason_code(), Some("operator_required"), "{e:?}");

    // Another org's source_id answers NotFound to a default-org operator on all three actions.
    let id_b = "src-orgb-d2b-0001";
    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO skill_sources (org_id, id, canonical_url, host, repo_path, allowed_subpaths, \
                 tracking_ref, pinned_sha, status, added_by, added_at, approval_id) \
                 VALUES ('org-b', ?1, 'https://github.com/org-b/skills', 'github.com', 'org-b/skills', '[]', \
                 'main', ?2, 'active', 'operator', '2026-01-01T00:00:00+00:00', NULL)",
                params![id_b, sha],
            )?;
            Ok(())
        })
        .unwrap();
    for (action, params) in [
        ("source_refresh", json!({ "source_id": id_b })),
        ("source_discover", json!({ "source_id": id_b })),
        ("source_import", json!({ "source_id": id_b, "path": "skills/demo" })),
    ] {
        let e = h.call(&human(), action, params).await.unwrap_err();
        assert!(matches!(e, UaError::NotFound(_)), "cross-org {action}: {e:?}");
    }

    // Revoke the default-org source; refresh, discover, and import must all refuse with Conflict.
    h.gated(&human(), "source_revoke", json!({ "source_id": src_id, "reason": "compromised" })).await;
    for (action, params) in [
        ("source_refresh", json!({ "source_id": src_id })),
        ("source_discover", json!({ "source_id": src_id })),
        ("source_import", json!({ "source_id": src_id, "path": "skills/demo" })),
    ] {
        let e = h.call(&human(), action, params).await.unwrap_err();
        assert!(matches!(e, UaError::Conflict { .. }), "revoked {action}: {e:?}");
    }
}

#[cfg(feature = "test-util")]
mod d2b_file_fixtures {
    use super::*;
    use std::collections::BTreeMap;
    use ua_tools::families::skill_registry::{MAX_APPROVAL_TEXT_BYTES, MAX_PACKAGE_FILE_BYTES};
    use ua_tools::families::skill_sources::fetch::cache_dir;

    struct GitFixture {
        _tmp: tempfile::TempDir,
        repo: std::path::PathBuf,
    }

    impl GitFixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let repo = tmp.path().join("upstream");
            std::fs::create_dir_all(&repo).unwrap();
            let f = Self { _tmp: tmp, repo };
            f.git(&["init", "-b", "main"]);
            f
        }

        fn url(&self) -> String {
            format!("file://{}", self.repo.display())
        }

        fn write(&self, rel: &str, bytes: &[u8]) {
            let p = self.repo.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, bytes).unwrap();
        }

        fn remove(&self, rel: &str) {
            std::fs::remove_file(self.repo.join(rel)).unwrap();
        }

        fn git(&self, args: &[&str]) -> String {
            let out = Command::new("git")
                .current_dir(&self.repo)
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        fn commit_all(&self, msg: &str) -> String {
            self.git(&["add", "-A"]);
            self.git(&["commit", "-m", msg]);
            self.git(&["rev-parse", "HEAD"])
        }
    }

    fn insert_file_source(
        h: &Harness,
        org: &str,
        id: &str,
        fixture: &GitFixture,
        sha: &str,
        tracking_ref: &str,
        allowed_subpaths: &[&str],
    ) {
        let subpaths = serde_json::to_string(allowed_subpaths).unwrap();
        h.hub
            .db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO skill_sources (org_id, id, canonical_url, host, repo_path, allowed_subpaths, \
                     tracking_ref, pinned_sha, status, added_by, added_at, approval_id) \
                     VALUES (?1, ?2, ?3, '', ?4, ?5, ?6, ?7, 'active', 'operator', \
                     '2026-01-01T00:00:00+00:00', NULL)",
                    params![
                        org,
                        id,
                        fixture.url(),
                        fixture.repo.display().to_string(),
                        subpaths,
                        tracking_ref,
                        sha,
                    ],
                )?;
                Ok(())
            })
            .unwrap();
    }

    fn valid_skill_md(name: &str, extra: &str) -> String {
        format!(
            "---\nname: {name}\ndescription: Git-sourced skill helper. Use when asked to verify packages.\n---\n\n\
             # {name}\n\nRead [the guide](references/guide.md).\nFollow step one.\nFollow step two.\n{extra}"
        )
    }

    #[tokio::test]
    async fn discover_import_cache_isolation_refresh_and_upgrade_member_diff() {
        let h = Harness::new();
        let fx = GitFixture::new();

        // Populate v1 with executable script, reference, template, plus an out-of-subpath skill.
        fx.write("skills/demo/SKILL.md", valid_skill_md("demo", "Version 1 instructions.\n").as_bytes());
        fx.write("skills/demo/references/guide.md", b"# Guide v1\nCheck hashes.\n");
        fx.write("skills/demo/scripts/run.sh", b"#!/bin/sh\necho v1\n");
        fx.write("skills/demo/templates/old.txt", b"remove me in v2\n");
        fx.write("other/ignored/SKILL.md", valid_skill_md("ignored", "").as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                fx.repo.join("skills/demo/scripts/run.sh"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let sha1 = fx.commit_all("v1");
        insert_file_source(&h, ua_core::DEFAULT_ORG, "src-demo", &fx, &sha1, "main", &["skills"]);

        // Non-operator agent can discover and refresh allowlisted sources; outside allowed_subpaths is filtered.
        let dev = caller("builder-1", ActorKind::Agent, Profile::Developer, ua_core::DEFAULT_ORG);
        let disc = h.call(&dev, "source_discover", json!({ "source_id": "src-demo" })).await.unwrap();
        let pkgs = disc["packages"].as_array().unwrap();
        assert_eq!(pkgs.len(), 1, "{disc}");
        assert_eq!(pkgs[0]["path"], "skills/demo");
        assert_eq!(pkgs[0]["suggested_name"], "demo");
        assert_eq!(pkgs[0]["file_count"], 4);

        // Path outside allowed_subpaths is refused on source_import.
        let outside = h
            .call(&human(), "source_import", json!({ "source_id": "src-demo", "path": "other/ignored" }))
            .await
            .unwrap_err();
        assert_eq!(outside.reason_code(), Some("subpath_not_allowed"), "{outside:?}");

        // source_import stages into skill_publish_staging with git provenance and 0o644 modes.
        let staged_v1 = h
            .call(&human(), "source_import", json!({ "source_id": "src-demo", "path": "skills/demo" }))
            .await
            .unwrap();
        assert_eq!(staged_v1["status"], "approval_pending", "{staged_v1}");
        let expected_prov_v1 = format!("git:{}@{}:skills/demo", fx.url(), sha1);
        assert_eq!(staged_v1["source"], expected_prov_v1);
        let approval_v1 = staged_v1["approval_id"].as_i64().unwrap();
        let staging_v1 = staged_v1["staging_id"].as_str().unwrap().to_string();
        for f in staged_v1["package_manifest"]["files"].as_array().unwrap() {
            assert_eq!(f["mode"], 0o644, "100755 must be normalized to 0o644: {f}");
        }
        let payload_v1 = h.approval_payload(approval_v1);
        assert_eq!(payload_v1["source"], expected_prov_v1);
        assert_eq!(payload_v1["source_id"], "src-demo");
        assert_eq!(payload_v1["source_pinned_sha"], sha1);
        assert_eq!(payload_v1["new_sha"], sha1);
        assert_eq!(payload_v1["repo_path"], "skills/demo");

        // Delete the bare cache completely before approval & publish: bytes must come from staging only.
        let bare = cache_dir(&h.hub.cfg().home, ua_core::DEFAULT_ORG, &fx.url());
        assert!(bare.join("HEAD").is_file());
        std::fs::remove_dir_all(&bare).unwrap();
        assert!(!bare.exists());

        h.approve(approval_v1).await;
        let pub_v1 = h.call(&human(), "publish", json!({ "staging_id": staging_v1 })).await.unwrap();
        assert_eq!(pub_v1["ok"], true, "{pub_v1}");
        assert_eq!(pub_v1["skill"]["version"], 1);
        assert!(!bare.exists(), "publish must never re-read or recreate the git cache");

        // Verify persisted provenance on skill_versions.source.
        let stored_src: String = h
            .hub
            .db()
            .read(|c| {
                Ok(c.query_row(
                    "SELECT source FROM skill_versions WHERE name = 'demo' AND version = 1",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(stored_src, expected_prov_v1);

        // Allow direct SHA wants (as GitHub/GitLab do) so default import of approved
        // pinned_sha can be tested after upstream advances main.
        fx.git(&["config", "uploadpack.allowAnySHA1InWant", "true"]);

        // Upstream pushes v2 (including a line starting with `++` to verify lines_added counts it):
        // modifies SKILL.md & scripts/run.sh, removes templates/old.txt, adds templates/new.md,
        // leaves references/guide.md unchanged.
        fx.write(
            "skills/demo/SKILL.md",
            valid_skill_md("demo", "Version 2 instructions.\n++added-double-plus\n").as_bytes(),
        );
        fx.write("skills/demo/scripts/run.sh", b"#!/bin/sh\necho v2-updated\n");
        fx.remove("skills/demo/templates/old.txt");
        fx.write("skills/demo/templates/new.md", b"# Added in v2\n");
        let sha2 = fx.commit_all("v2");

        // Create a non-tracking branch `alt` at a third commit while `main` stays at sha2.
        fx.git(&["checkout", "-b", "alt"]);
        fx.write("skills/demo/SKILL.md", valid_skill_md("demo", "Alt branch commit.\n").as_bytes());
        let sha_alt = fx.commit_all("alt-branch");
        fx.git(&["checkout", "main"]);

        // source_refresh refuses a caller-supplied tracking_ref override (Low 1).
        let override_err = h
            .call(&dev, "source_refresh", json!({ "source_id": "src-demo", "tracking_ref": "alt" }))
            .await
            .unwrap_err();
        assert_eq!(override_err.code(), "invalid_argument", "{override_err:?}");

        // source_refresh uses the row's tracking_ref only and never moves pinned_sha, versions, or assignments.
        let ref_out = h.call(&dev, "source_refresh", json!({ "source_id": "src-demo" })).await.unwrap();
        assert_eq!(ref_out["changed"], true, "{ref_out}");
        assert_eq!(ref_out["pinned_sha"], sha1);
        assert_eq!(ref_out["candidate_sha"], sha2);
        let pinned_after: String = h
            .hub
            .db()
            .read(|c| {
                Ok(c.query_row("SELECT pinned_sha FROM skill_sources WHERE id = 'src-demo'", [], |r| {
                    r.get(0)
                })?)
            })
            .unwrap();
        assert_eq!(pinned_after, sha1, "source_refresh must never move pinned_sha");
        let version_count: i64 = h
            .hub
            .db()
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM skill_versions", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(version_count, 1, "source_refresh must never create versions");
        let assign_count: i64 = h
            .hub
            .db()
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM skill_assignments", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(assign_count, 0, "source_refresh must never assign");

        // M4: omitting `sha` still imports/discovers the exact approved `pinned_sha` even after main moved to sha2.
        let pin_disc = h.call(&dev, "source_discover", json!({ "source_id": "src-demo" })).await.unwrap();
        assert_eq!(pin_disc["sha"], sha1, "{pin_disc}");
        let pin_reimport = h
            .call(&human(), "source_import", json!({ "source_id": "src-demo", "path": "skills/demo" }))
            .await
            .unwrap();
        assert_eq!(
            pin_reimport["idempotent"], true,
            "default import must stay on pinned_sha: {pin_reimport}"
        );

        // M4: an explicit `sha` on a non-tracking branch (`alt`) is refused (tracking_ref mismatch).
        let mismatch_disc = h
            .call(&dev, "source_discover", json!({ "source_id": "src-demo", "sha": sha_alt }))
            .await
            .unwrap_err();
        assert!(matches!(mismatch_disc, UaError::Conflict { .. }), "{mismatch_disc:?}");
        assert!(mismatch_disc.to_string().contains("does not match pinned_sha"), "{mismatch_disc}");

        let mismatch_imp = h
            .call(
                &human(),
                "source_import",
                json!({ "source_id": "src-demo", "path": "skills/demo", "sha": sha_alt }),
            )
            .await
            .unwrap_err();
        assert!(matches!(mismatch_imp, UaError::Conflict { .. }), "{mismatch_imp:?}");

        // Explicit upgrade import at sha2 (current tracking_ref tip) succeeds and populates
        // member_diff, SKILL.md diff, source_id, source_pinned_sha, and `pinned_sha → new_sha` display.
        let staged_v2 = h
            .call(
                &human(),
                "source_import",
                json!({ "source_id": "src-demo", "path": "skills/demo", "sha": sha2 }),
            )
            .await
            .unwrap();
        assert_eq!(staged_v2["status"], "approval_pending", "{staged_v2}");
        assert_eq!(staged_v2["previous_version"], 1);
        assert_eq!(staged_v2["source_id"], "src-demo");
        let approval_v2 = staged_v2["approval_id"].as_i64().unwrap();
        let staging_v2 = staged_v2["staging_id"].as_str().unwrap().to_string();

        let payload_v2 = h.approval_payload(approval_v2);
        assert_eq!(payload_v2["source_id"], "src-demo");
        assert_eq!(payload_v2["source_pinned_sha"], sha1);
        assert_eq!(payload_v2["previous_version"], 1);
        assert_eq!(payload_v2["previous_sha"], sha1);
        assert_eq!(payload_v2["new_sha"], sha2);
        assert_eq!(payload_v2["previous_source"], expected_prov_v1);
        assert_eq!(payload_v2["source_changed"], false);
        let diff = &payload_v2["member_diff"];
        assert_eq!(diff["added"].as_array().unwrap().len(), 1, "{diff}");
        assert_eq!(diff["added"][0]["path"], "templates/new.md");
        assert!(diff["added"][0]["new_sha256"].as_str().unwrap().len() == 64);
        assert_eq!(diff["removed"].as_array().unwrap().len(), 1, "{diff}");
        assert_eq!(diff["removed"][0]["path"], "templates/old.txt");
        assert!(diff["removed"][0]["old_sha256"].as_str().unwrap().len() == 64);
        let modified: BTreeMap<&str, &Value> =
            diff["modified"].as_array().unwrap().iter().map(|m| (m["path"].as_str().unwrap(), m)).collect();
        assert!(modified.contains_key("SKILL.md"), "{diff}");
        assert!(modified.contains_key("scripts/run.sh"), "{diff}");
        assert_eq!(diff["unchanged"].as_array().unwrap().len(), 1, "{diff}");
        assert_eq!(diff["unchanged"][0]["path"], "references/guide.md");
        let md_diff = payload_v2["skill_md_diff"].as_str().unwrap();
        assert!(md_diff.contains("-Version 1 instructions."), "{md_diff}");
        assert!(md_diff.contains("+Version 2 instructions."), "{md_diff}");
        assert!(md_diff.contains("+++added-double-plus"), "{md_diff}");

        // approval_pending returns display.diff with pin advance, previous_source, member diff,
        // SKILL.md unified diff, and accurate lines_added (including `++` line).
        let pending = h
            .reg
            .call(&h.hub, &approver(), "approval_pending", json!({ "tool": "skill_registry" }))
            .await
            .unwrap();
        let row = pending["pending"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == approval_v2)
            .expect("pending v2 approval");
        assert_eq!(row["display"]["lines_added"], 2, "must count added line starting with ++: {row}");
        assert_eq!(row["display"]["lines_removed"], 1, "{row}");
        assert_eq!(row["display"]["source_changed"], false, "{row}");
        let display_diff = row["display"]["diff"].as_str().unwrap();
        assert!(
            display_diff.contains(&format!("{sha1} \u{2192} {sha2}")),
            "display must show pinned_sha → new_sha:\n{display_diff}"
        );
        assert!(display_diff.contains(&format!("Previous source: {expected_prov_v1}")), "{display_diff}");
        assert!(display_diff.contains("+ templates/new.md"), "{display_diff}");
        assert!(display_diff.contains("- templates/old.txt"), "{display_diff}");
        assert!(display_diff.contains("~ scripts/run.sh"), "{display_diff}");
        assert!(display_diff.contains("references/guide.md (unchanged"), "{display_diff}");
        assert!(display_diff.contains("+Version 2 instructions."), "{display_diff}");

        // Delete remote repo AND bare cache before publishing v2 to prove zero cache/remote re-read.
        std::fs::remove_dir_all(&fx.repo).unwrap();
        std::fs::remove_dir_all(&bare).unwrap();

        h.approve(approval_v2).await;
        let pub_v2 = h.call(&human(), "publish", json!({ "staging_id": staging_v2 })).await.unwrap();
        assert_eq!(pub_v2["ok"], true, "{pub_v2}");
        assert_eq!(pub_v2["skill"]["version"], 2);
    }

    #[tokio::test]
    async fn symlink_gitlink_oversize_and_hidden_unicode_are_refused() {
        let h = Harness::new();

        // 1. Symlink (mode 120000) refused in both source_discover and source_import.
        #[cfg(unix)]
        {
            let fx = GitFixture::new();
            fx.write("skills/sym/SKILL.md", valid_skill_md("sym", "").as_bytes());
            fx.write("skills/sym/references/guide.md", b"# Guide\n");
            std::os::unix::fs::symlink("/etc/passwd", fx.repo.join("skills/sym/leak")).unwrap();
            let sha = fx.commit_all("symlink");
            insert_file_source(&h, ua_core::DEFAULT_ORG, "src-sym", &fx, &sha, "main", &["skills"]);

            let e_disc =
                h.call(&human(), "source_discover", json!({ "source_id": "src-sym" })).await.unwrap_err();
            assert_eq!(e_disc.code(), "invalid_argument", "{e_disc:?}");
            assert!(e_disc.to_string().contains("symlink"), "{e_disc}");

            let e_imp = h
                .call(&human(), "source_import", json!({ "source_id": "src-sym", "path": "skills/sym" }))
                .await
                .unwrap_err();
            assert_eq!(e_imp.code(), "invalid_argument", "{e_imp:?}");
            assert!(e_imp.to_string().contains("symlink"), "{e_imp}");
        }

        // 2. Gitlink / submodule (mode 160000) refused in both source_discover and source_import.
        {
            let fx = GitFixture::new();
            fx.write("skills/sub/SKILL.md", valid_skill_md("sub", "").as_bytes());
            fx.write("skills/sub/references/guide.md", b"# Guide\n");
            fx.git(&["add", "-A"]);
            let fake_commit = "a".repeat(40);
            fx.git(&[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{fake_commit},skills/sub/mod"),
            ]);
            fx.git(&["commit", "-m", "gitlink"]);
            let sha = fx.git(&["rev-parse", "HEAD"]);
            insert_file_source(&h, ua_core::DEFAULT_ORG, "src-sub", &fx, &sha, "main", &["skills"]);

            let e_disc =
                h.call(&human(), "source_discover", json!({ "source_id": "src-sub" })).await.unwrap_err();
            assert_eq!(e_disc.code(), "invalid_argument", "{e_disc:?}");
            assert!(e_disc.to_string().contains("gitlink"), "{e_disc}");

            let e_imp = h
                .call(&human(), "source_import", json!({ "source_id": "src-sub", "path": "skills/sub" }))
                .await
                .unwrap_err();
            assert_eq!(e_imp.code(), "invalid_argument", "{e_imp:?}");
            assert!(e_imp.to_string().contains("gitlink"), "{e_imp}");
        }

        // 3. Oversized supporting member (> 512 KiB) and approval text cap (> 256 KiB) refused.
        {
            let fx = GitFixture::new();
            fx.write("skills/big/SKILL.md", valid_skill_md("big", "").as_bytes());
            fx.write("skills/big/references/guide.md", b"# Guide\n");
            fx.write("skills/big/references/huge.txt", &vec![b'x'; MAX_PACKAGE_FILE_BYTES + 1]);
            let sha = fx.commit_all("too-big");
            insert_file_source(&h, ua_core::DEFAULT_ORG, "src-big", &fx, &sha, "main", &["skills"]);

            let e = h
                .call(&human(), "source_import", json!({ "source_id": "src-big", "path": "skills/big" }))
                .await
                .unwrap_err();
            assert_eq!(e.code(), "invalid_argument", "{e:?}");
            assert!(
                e.to_string().contains(&format!("exceeds the {MAX_PACKAGE_FILE_BYTES}-byte limit")),
                "must fail at pre-read declared-size cap, not post-read git overflow: {e}"
            );

            let fx_cap = GitFixture::new();
            fx_cap.write("skills/cap/SKILL.md", valid_skill_md("cap", "").as_bytes());
            fx_cap.write("skills/cap/references/guide.md", &vec![b'a'; MAX_APPROVAL_TEXT_BYTES + 1]);
            let sha_cap = fx_cap.commit_all("over-256k-text");
            insert_file_source(&h, ua_core::DEFAULT_ORG, "src-cap", &fx_cap, &sha_cap, "main", &["skills"]);

            let e_cap = h
                .call(&human(), "source_import", json!({ "source_id": "src-cap", "path": "skills/cap" }))
                .await
                .unwrap_err();
            assert_eq!(e_cap.code(), "invalid_argument", "{e_cap:?}");
            assert!(e_cap.to_string().contains("approval review limit"), "{e_cap}");
        }

        // 4. Hidden Unicode in a supporting member (and inside an allowlisted .png binary) is blocked.
        {
            let fx = GitFixture::new();
            fx.write("skills/hid/SKILL.md", valid_skill_md("hid", "").as_bytes());
            fx.write("skills/hid/references/guide.md", "ok\u{200B}hidden\n".as_bytes());
            let sha = fx.commit_all("hidden-unicode");
            insert_file_source(&h, ua_core::DEFAULT_ORG, "src-hid", &fx, &sha, "main", &["skills"]);

            let out = h
                .call(&human(), "source_import", json!({ "source_id": "src-hid", "path": "skills/hid" }))
                .await
                .unwrap();
            assert_eq!(out["ok"], false, "{out}");
            assert_eq!(out["blocked"], true, "{out}");
            assert_eq!(out["review"]["status"], "fail", "{out}");
            assert!(
                out["review"]["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|f| f["rule"] == "SKILL-HIDDEN-TEXT"),
                "{out}"
            );

            // Hidden Unicode stuffed inside an allowlisted .png binary is caught by lossy UTF-8 scan.
            let fx_png = GitFixture::new();
            fx_png.write("skills/hidpng/SKILL.md", valid_skill_md("hidpng", "").as_bytes());
            fx_png.write("skills/hidpng/references/guide.md", b"# Clean guide\n");
            let mut png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec();
            png.extend_from_slice("\u{202E}bidi".as_bytes());
            fx_png.write("skills/hidpng/assets/icon.png", &png);
            let sha_png = fx_png.commit_all("hidden-in-png");
            insert_file_source(
                &h,
                ua_core::DEFAULT_ORG,
                "src-hidpng",
                &fx_png,
                &sha_png,
                "main",
                &["skills"],
            );

            let out_png = h
                .call(
                    &human(),
                    "source_import",
                    json!({ "source_id": "src-hidpng", "path": "skills/hidpng" }),
                )
                .await
                .unwrap();
            assert_eq!(out_png["blocked"], true, "{out_png}");
            assert_eq!(out_png["review"]["status"], "fail", "{out_png}");
        }

        // 5. Non-allowlisted binary (.txt with NUL) is refused; clean allowlisted .png emits SKILL-BINARY-ASSET.
        {
            let fx = GitFixture::new();
            fx.write("skills/bin/SKILL.md", valid_skill_md("bin", "").as_bytes());
            fx.write("skills/bin/references/guide.md", b"# Guide\n");
            fx.write("skills/bin/references/sneaky.txt", b"hello\x00world");
            let sha = fx.commit_all("nul-txt");
            insert_file_source(&h, ua_core::DEFAULT_ORG, "src-bin", &fx, &sha, "main", &["skills"]);

            let e = h
                .call(&human(), "source_import", json!({ "source_id": "src-bin", "path": "skills/bin" }))
                .await
                .unwrap_err();
            assert_eq!(e.code(), "invalid_argument", "{e:?}");
            assert!(e.to_string().contains("allowlisted binary assets"), "{e}");

            let fx_ok = GitFixture::new();
            fx_ok.write("skills/pngok/SKILL.md", valid_skill_md("pngok", "").as_bytes());
            fx_ok.write("skills/pngok/references/guide.md", b"# Guide\n");
            fx_ok.write("skills/pngok/assets/logo.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\x00IEND");
            let sha_ok = fx_ok.commit_all("clean-png");
            insert_file_source(&h, ua_core::DEFAULT_ORG, "src-pngok", &fx_ok, &sha_ok, "main", &["skills"]);

            let staged = h
                .call(&human(), "source_import", json!({ "source_id": "src-pngok", "path": "skills/pngok" }))
                .await
                .unwrap();
            assert_eq!(staged["status"], "approval_pending", "{staged}");
            assert!(
                staged["review"]["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|f| f["rule"] == "SKILL-BINARY-ASSET" && f["path"] == "assets/logo.png"),
                "{staged}"
            );
        }

        assert_eq!(h.approval_count(), 1, "only the clean allowlisted-png import may park an approval");
    }

    #[tokio::test]
    async fn revoke_between_stage_and_publish_source_change_warning_nested_and_controls() {
        let h = Harness::new();

        // M1: Revoke between stage and publish must refuse publishing the already-staged import.
        {
            let fx = GitFixture::new();
            fx.write("skills/revoked-mid/SKILL.md", valid_skill_md("revoked-mid", "").as_bytes());
            fx.write("skills/revoked-mid/references/guide.md", b"# Guide\n");
            let sha = fx.commit_all("v1");
            insert_file_source(&h, ua_core::DEFAULT_ORG, "src-rev-mid", &fx, &sha, "main", &["skills"]);

            let staged = h
                .call(
                    &human(),
                    "source_import",
                    json!({ "source_id": "src-rev-mid", "path": "skills/revoked-mid" }),
                )
                .await
                .unwrap();
            let approval_id = staged["approval_id"].as_i64().unwrap();
            let staging_id = staged["staging_id"].as_str().unwrap().to_string();

            // Revoke the source BEFORE publish, even though a human approves the parked publish.
            h.gated(
                &human(),
                "source_revoke",
                json!({ "source_id": "src-rev-mid", "reason": "compromised after staging" }),
            )
            .await;
            h.approve(approval_id).await;

            let err = h.call(&human(), "publish", json!({ "staging_id": staging_id })).await.unwrap_err();
            assert!(matches!(err, UaError::Conflict { .. }), "{err:?}");
            assert!(err.to_string().contains("revoked"), "{err}");

            let versions: i64 = h
                .hub
                .db()
                .read(|c| {
                    Ok(c.query_row(
                        "SELECT COUNT(*) FROM skill_versions WHERE name = 'revoked-mid'",
                        [],
                        |r| r.get(0),
                    )?)
                })
                .unwrap();
            assert_eq!(versions, 0, "revoked source must not produce a published skill version");
        }

        // M3: Another repository claiming an existing skill name flags WARNING: SOURCE CHANGED
        // and shows previous_source prominently in approval_display.
        {
            let fx_a = GitFixture::new();
            fx_a.write("skills/shared-name/SKILL.md", valid_skill_md("shared-name", "From A.\n").as_bytes());
            fx_a.write("skills/shared-name/references/guide.md", b"# Guide A\n");
            let sha_a = fx_a.commit_all("a1");
            insert_file_source(&h, ua_core::DEFAULT_ORG, "src-a", &fx_a, &sha_a, "main", &["skills"]);

            let st_a = h
                .call(
                    &human(),
                    "source_import",
                    json!({ "source_id": "src-a", "path": "skills/shared-name" }),
                )
                .await
                .unwrap();
            h.approve(st_a["approval_id"].as_i64().unwrap()).await;
            h.call(&human(), "publish", json!({ "staging_id": st_a["staging_id"] })).await.unwrap();

            let fx_b = GitFixture::new();
            fx_b.write("skills/shared-name/SKILL.md", valid_skill_md("shared-name", "From B.\n").as_bytes());
            fx_b.write("skills/shared-name/references/guide.md", b"# Guide B\n");
            let sha_b = fx_b.commit_all("b1");
            insert_file_source(&h, ua_core::DEFAULT_ORG, "src-b", &fx_b, &sha_b, "main", &["skills"]);

            let st_b = h
                .call(
                    &human(),
                    "source_import",
                    json!({ "source_id": "src-b", "path": "skills/shared-name" }),
                )
                .await
                .unwrap();
            let app_b = st_b["approval_id"].as_i64().unwrap();
            let payload_b = h.approval_payload(app_b);
            assert_eq!(payload_b["source_changed"], true, "{payload_b}");
            let expected_prev = format!("git:{}@{}:skills/shared-name", fx_a.url(), sha_a);
            assert_eq!(payload_b["previous_source"], expected_prev);

            let pending = h
                .reg
                .call(&h.hub, &approver(), "approval_pending", json!({ "tool": "skill_registry" }))
                .await
                .unwrap();
            let row = pending["pending"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == app_b)
                .expect("pending source-change approval");
            assert_eq!(row["display"]["source_changed"], true, "{row}");
            let diff = row["display"]["diff"].as_str().unwrap();
            assert!(diff.contains("WARNING: SOURCE CHANGED"), "{diff}");
            assert!(diff.contains(&format!("Previous source: {expected_prev}")), "{diff}");
            assert!(
                diff.contains(&format!("Source: git:{}@{}:skills/shared-name", fx_b.url(), sha_b)),
                "{diff}"
            );
        }

        // M2: C1 control (U+009B) and bidi override (U+202E) in a member path are refused on both discover and import.
        for (id, bad_name) in [
            ("src-c1", "skills/badpath/run\u{009B}csi.txt"),
            ("src-bidi", "skills/badpath/run\u{202E}txt.sh"),
        ] {
            let fx = GitFixture::new();
            fx.write("skills/badpath/SKILL.md", valid_skill_md("badpath", "").as_bytes());
            fx.write("skills/badpath/references/guide.md", b"# Guide\n");
            fx.write(bad_name, b"echo ok\n");
            let sha = fx.commit_all("bad-path");
            insert_file_source(&h, ua_core::DEFAULT_ORG, id, &fx, &sha, "main", &["skills"]);

            let e_disc = h.call(&human(), "source_discover", json!({ "source_id": id })).await.unwrap_err();
            assert_eq!(e_disc.code(), "invalid_argument", "{id} discover: {e_disc:?}");
            let e_imp = h
                .call(&human(), "source_import", json!({ "source_id": id, "path": "skills/badpath" }))
                .await
                .unwrap_err();
            assert_eq!(e_imp.code(), "invalid_argument", "{id} import: {e_imp:?}");
        }

        // Mutation 1 + Nit 2: Nested SKILL.md (and case-insensitive skill.md) refused on source_import.
        for (id, nested_rel) in [
            ("src-nested-upper", "skills/outer/inner/SKILL.md"),
            ("src-nested-lower", "skills/outer/inner/skill.md"),
        ] {
            let fx = GitFixture::new();
            fx.write("skills/outer/SKILL.md", valid_skill_md("outer", "").as_bytes());
            fx.write("skills/outer/references/guide.md", b"# Guide\n");
            fx.write(nested_rel, valid_skill_md("inner", "").as_bytes());
            let sha = fx.commit_all("nested");
            insert_file_source(&h, ua_core::DEFAULT_ORG, id, &fx, &sha, "main", &["skills"]);

            let e = h
                .call(&human(), "source_import", json!({ "source_id": id, "path": "skills/outer" }))
                .await
                .unwrap_err();
            assert_eq!(e.code(), "invalid_argument", "{id}: {e:?}");
            assert!(e.to_string().contains("nested"), "{id}: {e}");
        }

        // Low 2: ESC (\x1b) and CR (\r) in SKILL.md are blocked by skill_review.
        for (id, payload) in [("src-esc", "Escape \x1b[31mred\x1b[0m\n"), ("src-cr", "Fake\roverwrite\n")] {
            let fx = GitFixture::new();
            fx.write("skills/ctrl/SKILL.md", valid_skill_md("ctrl", payload).as_bytes());
            fx.write("skills/ctrl/references/guide.md", b"# Guide\n");
            let sha = fx.commit_all("ctrl");
            insert_file_source(&h, ua_core::DEFAULT_ORG, id, &fx, &sha, "main", &["skills"]);

            let out = h
                .call(&human(), "source_import", json!({ "source_id": id, "path": "skills/ctrl" }))
                .await
                .unwrap();
            assert_eq!(out["blocked"], true, "{id}: {out}");
            assert_eq!(out["review"]["status"], "fail", "{id}: {out}");
        }

        // Low 3: Leading-dot repo prefix `.claude/skills` and deeper layouts work end-to-end.
        {
            let fx = GitFixture::new();
            let deep_dir = ".claude/skills/team/platform/a/b/c/d/e/dot-skill";
            fx.write(&format!("{deep_dir}/SKILL.md"), valid_skill_md("dot-skill", "").as_bytes());
            fx.write(&format!("{deep_dir}/references/guide.md"), b"# Guide\n");
            let sha = fx.commit_all("dot-claude");
            insert_file_source(
                &h,
                ua_core::DEFAULT_ORG,
                "src-claude",
                &fx,
                &sha,
                "main",
                &[".claude/skills"],
            );

            let disc =
                h.call(&human(), "source_discover", json!({ "source_id": "src-claude" })).await.unwrap();
            let pkgs = disc["packages"].as_array().unwrap();
            assert_eq!(pkgs.len(), 1, "{disc}");
            assert_eq!(pkgs[0]["path"], deep_dir);

            let staged = h
                .call(&human(), "source_import", json!({ "source_id": "src-claude", "path": deep_dir }))
                .await
                .unwrap();
            assert_eq!(staged["status"], "approval_pending", "{staged}");
            assert_eq!(staged["name"], "dot-skill");
        }
    }
}
