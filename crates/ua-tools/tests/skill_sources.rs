//! Org-scoped Git skill source allowlist and hardened fetch tests (slice D2a).
//!
//! Exercises `source_add`, `source_revoke`, and `source_list` through
//! `builtin_registry().call(..)` as well as URL validation, DNS-pinning / SSRF
//! refusals, exact git `-c` argv and scrubbed env, and local `file://` bare
//! cache fetching behind the test-only flag. Runs completely offline.

use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use rusqlite::params;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::families::skill_sources::fetch::{
    DnsResolver, FetchOptions, build_git_command_with_host_env, classify_and_pin_ip, fetch_exact_sha,
    validate_source_url,
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

    // Add source: parks a one-time human approval bound to all §1 fields.
    let add_params = json!({
        "url": "https://GitHub.com/Example-Org/Agent-Skills/",
        "tracking_ref": "main",
        "pinned_sha": sha1,
        "allowed_subpaths": ["skills/ops/", "skills/core"],
    });
    let (approval_id, added) = h.gated(&human(), "source_add", add_params.clone()).await;
    assert_eq!(added["ok"], true, "{added}");
    assert_eq!(added["idempotent"], false, "{added}");
    let src = &added["source"];
    let src_id = src["id"].as_str().unwrap().to_string();
    assert_eq!(src["canonical_url"], "https://github.com/Example-Org/Agent-Skills");
    assert_eq!(src["host"], "github.com");
    assert_eq!(src["repo_path"], "Example-Org/Agent-Skills");
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
            "canonical_url": "https://github.com/Example-Org/Agent-Skills",
            "tracking_ref": "main",
            "pinned_sha": sha1,
            "allowed_subpaths": ["skills/core", "skills/ops"],
        })
    );

    // Re-adding identical active source is idempotent (no new approval, no new row).
    let again = h.call(&human(), "source_add", add_params).await.unwrap();
    assert_eq!(again["idempotent"], true, "{again}");
    assert_eq!(again["source"]["id"], src_id);

    // Adding a different pin for the same active URL is refused (conflict).
    let conflict = h
        .call(
            &human(),
            "source_add",
            json!({
                "url": "https://github.com/Example-Org/Agent-Skills",
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
    assert_eq!(rev_bound["canonical_url"], "https://github.com/Example-Org/Agent-Skills");

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

    // Revocation is terminal: revoking again fails with Conflict.
    let rev_again = h.call(&human(), "source_revoke", rev_params).await.unwrap_err();
    assert!(matches!(rev_again, UaError::Conflict { .. }), "{rev_again:?}");

    // Re-allowing the same URL after revocation creates a fresh row with a fresh approval.
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
    assert_eq!(readded["source"]["approval_id"], new_approval_id);

    // Ledger recorded both skill.source_added and skill.source_revoked events.
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

    // Seed one active source as a real human operator so we can test revoke refusals too.
    let (_, added) = h.gated(&human(), "source_add", add_params.clone()).await;
    let src_id = added["source"]["id"].as_str().unwrap().to_string();
    let approvals_before = h.approval_count();

    let unauthorized = [
        // Regular developer agent.
        caller("builder-1", ActorKind::Agent, Profile::Developer, ua_core::DEFAULT_ORG),
        // Lifecycle operator agent (explicitly NOT a human operator).
        caller("ops-bot", ActorKind::Agent, Profile::Coordinator, ua_core::DEFAULT_ORG),
        // Unattended agent running under a human identity's label.
        caller("operator", ActorKind::Agent, Profile::Coordinator, ua_core::DEFAULT_ORG),
        // Anonymous caller.
        caller("", ActorKind::Anonymous, Profile::Coordinator, ua_core::DEFAULT_ORG),
        // System caller.
        caller("system", ActorKind::System, Profile::Coordinator, ua_core::DEFAULT_ORG),
        // Human caller outside the default organization (no Operator grant yet).
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

    // Default org adds a source through the normal tool path.
    let (_, added_a) = h
        .gated(&human(), "source_add", json!({ "url": "https://github.com/org-a/skills", "pinned_sha": sha }))
        .await;
    let id_a = added_a["source"]["id"].as_str().unwrap().to_string();

    // Seed an org-b source directly in SQL (non-default org human operator memberships land in org.v2).
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

    // org-b sees only org-b's source; default sees only default's source.
    let org_b_dev = caller("builder-b", ActorKind::Agent, Profile::Developer, "org-b");
    let list_b = h.call(&org_b_dev, "source_list", json!({})).await.unwrap();
    let arr_b = list_b["sources"].as_array().unwrap();
    assert_eq!(arr_b.len(), 1, "{list_b}");
    assert_eq!(arr_b[0]["id"], id_b);

    let list_a = h.call(&human(), "source_list", json!({})).await.unwrap();
    let arr_a = list_a["sources"].as_array().unwrap();
    assert_eq!(arr_a.len(), 1, "{list_a}");
    assert_eq!(arr_a[0]["id"], id_a);

    // Default operator trying to revoke org-b's source gets NotFound (never leaks existence).
    let err = h.call(&human(), "source_revoke", json!({ "source_id": id_b })).await.unwrap_err();
    assert!(matches!(err, UaError::NotFound(_)), "{err:?}");

    // Confirm org-b's source is untouched.
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

    // Invalid pinned_sha, tracking_ref, and allowed_subpaths are refused.
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
    for bad_subpath in ["../escape", ".hidden", "skills/.git", "a:b"] {
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

    // D2b actions remain refused in D2a.
    for action in ["source_discover", "source_refresh", "source_import"] {
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
fn fetch_module_enforces_dns_pinning_exact_argv_scrubbed_env_and_file_fixture() {
    let parsed = validate_source_url("https://github.com/example/skills", false).unwrap();

    // Private, loopback, cloud metadata, and mixed DNS results are all refused.
    for bad_ips in [
        vec!["127.0.0.1".parse().unwrap()],
        vec!["10.0.0.5".parse().unwrap()],
        vec!["169.254.169.254".parse().unwrap()],
        vec!["100.100.100.200".parse().unwrap()],
        vec!["::1".parse().unwrap()],
        vec!["93.184.215.14".parse().unwrap(), "192.168.1.1".parse().unwrap()],
    ] {
        let e = classify_and_pin_ip(&parsed.host, parsed.port, &FakeResolver(bad_ips.clone())).unwrap_err();
        assert_eq!(e.reason_code(), Some("ssrf_blocked"), "{bad_ips:?}: {e:?}");
    }

    // Public IP is pinned into http.curloptResolve alongside every §3 override and scrubbed env.
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
        "http.sslVerify=true",
        "http.curloptResolve=github.com:443:93.184.215.14",
    ] {
        assert!(spec.args.contains(&flag.to_string()), "missing {flag}: {:?}", spec.args);
    }
    assert!(!spec.env.contains_key("HTTPS_PROXY"));
    assert!(!spec.env.contains_key("http_proxy"));
    assert!(!spec.env.contains_key("SSH_AUTH_SOCK"));
    assert!(!spec.env.contains_key("GIT_ASKPASS"));
    assert!(!spec.env.contains_key("GITHUB_TOKEN"));
    assert_eq!(spec.env.get("GIT_ALLOW_PROTOCOL").map(String::as_str), Some("https"));
    assert_eq!(spec.env.get("GIT_LFS_SKIP_SMUDGE").map(String::as_str), Some("1"));

    // End-to-end local file:// bare fetch behind the explicit test-only flag.
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

    let file_url = validate_source_url(&format!("file://{}", repo.display()), true).unwrap();
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
