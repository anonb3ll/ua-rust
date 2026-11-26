//! Version yanking and catalog install tests (hub task #2714, slice D2c;
//! `docs/skill-sources.md` §4 & §6).
//!
//! Exercises `skill_registry { action: "yank" }` and `skill_registry { action: "install" }`
//! through `builtin_registry().call(..)`: human-operator enforcement, permanent
//! `skill_version_yanks` storage and `skill.yanked` ledger events, every yank
//! effect (`assign`, `install`, `get`, `resolve`, `node_config`, re-publish,
//! re-import), catalog install attestation and `expected_hash` checks, `0o644`
//! / `O_NOFOLLOW` writes, symlink and out-of-root refusals, atomic overwrite,
//! and cross-organization `not_found` isolation. Runs completely offline.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rusqlite::params;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::families::harness_config::render::{content_hash, py_dumps};
use ua_tools::families::skill_registry::PACKAGE_SCHEMA_VERSION;
use ua_tools::{Hub, Registry, builtin_registry};

const NODE: &str = "node-d2c-1";

struct Harness {
    _home: tempfile::TempDir,
    _ws: tempfile::TempDir,
    hub: Hub,
    reg: Registry,
}

impl Harness {
    fn new() -> Self {
        Self::with_cfg(|_| {})
    }

    fn with_cfg(f: impl FnOnce(&mut Config)) -> Self {
        let home = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(home.path());
        cfg.human_identities = vec!["operator".into(), "reviewer".into()];
        cfg.lifecycle_operators = Some(vec!["ops-bot".into()]);
        cfg.workspace = Some(ws.path().to_path_buf());
        f(&mut cfg);
        let hub = Hub::in_memory(cfg).unwrap();
        Self { _home: home, _ws: ws, hub, reg: builtin_registry() }
    }

    fn ws(&self) -> PathBuf {
        self.hub.cfg().workspace_root()
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn reg_call(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "skill_registry", json!({ "action": action, "params": params })).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.call(who, tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
    }

    async fn approve(&self, id: i64) {
        self.ok(&approver(), "approval_resolve", json!({ "id": id, "decision": "approve" })).await;
    }

    async fn gated_reg(&self, who: &Caller, action: &str, params: Value) -> (i64, Value) {
        let approval_id = match self.reg_call(who, action, params.clone()).await {
            Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
            other => panic!("expected approval_required for {action}, got {other:?}"),
        };
        self.approve(approval_id).await;
        let out = self
            .reg_call(who, action, params)
            .await
            .unwrap_or_else(|e| panic!("{action} failed after approval: {e}"));
        (approval_id, out)
    }

    async fn publish_skill(&self, name: &str, rel_path: &str) -> Value {
        let staged =
            self.reg_call(&ops_bot(), "publish", json!({ "name": name, "path": rel_path })).await.unwrap();
        if staged["idempotent"] == true {
            return staged;
        }
        assert_eq!(staged["status"], "approval_pending", "{staged}");
        let approval_id = staged["approval_id"].as_i64().unwrap();
        let staging_id = staged["staging_id"].as_str().unwrap().to_string();
        self.approve(approval_id).await;
        self.reg_call(&ops_bot(), "publish", json!({ "staging_id": staging_id })).await.unwrap()
    }

    async fn assign_skill(&self, name: &str, target: &str, version: Option<i64>) -> Value {
        let mut params = json!({ "skill_name": name, "target": target, "target_type": "agent" });
        if let Some(v) = version {
            params["version"] = json!(v);
        }
        self.gated_reg(&ops_bot(), "assign", params).await.1
    }

    fn add_org(&self, id: &str) {
        self.hub
            .db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                     VALUES (?1, ?1, 'Org B', '[\"developer\", \"coordinator\", \"operator\"]', \
                     '2026-01-01T00:00:00+00:00')",
                    [id],
                )?;
                Ok(())
            })
            .unwrap();
    }

    async fn register_node_and_bundle(&self) {
        self.ok(&device(), "node_register", json!({ "node": NODE })).await;
        let bundle = json!({ "version": "v1" });
        match self.call(&human_op(), "harness_config_publish", json!({ "bundle": bundle })).await {
            Ok(_) => {}
            Err(UaError::ApprovalRequired { approval_id, .. }) => {
                self.approve(approval_id).await;
                self.ok(&human_op(), "harness_config_publish", json!({ "bundle": bundle })).await;
            }
            Err(e) => panic!("harness_config_publish failed: {e}"),
        }
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

fn human_op() -> Caller {
    caller("operator", ActorKind::Human, Profile::Coordinator, DEFAULT_ORG)
}

fn approver() -> Caller {
    caller("reviewer", ActorKind::Human, Profile::Operator, DEFAULT_ORG)
}

fn ops_bot() -> Caller {
    caller("ops-bot", ActorKind::Agent, Profile::Coordinator, DEFAULT_ORG)
}

fn dev_agent(label: &str, org: &str) -> Caller {
    caller(label, ActorKind::Agent, Profile::Developer, org)
}

fn reviewer_agent() -> Caller {
    caller("rev-1", ActorKind::Agent, Profile::Reviewer, DEFAULT_ORG)
}

fn anon() -> Caller {
    caller("local", ActorKind::Anonymous, Profile::Developer, DEFAULT_ORG)
}

fn device() -> Caller {
    caller("builder-1", ActorKind::Agent, Profile::Developer, DEFAULT_ORG)
}

fn write_skill_dir(root: &Path, name: &str, body_extra: &str, extra_files: &[(&str, &[u8])]) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let md = format!(
        "---\nname: {name}\ndescription: Verifies {name} workflows. Use when asked to run {name} checks.\n---\n\n\
         # {name}\n\nStep one: inspect inputs.\nStep two: apply check.\nStep three: {body_extra}\n"
    );
    std::fs::write(dir.join("SKILL.md"), md).unwrap();
    for (rel, bytes) in extra_files {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, bytes).unwrap();
    }
}

#[tokio::test]
async fn non_operator_yank_refused_and_yank_is_permanent_and_ledgered() {
    let h = Harness::new();
    let src_root = h.ws().join("src-skills");
    write_skill_dir(&src_root, "yank-me", "report results.", &[]);
    let pub_out = h.publish_skill("yank-me", "src-skills/yank-me").await;
    let hash = pub_out["skill"]["content_hash"].as_str().unwrap().to_string();

    // Non-operators (anonymous, developer agent, and even lifecycle operator) are refused.
    let anon_err = h
        .reg_call(&anon(), "yank", json!({ "name": "yank-me", "version": 1, "reason": "bad" }))
        .await
        .unwrap_err();
    assert_eq!(anon_err.code(), "denied");
    assert_eq!(anon_err.reason_code(), Some("identity_required"));

    let dev_err = h
        .reg_call(&dev_agent("builder-1", DEFAULT_ORG), "yank", json!({ "name": "yank-me", "version": 1 }))
        .await
        .unwrap_err();
    assert_eq!(dev_err.code(), "denied");
    assert_eq!(dev_err.reason_code(), Some("operator_required"));

    let lifecycle_err =
        h.reg_call(&ops_bot(), "yank", json!({ "name": "yank-me", "version": 1 })).await.unwrap_err();
    assert_eq!(lifecycle_err.code(), "denied");
    assert_eq!(lifecycle_err.reason_code(), Some("operator_required"));

    // Human operator yanks v1 behind human approval.
    let (_aid, yanked) = h
        .gated_reg(&human_op(), "yank", json!({ "name": "yank-me", "version": 1, "reason": "CVE-test" }))
        .await;
    assert_eq!(yanked["ok"], true);
    assert_eq!(yanked["yank"]["name"], "yank-me");
    assert_eq!(yanked["yank"]["version"], 1);
    assert_eq!(yanked["yank"]["content_hash"], hash);
    assert_eq!(yanked["yank"]["reason"], "CVE-test");
    assert_eq!(yanked["yank"]["yanked_by"], "operator");

    // Verify `skill_version_yanks` row matches docs/skill-sources.md §6 columns.
    let row: (String, String, i64, String, Option<String>, String, String) = h
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT org_id, name, version, content_hash, reason, yanked_by, yanked_at \
                 FROM skill_version_yanks WHERE org_id = 'default' AND name = 'yank-me' AND version = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )?)
        })
        .unwrap();
    assert_eq!(row.0, DEFAULT_ORG);
    assert_eq!(row.1, "yank-me");
    assert_eq!(row.2, 1);
    assert_eq!(row.3, hash);
    assert_eq!(row.4.as_deref(), Some("CVE-test"));
    assert_eq!(row.5, "operator");
    assert!(!row.6.is_empty());

    // Verify `skill.yanked` ledger event was appended in the same transaction.
    let (orig, ev_payload): (String, String) = h
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT originator, payload FROM event_log WHERE channel = 'skill.yanked' \
                 ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(orig, "operator");
    let ev: Value = serde_json::from_str(&ev_payload).unwrap();
    assert_eq!(ev["name"], "yank-me");
    assert_eq!(ev["version"], 1);
    assert_eq!(ev["content_hash"], hash);
    assert_eq!(ev["reason"], "CVE-test");

    // Yanks are permanent: re-yanking is refused and DB triggers block UPDATE/DELETE.
    let again_err =
        h.reg_call(&human_op(), "yank", json!({ "name": "yank-me", "version": 1 })).await.unwrap_err();
    assert_eq!(again_err.code(), "conflict");
    assert_eq!(again_err.reason_code(), Some("yanked"));

    assert!(
        h.hub
            .db()
            .write(|tx| {
                tx.execute("UPDATE skill_version_yanks SET reason = 'edited' WHERE name = 'yank-me'", [])?;
                Ok(())
            })
            .is_err(),
        "UPDATE on skill_version_yanks must abort"
    );
    assert!(
        h.hub
            .db()
            .write(|tx| {
                tx.execute("DELETE FROM skill_version_yanks WHERE name = 'yank-me'", [])?;
                Ok(())
            })
            .is_err(),
        "DELETE on skill_version_yanks must abort"
    );
}

#[tokio::test]
async fn yank_effects_block_assign_install_get_resolve_node_config_and_republish() {
    let h = Harness::new();
    let src_root = h.ws().join("src-skills");
    write_skill_dir(&src_root, "bad-skill", "v1 bad payload.", &[]);
    write_skill_dir(&src_root, "good-skill", "v1 good payload.", &[]);

    let bad_v1 = h.publish_skill("bad-skill", "src-skills/bad-skill").await;
    let bad_hash = bad_v1["skill"]["content_hash"].as_str().unwrap().to_string();
    h.publish_skill("good-skill", "src-skills/good-skill").await;

    h.assign_skill("bad-skill", "builder-1", Some(1)).await;
    h.assign_skill("good-skill", "builder-1", Some(1)).await;
    h.register_node_and_bundle().await;

    // Sanity check before yank: resolve & node_config include both skills.
    let pre_res = h
        .reg_call(&dev_agent("builder-1", DEFAULT_ORG), "resolve", json!({ "agent_label": "builder-1" }))
        .await
        .unwrap();
    assert_eq!(pre_res["skills"].as_array().unwrap().len(), 2);

    // Also create a second workspace copy with identical bytes and stage it
    // under a different skill name BEFORE yanking `bad-skill` v1, so we can
    // prove `publish {staging_id}` refuses a yanked content_hash even if staged
    // prior to the yank.
    let dup_dir = h.ws().join("src-skills/dup-before-yank");
    std::fs::create_dir_all(&dup_dir).unwrap();
    let bad_md = std::fs::read_to_string(src_root.join("bad-skill/SKILL.md")).unwrap();
    std::fs::write(dup_dir.join("SKILL.md"), &bad_md).unwrap();
    let pre_staged_id = "sk-pre-yank-dup";
    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO skill_publish_staging (org_id, id, name, content, content_hash, source, \
                 findings_json, requested_by, created_at) \
                 VALUES ('default', ?1, 'bad-skill', ?2, ?3, 'src-skills/dup-before-yank/SKILL.md', \
                 '[]', 'ops-bot', '2026-01-01T00:00:00+00:00')",
                params![pre_staged_id, bad_md, bad_hash],
            )?;
            Ok(())
        })
        .unwrap();

    // Yank `bad-skill` v1.
    h.gated_reg(&human_op(), "yank", json!({ "name": "bad-skill", "version": 1, "reason": "compromised" }))
        .await;

    // 1. `get` refuses yanked version (explicit version and implicit latest) with conflict/yanked.
    for params in [json!({ "name": "bad-skill", "version": 1 }), json!({ "name": "bad-skill" })] {
        let err = h.reg_call(&dev_agent("builder-1", DEFAULT_ORG), "get", params).await.unwrap_err();
        assert_eq!(err.code(), "conflict");
        assert_eq!(err.reason_code(), Some("yanked"));
    }

    // 2. `assign` refuses yanked version (explicit version and implicit latest).
    for params in [
        json!({ "skill_name": "bad-skill", "target": "builder-2", "version": 1 }),
        json!({ "skill_name": "bad-skill", "target": "builder-2" }),
    ] {
        let err = h.reg_call(&ops_bot(), "assign", params).await.unwrap_err();
        assert_eq!(err.code(), "conflict");
        assert_eq!(err.reason_code(), Some("yanked"));
    }

    // 3. `install` refuses yanked version and writes nothing to disk.
    let inst_err = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "bad-skill", "version": 1, "target_dir": "installed" }),
        )
        .await
        .unwrap_err();
    assert_eq!(inst_err.code(), "conflict");
    assert_eq!(inst_err.reason_code(), Some("yanked"));
    assert!(!h.ws().join("installed/bad-skill").exists());

    // 4. `resolve` omits the yanked version while still returning `good-skill`.
    let post_res = h
        .reg_call(&dev_agent("builder-1", DEFAULT_ORG), "resolve", json!({ "agent_label": "builder-1" }))
        .await
        .unwrap();
    let names: Vec<&str> =
        post_res["skills"].as_array().unwrap().iter().filter_map(|s| s["name"].as_str()).collect();
    assert_eq!(names, vec!["good-skill"], "resolve must omit yanked skill: {post_res}");

    // 5. `node_config` fails closed per skill (`included: false`, `reason: "yanked"`),
    //    omitting `bad-skill` from the bundle while still serving `good-skill`.
    let nc = h.ok(&device(), "node_config", json!({ "node": NODE })).await;
    let notes = nc["assigned_skills"].as_array().unwrap();
    let bad_note = notes.iter().find(|n| n["name"] == "bad-skill").expect("bad-skill note");
    assert_eq!(bad_note["included"], false, "{bad_note}");
    assert_eq!(bad_note["reason"], "yanked", "{bad_note}");
    assert_eq!(bad_note["skipped"], "yanked", "{bad_note}");
    assert_eq!(bad_note["version"], 1, "{bad_note}");
    let good_note = notes.iter().find(|n| n["name"] == "good-skill").expect("good-skill note");
    assert_eq!(good_note["included"], true, "{good_note}");
    let bundle_skill_names: Vec<&str> =
        nc["bundle"]["skills"].as_array().unwrap().iter().filter_map(|s| s["name"].as_str()).collect();
    assert_eq!(bundle_skill_names, vec!["good-skill"]);

    // 6. Re-publishing the exact yanked `content_hash` is refused (NOT `idempotent: true`).
    let repub_err = h
        .reg_call(&ops_bot(), "publish", json!({ "name": "bad-skill", "path": "src-skills/bad-skill" }))
        .await
        .unwrap_err();
    assert_eq!(repub_err.code(), "conflict");
    assert_eq!(repub_err.reason_code(), Some("yanked"));

    // Already-staged copy carrying the yanked content_hash is also refused at publish time.
    let staged_err =
        h.reg_call(&ops_bot(), "publish", json!({ "staging_id": pre_staged_id })).await.unwrap_err();
    assert_eq!(staged_err.code(), "conflict");
    assert_eq!(staged_err.reason_code(), Some("yanked"));

    // 7. `list` reports `yanked: true` on v1 while publishing a fixed v2 with a
    //    distinct `content_hash` succeeds and restores the skill.
    let listed = h.reg_call(&ops_bot(), "list", json!({ "name": "bad-skill" })).await.unwrap();
    assert_eq!(listed["skills"][0]["yanked"], true);

    write_skill_dir(&src_root, "bad-skill", "v2 fixed safe payload.", &[]);
    let v2 = h.publish_skill("bad-skill", "src-skills/bad-skill").await;
    assert_eq!(v2["ok"], true);
    assert_eq!(v2["skill"]["version"], 2);
    assert_ne!(v2["skill"]["content_hash"], bad_hash);

    // v2 can be fetched, assigned, and installed cleanly.
    let got_v2 = h
        .reg_call(&dev_agent("builder-1", DEFAULT_ORG), "get", json!({ "name": "bad-skill", "version": 2 }))
        .await
        .unwrap();
    assert_eq!(got_v2["version"], 2);
    h.assign_skill("bad-skill", "builder-1", Some(2)).await;
    let res_v2 = h
        .reg_call(&dev_agent("builder-1", DEFAULT_ORG), "resolve", json!({ "agent_label": "builder-1" }))
        .await
        .unwrap();
    assert_eq!(res_v2["skills"].as_array().unwrap().len(), 2);
}

#[cfg(feature = "test-util")]
#[tokio::test]
async fn yank_refuses_reimporting_exact_content_hash_from_git_source() {
    use std::process::Command;

    let h = Harness::new();
    let remote = tempfile::tempdir().unwrap();
    let git_ok = |args: &[&str]| -> String {
        let out = Command::new("git")
            .current_dir(remote.path())
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
    git_ok(&["init", "-b", "main"]);
    write_skill_dir(&remote.path().join("skills"), "git-yank", "upstream v1 content.", &[]);
    git_ok(&["add", "."]);
    git_ok(&["commit", "-m", "v1"]);
    let sha = git_ok(&["rev-parse", "HEAD"]);

    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO skill_sources (org_id, id, canonical_url, host, repo_path, allowed_subpaths, \
                 tracking_ref, pinned_sha, status, added_by, added_at, approval_id) \
                 VALUES ('default', 'src-git-yank', ?1, '', ?2, '[\"skills\"]', 'main', ?3, 'active', \
                 'operator', '2026-01-01T00:00:00+00:00', NULL)",
                params![
                    format!("file://{}", remote.path().display()),
                    remote.path().display().to_string(),
                    sha
                ],
            )?;
            Ok(())
        })
        .unwrap();

    // Import & publish v1 from the Git source.
    let staged = h
        .reg_call(
            &ops_bot(),
            "source_import",
            json!({ "source_id": "src-git-yank", "path": "skills/git-yank" }),
        )
        .await
        .unwrap();
    h.approve(staged["approval_id"].as_i64().unwrap()).await;
    let published =
        h.reg_call(&ops_bot(), "publish", json!({ "staging_id": staged["staging_id"] })).await.unwrap();
    assert_eq!(published["skill"]["version"], 1);

    // Yank v1.
    h.gated_reg(&human_op(), "yank", json!({ "name": "git-yank", "version": 1, "reason": "bad upstream" }))
        .await;

    // Re-importing the exact same upstream commit/content_hash is refused (`yanked`), NOT idempotent.
    let reimport_err = h
        .reg_call(
            &ops_bot(),
            "source_import",
            json!({ "source_id": "src-git-yank", "path": "skills/git-yank" }),
        )
        .await
        .unwrap_err();
    assert_eq!(reimport_err.code(), "conflict");
    assert_eq!(reimport_err.reason_code(), Some("yanked"));
}

#[tokio::test]
async fn catalog_install_verifies_members_expected_hash_mode_0644_and_rejects_tamper_symlinks_and_escape() {
    let h = Harness::new();
    let src_root = h.ws().join("src-skills");
    write_skill_dir(
        &src_root,
        "pkg-install",
        "install cleanly.",
        &[
            ("references/guide.md", b"# Guide\nRead carefully.\n"),
            ("scripts/helper.sh", b"#!/bin/sh\necho hello\n"),
        ],
    );
    // Mark helper.sh executable on disk before publish to verify install writes 0o644.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            src_root.join("pkg-install/scripts/helper.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    let pub1 = h.publish_skill("pkg-install", "src-skills/pkg-install").await;
    let hash1 = pub1["skill"]["content_hash"].as_str().unwrap().to_string();

    // Read-only Reviewer profile cannot install into workspace.
    let rev_err = h
        .reg_call(&reviewer_agent(), "install", json!({ "name": "pkg-install", "target_dir": "installed" }))
        .await
        .unwrap_err();
    assert_eq!(rev_err.code(), "denied");

    // Mismatched expected_hash is refused before any write.
    let wrong_hash = "0".repeat(64);
    let hash_err = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({
                "name": "pkg-install",
                "version": 1,
                "expected_hash": wrong_hash,
                "target_dir": "installed",
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(hash_err.code(), "conflict");
    assert_eq!(hash_err.reason_code(), Some("hash_mismatch"));
    assert!(!h.ws().join("installed/pkg-install").exists());

    // Valid install with matching expected_hash materializes all members at mode 0o644.
    let inst = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({
                "name": "pkg-install",
                "version": 1,
                "expected_hash": hash1,
                "target_dir": ".claude/skills",
            }),
        )
        .await
        .unwrap();
    assert_eq!(inst["ok"], true);
    assert_eq!(inst["version"], 1);
    assert_eq!(inst["content_hash"], hash1);
    assert_eq!(inst["installed_path"], ".claude/skills/pkg-install");
    assert_eq!(inst["file_count"], 3);

    let dest = h.ws().join(".claude/skills/pkg-install");
    assert_eq!(std::fs::read(dest.join("references/guide.md")).unwrap(), b"# Guide\nRead carefully.\n");
    assert_eq!(std::fs::read(dest.join("scripts/helper.sh")).unwrap(), b"#!/bin/sh\necho hello\n");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for rel in ["SKILL.md", "references/guide.md", "scripts/helper.sh"] {
            let mode = std::fs::symlink_metadata(dest.join(rel)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "{rel} must be installed with mode 0o644, got {mode:o}");
        }
    }

    // L1: Verify `skill.installed` ledger event was recorded with caller, skill, version, hash, target.
    let (inst_orig, inst_ev_raw): (String, String) = h
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT originator, payload FROM event_log WHERE channel = 'skill.installed' \
                 ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(inst_orig, "builder-1");
    let inst_ev: Value = serde_json::from_str(&inst_ev_raw).unwrap();
    assert_eq!(inst_ev["name"], "pkg-install");
    assert_eq!(inst_ev["version"], 1);
    assert_eq!(inst_ev["content_hash"], hash1);
    assert_eq!(inst_ev["target"], ".claude/skills/pkg-install");
    assert_eq!(inst_ev["file_count"], 3);

    // M1: Overwrite defaults to `false`: omitting `overwrite` refuses an existing directory.
    let default_no_overwrite = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "pkg-install", "target_dir": ".claude/skills" }),
        )
        .await
        .unwrap_err();
    assert_eq!(default_no_overwrite.code(), "conflict");

    // Refuses overwriting an unrelated non-skill directory (no SKILL.md).
    let non_skill = h.ws().join("non-skill-root/pkg-install");
    std::fs::create_dir_all(&non_skill).unwrap();
    std::fs::write(non_skill.join("important.txt"), "do not delete").unwrap();
    let non_skill_err = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "pkg-install", "target_dir": "non-skill-root", "overwrite": true }),
        )
        .await
        .unwrap_err();
    assert_eq!(non_skill_err.code(), "conflict");
    assert_eq!(std::fs::read_to_string(non_skill.join("important.txt")).unwrap(), "do not delete");

    // M1: A planted SKILL.md (even an exact copy of the published SKILL.md declaring
    // `name: pkg-install`) alongside unknown files (`important.md`, `sub/notes.md`)
    // MUST be refused even with `overwrite: true`, deleting ZERO files!
    let planted = h.ws().join("area/pkg-install");
    std::fs::create_dir_all(planted.join("sub")).unwrap();
    let real_md = std::fs::read(dest.join("SKILL.md")).unwrap();
    std::fs::write(planted.join("SKILL.md"), &real_md).unwrap();
    std::fs::write(planted.join("important.md"), "precious top-level file").unwrap();
    std::fs::write(planted.join("sub/notes.md"), "precious nested file").unwrap();
    let planted_err = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "pkg-install", "target_dir": "area", "overwrite": true }),
        )
        .await
        .unwrap_err();
    assert_eq!(planted_err.code(), "conflict", "planted SKILL.md must be refused: {planted_err:?}");
    assert_eq!(std::fs::read_to_string(planted.join("important.md")).unwrap(), "precious top-level file");
    assert_eq!(std::fs::read_to_string(planted.join("sub/notes.md")).unwrap(), "precious nested file");

    // Atomic upgrade v1 -> v2 with `overwrite: true` succeeds when every on-disk
    // file matches published v1, replacing files cleanly with no stale v1 files.
    std::fs::remove_file(src_root.join("pkg-install/scripts/helper.sh")).unwrap();
    write_skill_dir(
        &src_root,
        "pkg-install",
        "v2 upgraded payload.",
        &[("references/guide.md", b"# Guide v2\n")],
    );
    let pub2 = h.publish_skill("pkg-install", "src-skills/pkg-install").await;
    assert_eq!(pub2["skill"]["version"], 2);
    let inst2 = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "pkg-install", "version": 2, "target_dir": ".claude/skills", "overwrite": true }),
        )
        .await
        .unwrap();
    assert_eq!(inst2["version"], 2);
    assert!(!dest.join("scripts/helper.sh").exists(), "stale v1 file must be removed on atomic swap");
    assert_eq!(std::fs::read(dest.join("references/guide.md")).unwrap(), b"# Guide v2\n");
    for entry in std::fs::read_dir(h.ws().join(".claude/skills")).unwrap() {
        let fname = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(!fname.contains(".ua-install-") && !fname.contains(".ua-backup-"), "leftover temp {fname}");
    }

    // Out-of-root target_dir (`..` and absolute path outside workspace) refused without writing.
    let outside = tempfile::tempdir().unwrap();
    for bad_target in ["../escape", outside.path().to_str().unwrap()] {
        let err = h
            .reg_call(
                &dev_agent("builder-1", DEFAULT_ORG),
                "install",
                json!({ "name": "pkg-install", "target_dir": bad_target }),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), "denied", "target {bad_target}: {err:?}");
        assert_eq!(err.reason_code(), Some("outside_sandbox"), "target {bad_target}: {err:?}");
    }
    assert!(!outside.path().join("pkg-install").exists());

    // Symlink target_dir and symlink destination directory are both refused without touching target.
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside_dir = tempfile::tempdir().unwrap();
        let link_root = h.ws().join("sym-root");
        symlink(outside_dir.path(), &link_root).unwrap();
        let err1 = h
            .reg_call(
                &dev_agent("builder-1", DEFAULT_ORG),
                "install",
                json!({ "name": "pkg-install", "target_dir": "sym-root" }),
            )
            .await
            .unwrap_err();
        assert_eq!(err1.code(), "invalid_argument");
        assert!(!outside_dir.path().join("pkg-install").exists());

        let real_root = h.ws().join("real-root");
        std::fs::create_dir_all(&real_root).unwrap();
        symlink(outside_dir.path(), real_root.join("pkg-install")).unwrap();
        let err2 = h
            .reg_call(
                &dev_agent("builder-1", DEFAULT_ORG),
                "install",
                json!({ "name": "pkg-install", "target_dir": "real-root", "overwrite": true }),
            )
            .await
            .unwrap_err();
        assert_eq!(err2.code(), "invalid_argument");
        assert!(std::fs::read_dir(outside_dir.path()).unwrap().next().is_none());
    }

    // Tampered DB row (supporting file byte tampered in package_payload) is refused before any write.
    let md = "---\nname: tampered-skill\ndescription: Tampered package test. Use when testing tamper.\n---\n\n# Tampered\n\nOne.\nTwo.\nThree.\n";
    let orig_ref = "original clean reference\n";
    let tampered_ref = "TAMPERED reference bytes\n";
    let manifest = json!({
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "files": [
            { "path": "SKILL.md", "sha256": content_hash(md), "bytes": md.len(), "mode": 0o644 },
            { "path": "references/a.md", "sha256": content_hash(orig_ref), "bytes": orig_ref.len(), "mode": 0o644 },
        ],
    });
    let manifest_str = py_dumps(&manifest, None);
    let stored_hash = content_hash(&manifest_str);
    let tampered_payload = py_dumps(
        &json!({
            "SKILL.md": BASE64.encode(md.as_bytes()),
            "references/a.md": BASE64.encode(tampered_ref.as_bytes()),
        }),
        None,
    );
    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO skill_versions (org_id, name, version, content_hash, source, content, \
                 published_by, published_at, package_manifest, package_payload) \
                 VALUES ('default', 'tampered-skill', 1, ?1, 'src/tampered/SKILL.md', ?2, 'ops-bot', \
                 '2026-01-01T00:00:00+00:00', ?3, ?4)",
                params![stored_hash, md, manifest_str, tampered_payload],
            )?;
            Ok(())
        })
        .unwrap();

    let tamper_err = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "tampered-skill", "version": 1, "target_dir": "tamper-out" }),
        )
        .await
        .unwrap_err();
    assert_eq!(tamper_err.code(), "conflict");
    assert!(!h.ws().join("tamper-out").exists(), "tampered install must not even create target_dir");
}

#[tokio::test]
async fn cross_org_isolation_returns_not_found_for_foreign_get_and_install() {
    let h = Harness::new();
    h.add_org("org-b");
    let src_root = h.ws().join("src-skills");
    write_skill_dir(&src_root, "default-only", "default org skill.", &[]);
    h.publish_skill("default-only", "src-skills/default-only").await;

    let org_b_dev = dev_agent("builder-b", "org-b");

    // Foreign org gets identical `not_found` for both `get` and `install`.
    let get_foreign =
        h.reg_call(&org_b_dev, "get", json!({ "name": "default-only", "version": 1 })).await.unwrap_err();
    let get_missing =
        h.reg_call(&org_b_dev, "get", json!({ "name": "no-such-skill", "version": 1 })).await.unwrap_err();
    assert_eq!(get_foreign.code(), "not_found");
    assert_eq!(get_missing.code(), "not_found");

    let inst_foreign = h
        .reg_call(
            &org_b_dev,
            "install",
            json!({ "name": "default-only", "version": 1, "target_dir": "installed" }),
        )
        .await
        .unwrap_err();
    let inst_missing = h
        .reg_call(
            &org_b_dev,
            "install",
            json!({ "name": "no-such-skill", "version": 1, "target_dir": "installed" }),
        )
        .await
        .unwrap_err();
    assert_eq!(inst_foreign.code(), "not_found");
    assert_eq!(inst_missing.code(), "not_found");
    assert!(!h.ws().join("installed").exists());
}

#[tokio::test]
async fn install_enforces_workspace_sandbox_hook_and_dependency_guards() {
    let agent_ws = tempfile::tempdir().unwrap();
    let agent_ws_path = agent_ws.path().to_path_buf();
    let h = Harness::with_cfg(|cfg| {
        cfg.agent_workspaces.insert("denied-bot".into(), "deny".into());
        cfg.agent_workspaces.insert("scoped-bot".into(), agent_ws_path.to_string_lossy().into_owned());
    });

    // Initialize a real git repo in the hub workspace with a custom `core.hooksPath`
    // so `guard_configured_hooks_dir` and `guard_configured_hooks` are exercised too.
    let git_init = std::process::Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(h.ws())
        .status()
        .expect("git init");
    assert!(git_init.success());
    let git_cfg = std::process::Command::new("git")
        .args(["config", "core.hooksPath", "custom-hooks"])
        .current_dir(h.ws())
        .status()
        .expect("git config core.hooksPath");
    assert!(git_cfg.success());
    std::fs::create_dir_all(h.ws().join("custom-hooks")).unwrap();

    let src_root = h.ws().join("src-skills");
    write_skill_dir(&src_root, "sandbox-skill", "sandbox guard test.", &[]);
    h.publish_skill("sandbox-skill", "src-skills/sandbox-skill").await;

    // 1. Agent with `agent_workspaces = deny` is refused with `workspace_denied`
    //    and writes nothing to the hub workspace root.
    let deny_err = h
        .reg_call(
            &dev_agent("denied-bot", DEFAULT_ORG),
            "install",
            json!({ "name": "sandbox-skill", "target_dir": "installed" }),
        )
        .await
        .unwrap_err();
    assert_eq!(deny_err.code(), "denied");
    assert_eq!(deny_err.reason_code(), Some("workspace_denied"));
    assert!(!h.ws().join("installed").exists());

    // 2. Agent with its own `agent_workspaces` root installs ONLY into its own
    //    root and never into the hub root.
    let scoped_res = h
        .reg_call(
            &dev_agent("scoped-bot", DEFAULT_ORG),
            "install",
            json!({ "name": "sandbox-skill", "target_dir": "skills" }),
        )
        .await
        .unwrap();
    assert_eq!(scoped_res["ok"], true);
    assert!(agent_ws.path().join("skills/sandbox-skill/SKILL.md").is_file());
    assert!(!h.ws().join("skills/sandbox-skill").exists());

    // 3. Hook dirs (`.git`, `.husky`, configured `custom-hooks`) and dependency
    //    dirs (`node_modules`, `.venv/lib/python3.12/site-packages`, `target`)
    //    are ALL refused without writing anything.
    for (bad_target, expected_reason) in [
        (".git", "hook_dir"),
        (".git/hooks", "hook_dir"),
        (".husky", "hook_dir"),
        ("custom-hooks", "hook_dir"),
        ("custom-hooks/nested", "hook_dir"),
        ("node_modules", "dependency_dir"),
        (".venv/lib/python3.12/site-packages", "dependency_dir"),
        ("target", "dependency_dir"),
    ] {
        let err = h
            .reg_call(
                &dev_agent("builder-1", DEFAULT_ORG),
                "install",
                json!({ "name": "sandbox-skill", "target_dir": bad_target }),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), "denied", "{bad_target}: {err:?}");
        assert_eq!(err.reason_code(), Some(expected_reason), "{bad_target}: {err:?}");
        assert!(
            !h.ws().join(bad_target).join("sandbox-skill").exists(),
            "{bad_target} must not receive installed files"
        );
    }

    // 4. A package carrying a member path inside a dependency dir (`node_modules/p.js`)
    //    is also refused by member-path guard checks before any write.
    let md = "---\nname: dep-member\ndescription: Dep member test. Use when testing guards.\n---\n\n# Dep\n\nOne.\nTwo.\nThree.\n";
    let js = "module.exports = {};\n";
    let manifest = json!({
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "files": [
            { "path": "SKILL.md", "sha256": content_hash(md), "bytes": md.len(), "mode": 0o644 },
            { "path": "node_modules/p.js", "sha256": content_hash(js), "bytes": js.len(), "mode": 0o644 },
        ],
    });
    let manifest_str = py_dumps(&manifest, None);
    let stored_hash = content_hash(&manifest_str);
    let payload_str = py_dumps(
        &json!({
            "SKILL.md": BASE64.encode(md.as_bytes()),
            "node_modules/p.js": BASE64.encode(js.as_bytes()),
        }),
        None,
    );
    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO skill_versions (org_id, name, version, content_hash, source, content, \
                 published_by, published_at, package_manifest, package_payload) \
                 VALUES ('default', 'dep-member', 1, ?1, 'src/dep-member/SKILL.md', ?2, 'ops-bot', \
                 '2026-01-01T00:00:00+00:00', ?3, ?4)",
                params![stored_hash, md, manifest_str, payload_str],
            )?;
            Ok(())
        })
        .unwrap();
    let member_err = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "dep-member", "target_dir": "safe-skills" }),
        )
        .await
        .unwrap_err();
    assert_eq!(member_err.code(), "denied");
    assert_eq!(member_err.reason_code(), Some("dependency_dir"));
    assert!(!h.ws().join("safe-skills").exists());

    // 5. Target-guard-only path: when `core.hooksPath` lies *inside* `target_dir`
    //    or `<target_dir>/<name>` (so no member path lands inside the hooks dir,
    //    and ONLY `guard_configured_hooks_dir` catches `hooks.starts_with(dir)`),
    //    install MUST still refuse with `denied` / `hook_dir`.
    let set_nested_hooks = std::process::Command::new("git")
        .args(["config", "core.hooksPath", "hooks-parent/sandbox-skill/nested-hooks"])
        .current_dir(h.ws())
        .status()
        .expect("git config nested core.hooksPath");
    assert!(set_nested_hooks.success());
    std::fs::create_dir_all(h.ws().join("hooks-parent/sandbox-skill/nested-hooks")).unwrap();
    let parent_contains_err = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "sandbox-skill", "target_dir": "hooks-parent" }),
        )
        .await
        .unwrap_err();
    assert_eq!(parent_contains_err.code(), "denied", "{parent_contains_err:?}");
    assert_eq!(parent_contains_err.reason_code(), Some("hook_dir"), "{parent_contains_err:?}");
    assert!(!h.ws().join("hooks-parent/sandbox-skill/SKILL.md").exists());

    // 6. Destination-name guard: a valid kebab-case skill named `"target"`
    //    installed into a safe `target_dir` is still refused by `guard_inside_root`
    //    because `<target_dir>/target` hits `DEPENDENCY_DIRS`.
    write_skill_dir(&src_root, "target", "skill named target.", &[]);
    h.publish_skill("target", "src-skills/target").await;
    let dep_name_err = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "target", "target_dir": "safe-skills" }),
        )
        .await
        .unwrap_err();
    assert_eq!(dep_name_err.code(), "denied");
    assert_eq!(dep_name_err.reason_code(), Some("dependency_dir"));
    assert!(!h.ws().join("safe-skills/target").exists());

    // 7. `SKILL.md` frontmatter `name` check on overwrite: even when the existing
    //    directory's file hash matches a row in `skill_versions` for this skill,
    //    overwrite MUST still be refused if the on-disk `SKILL.md` does not
    //    declare `name: <skill>` (e.g., legacy/imported row with wrong/missing name).
    let wrong_name_md =
        "---\nname: other-skill\ndescription: Mismatched frontmatter name.\n---\n\n# Wrong\n\nBody.\n";
    let wrong_hash = content_hash(wrong_name_md);
    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO skill_versions (org_id, name, version, content_hash, source, content, \
                 published_by, published_at) \
                 VALUES ('default', 'name-check', 1, ?1, 'src/name-check/SKILL.md', ?2, 'ops-bot', \
                 '2026-01-01T00:00:00+00:00')",
                params![wrong_hash, wrong_name_md],
            )?;
            Ok(())
        })
        .unwrap();
    write_skill_dir(&src_root, "name-check", "proper v2 skill.", &[]);
    h.publish_skill("name-check", "src-skills/name-check").await;

    let existing_dir = h.ws().join("name-check-root/name-check");
    std::fs::create_dir_all(&existing_dir).unwrap();
    std::fs::write(existing_dir.join("SKILL.md"), wrong_name_md).unwrap();

    let fm_name_err = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({
                "name": "name-check",
                "version": 2,
                "target_dir": "name-check-root",
                "overwrite": true,
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(fm_name_err.code(), "conflict", "{fm_name_err:?}");
    assert!(
        fm_name_err.to_string().contains("does not declare name"),
        "expected SKILL.md frontmatter name refusal, got: {fm_name_err}"
    );
    assert_eq!(std::fs::read_to_string(existing_dir.join("SKILL.md")).unwrap(), wrong_name_md);
}

#[tokio::test]
async fn drift_flags_installed_yanked_skill_and_hash_wide_yank_blocks_other_names() {
    let h = Harness::new();
    let src_root = h.ws().join("src-skills");
    write_skill_dir(&src_root, "yanked-drift", "drift test payload.", &[]);
    let pub1 = h.publish_skill("yanked-drift", "src-skills/yanked-drift").await;
    let hash1 = pub1["skill"]["content_hash"].as_str().unwrap().to_string();

    // Install v1 onto disk BEFORE yanking it.
    let inst = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "yanked-drift", "version": 1, "target_dir": "surface" }),
        )
        .await
        .unwrap();
    assert_eq!(inst["ok"], true);

    // L3: Seed a second skill `hash-twin` v1 carrying the exact same `content_hash`
    // (same SKILL.md + manifest + payload) BEFORE yanking `yanked-drift` v1, and
    // assign `hash-twin` to `builder-1`.
    let (md, manifest_str, payload_str): (String, String, String) = h
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT content, package_manifest, package_payload FROM skill_versions \
                 WHERE org_id = 'default' AND name = 'yanked-drift' AND version = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?)
        })
        .unwrap();
    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO skill_versions (org_id, name, version, content_hash, source, content, \
                 published_by, published_at, package_manifest, package_payload) \
                 VALUES ('default', 'hash-twin', 1, ?1, 'src/hash-twin/SKILL.md', ?2, 'ops-bot', \
                 '2026-01-01T00:00:00+00:00', ?3, ?4)",
                params![hash1, md, manifest_str, payload_str],
            )?;
            Ok(())
        })
        .unwrap();
    h.assign_skill("hash-twin", "builder-1", Some(1)).await;
    h.register_node_and_bundle().await;

    // Yank `yanked-drift` v1 ONLY (NOT `hash-twin` by name).
    h.gated_reg(&human_op(), "yank", json!({ "name": "yanked-drift", "version": 1, "reason": "bad-hash" }))
        .await;

    // L2: `drift` flags the installed-but-yanked skill in `yanked`, NOT `unregistered`.
    let d1 = h.reg_call(&ops_bot(), "drift", json!({ "surface_dir": "surface" })).await.unwrap();
    assert!(d1["unregistered"].as_array().unwrap().is_empty(), "yanked skill must not be unregistered: {d1}");
    let yanked_list = d1["yanked"].as_array().unwrap();
    assert_eq!(yanked_list.len(), 1, "{d1}");
    assert_eq!(yanked_list[0]["name"], "yanked-drift");
    assert_eq!(yanked_list[0]["yanked_version"], 1);
    assert_eq!(yanked_list[0]["reason"], "bad-hash");

    // Publish fixed v2: `drift` still flags on-disk yanked v1 in `yanked` (with
    // replacement_version: 2) as well as `stale`, and upgrading on-disk yanked v1
    // to v2 with `overwrite: true` succeeds cleanly.
    write_skill_dir(&src_root, "yanked-drift", "v2 fixed payload.", &[]);
    h.publish_skill("yanked-drift", "src-skills/yanked-drift").await;
    let d2 = h.reg_call(&ops_bot(), "drift", json!({ "surface_dir": "surface" })).await.unwrap();
    assert_eq!(d2["yanked"].as_array().unwrap().len(), 1, "{d2}");
    assert_eq!(d2["yanked"][0]["replacement_version"], 2);
    assert_eq!(d2["stale"].as_array().unwrap().len(), 1, "{d2}");

    let upgrade = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "yanked-drift", "version": 2, "target_dir": "surface", "overwrite": true }),
        )
        .await
        .unwrap();
    assert_eq!(upgrade["version"], 2);

    // L3: Hash-wide yank refusal blocks `hash-twin` v1 across `get`, `install`,
    // `assign`, `resolve`, and `node_config` even though only `yanked-drift` v1
    // is named in `skill_version_yanks`.
    let twin_get = h
        .reg_call(&dev_agent("builder-1", DEFAULT_ORG), "get", json!({ "name": "hash-twin", "version": 1 }))
        .await
        .unwrap_err();
    assert_eq!(twin_get.code(), "conflict");
    assert_eq!(twin_get.reason_code(), Some("yanked"));

    let twin_inst = h
        .reg_call(
            &dev_agent("builder-1", DEFAULT_ORG),
            "install",
            json!({ "name": "hash-twin", "version": 1, "target_dir": "twin-out" }),
        )
        .await
        .unwrap_err();
    assert_eq!(twin_inst.code(), "conflict");
    assert_eq!(twin_inst.reason_code(), Some("yanked"));

    let twin_assign = h
        .reg_call(
            &ops_bot(),
            "assign",
            json!({ "skill_name": "hash-twin", "target": "builder-2", "version": 1 }),
        )
        .await
        .unwrap_err();
    assert_eq!(twin_assign.code(), "conflict");
    assert_eq!(twin_assign.reason_code(), Some("yanked"));

    let twin_res = h
        .reg_call(&dev_agent("builder-1", DEFAULT_ORG), "resolve", json!({ "agent_label": "builder-1" }))
        .await
        .unwrap();
    assert!(
        twin_res["skills"].as_array().unwrap().is_empty(),
        "resolve must omit hash-yanked twin: {twin_res}"
    );

    let nc = h.ok(&device(), "node_config", json!({ "node": NODE })).await;
    let notes = nc["assigned_skills"].as_array().unwrap();
    let twin_note = notes.iter().find(|n| n["name"] == "hash-twin").expect("hash-twin note");
    assert_eq!(twin_note["included"], false);
    assert_eq!(twin_note["reason"], "yanked");
    assert_eq!(twin_note["skipped"], "yanked");
}
