//! Multi-file skill package tests (hub task #2714, slice D1).
//!
//! Covers staging, approval payloads, workspace isolation after staging,
//! content-hash determinism, no-exec mode normalization, tamper refusal on
//! `get`/`resolve`/`node_config`, path/symlink/hidden-file refusals, every
//! package limit at its boundary, cross-org isolation, and Python-hub imported
//! package compatibility. Runs offline with no network.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rusqlite::params;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::families::harness_config::render::{self, content_hash, py_dumps};
use ua_tools::families::skill_registry::{
    MAX_APPROVAL_TEXT_BYTES, MAX_PACKAGE_BYTES, MAX_PACKAGE_DEPTH, MAX_PACKAGE_ENTRIES,
    MAX_PACKAGE_FILE_BYTES, MAX_PACKAGE_FILES, MAX_PACKAGE_PATH, MAX_SKILL_FILE_BYTES,
    PACKAGE_SCHEMA_VERSION,
};
use ua_tools::{Hub, Registry, builtin_registry};

const NODE: &str = "node-pkg-1";

struct Harness {
    _home: tempfile::TempDir,
    _ws: tempfile::TempDir,
    hub: Hub,
    reg: Registry,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(home.path());
        cfg.human_identities = vec!["operator".into(), "publisher".into()];
        cfg.lifecycle_operators = Some(vec!["ops-bot".into()]);
        cfg.workspace = Some(ws.path().to_path_buf());
        let hub = Hub::in_memory(cfg).unwrap();
        Self { _home: home, _ws: ws, hub, reg: builtin_registry() }
    }

    fn ws(&self) -> PathBuf {
        self.hub.cfg().workspace_root()
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.call(who, tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
    }

    async fn approve(&self, id: i64) {
        self.ok(&human(), "approval_resolve", json!({ "id": id, "decision": "approve" })).await;
    }

    async fn gated(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(UaError::ApprovalRequired { approval_id, .. }) => {
                self.approve(approval_id).await;
                self.ok(who, tool, args).await
            }
            Err(e) => panic!("{tool} failed: {e}"),
        }
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

    async fn register_node(&self) {
        self.ok(&device(), "node_register", json!({ "node": NODE })).await;
    }

    async fn publish_bundle(&self, bundle: Value) {
        self.gated(&publisher(), "harness_config_publish", json!({ "bundle": bundle })).await;
    }

    async fn publish_skill(&self, name: &str, path: &str) -> Value {
        let staged = self
            .ok(
                &ops(),
                "skill_registry",
                json!({ "action": "publish", "params": { "name": name, "path": path } }),
            )
            .await;
        if staged["idempotent"] == true {
            return staged;
        }
        let approval_id = staged["approval_id"].as_i64().unwrap_or_else(|| panic!("{staged}"));
        let staging_id = staged["staging_id"].as_str().unwrap().to_string();
        self.approve(approval_id).await;
        self.ok(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "staging_id": staging_id } }),
        )
        .await
    }

    fn add_org(&self, id: &str) {
        self.hub
            .db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                     VALUES (?1, ?1, 'Org B', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                    [id],
                )?;
                Ok(())
            })
            .unwrap();
    }
}

fn caller_with_profile(label: &str, kind: ActorKind, profile: Profile, org: &str) -> Caller {
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

fn caller(label: &str, kind: ActorKind, org: &str) -> Caller {
    caller_with_profile(label, kind, Profile::Developer, org)
}

fn human() -> Caller {
    caller_with_profile("operator", ActorKind::Human, Profile::Operator, ua_core::DEFAULT_ORG)
}

fn publisher() -> Caller {
    caller_with_profile("publisher", ActorKind::Human, Profile::Coordinator, ua_core::DEFAULT_ORG)
}

fn ops() -> Caller {
    caller("ops-bot", ActorKind::Agent, ua_core::DEFAULT_ORG)
}

fn device() -> Caller {
    caller("builder-1", ActorKind::Agent, ua_core::DEFAULT_ORG)
}

fn valid_skill_md(name: &str, extra: &str) -> String {
    format!(
        "---\nname: {name}\ndescription: Package helper skill. Use when asked to run a structured check.\n---\n\n\
         # Package helper\n\nFollow the instructions.\nRead the references.\nUse the templates.\n{extra}"
    )
}

fn write_file(base: &Path, rel: &str, bytes: &[u8]) {
    let p = base.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&p, bytes).unwrap();
}

#[tokio::test]
async fn multi_file_publish_round_trip_and_workspace_isolation() {
    let h = Harness::new();
    h.register_node().await;

    let skill_dir = h.ws().join("skills/release-check");
    let md = valid_skill_md("release-check", "");
    let script = "#!/bin/sh\necho check\n";
    let template = "## Release Checklist\n- [ ] Tests pass\n";
    let reference = "# Criteria\nVerify hashes before shipping.\n";

    write_file(&skill_dir, "SKILL.md", md.as_bytes());
    write_file(&skill_dir, "scripts/check.sh", script.as_bytes());
    write_file(&skill_dir, "templates/report.md", template.as_bytes());
    write_file(&skill_dir, "references/guide.md", reference.as_bytes());

    // Mark script executable on disk: the registry must NOT honour execute bits.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(skill_dir.join("scripts/check.sh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    // Stage: copies all files into hub staging and creates an approval showing full text.
    let staged = h
        .ok(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "release-check", "path": "skills/release-check" } }),
        )
        .await;
    assert_eq!(staged["status"], "approval_pending", "{staged}");
    let approval_id = staged["approval_id"].as_i64().unwrap();
    let staging_id = staged["staging_id"].as_str().unwrap().to_string();

    let payload = h.approval_payload(approval_id);
    assert_eq!(payload["action"], "publish");
    assert_eq!(payload["content"], md);
    let manifest_files = payload["package_manifest"]["files"].as_array().unwrap();
    assert_eq!(manifest_files.len(), 4, "{payload}");
    for f in manifest_files {
        assert_eq!(f["mode"], 0o644, "execute bit must never be honoured: {f}");
    }
    let expected_hash = content_hash(&py_dumps(&payload["package_manifest"], None));
    assert_eq!(payload["content_hash"], expected_hash);
    assert_eq!(staged["content_hash"], expected_hash);

    // Approval payload shows the full text of every supporting text file.
    let pkg_files = payload["package_files"].as_array().unwrap();
    assert_eq!(pkg_files.len(), 3, "{payload}");
    let by_path: BTreeMap<&str, &Value> =
        pkg_files.iter().map(|f| (f["path"].as_str().unwrap(), f)).collect();
    assert_eq!(by_path["scripts/check.sh"]["content"], script);
    assert_eq!(by_path["scripts/check.sh"]["encoding"], "utf-8");
    assert_eq!(by_path["templates/report.md"]["content"], template);
    assert_eq!(by_path["references/guide.md"]["content"], reference);

    // Mutate and delete workspace files after staging: publish must use the staged copy only.
    write_file(&skill_dir, "scripts/check.sh", b"#!/bin/sh\nrm -rf /\n");
    std::fs::remove_file(skill_dir.join("templates/report.md")).unwrap();

    h.approve(approval_id).await;
    let published = h
        .ok(&ops(), "skill_registry", json!({ "action": "publish", "params": { "staging_id": staging_id } }))
        .await;
    assert_eq!(published["ok"], true, "{published}");
    assert_eq!(published["idempotent"], false);
    assert_eq!(published["skill"]["version"], 1);
    assert_eq!(published["skill"]["content_hash"], expected_hash);

    // get returns SKILL.md, canonical manifest, and every verified file from staging.
    let got = h
        .ok(&ops(), "skill_registry", json!({ "action": "get", "params": { "name": "release-check" } }))
        .await;
    assert_eq!(got["content"], md);
    assert_eq!(got["content_hash"], expected_hash);
    let got_files: BTreeMap<&str, &Value> =
        got["files"].as_array().unwrap().iter().map(|f| (f["path"].as_str().unwrap(), f)).collect();
    assert_eq!(got_files.len(), 4);
    assert_eq!(got_files["SKILL.md"]["content"], md);
    assert_eq!(got_files["scripts/check.sh"]["content"], script);
    assert_eq!(got_files["templates/report.md"]["content"], template);
    assert_eq!(got_files["references/guide.md"]["content"], reference);

    // Assign to builder-1 and verify resolve serves the whole package.
    h.gated(
        &ops(),
        "skill_registry",
        json!({ "action": "assign", "params": { "skill_name": "release-check", "target": "builder-1" } }),
    )
    .await;
    let resolved = h
        .ok(
            &device(),
            "skill_registry",
            json!({ "action": "resolve", "params": { "agent_label": "builder-1" } }),
        )
        .await;
    let r_skill = &resolved["skills"][0];
    assert_eq!(r_skill["name"], "release-check");
    assert_eq!(r_skill["hash"], expected_hash);
    assert_eq!(r_skill["files"].as_array().unwrap().len(), 4);
    let r_by_path: BTreeMap<&str, &Value> =
        r_skill["files"].as_array().unwrap().iter().map(|f| (f["path"].as_str().unwrap(), f)).collect();
    assert_eq!(r_by_path["scripts/check.sh"]["content"], script);

    // Harness config bundle carries the whole verified multi-file skill package.
    h.publish_bundle(json!({ "version": "v1" })).await;
    let cfg = h.ok(&device(), "node_config", json!({ "node": NODE })).await;
    assert_eq!(cfg["assigned_skills"][0]["included"], true, "{cfg}");
    assert_eq!(cfg["assigned_skills"][0]["file_count"], 4, "{cfg}");
    let bundle_skill = &cfg["bundle"]["skills"][0];
    assert_eq!(bundle_skill["name"], "release-check");
    assert_eq!(bundle_skill["body"], md);
    assert_eq!(bundle_skill["files"].as_array().unwrap().len(), 4, "{bundle_skill}");
    let served: render::Bundle = serde_json::from_value(cfg["bundle"].clone()).unwrap();
    for (surface, rendered) in render::render_all(&served).unwrap() {
        assert_eq!(cfg["rendered"][&surface]["hash"], rendered.hash, "{surface}");
    }

    // Drift detects supporting-file changes and reports synced when restored.
    write_file(&skill_dir, "scripts/check.sh", script.as_bytes());
    write_file(&skill_dir, "templates/report.md", template.as_bytes());
    let drift_synced = h
        .ok(&ops(), "skill_registry", json!({ "action": "drift", "params": { "surface_dir": "skills" } }))
        .await;
    assert_eq!(drift_synced["synced"][0]["name"], "release-check", "{drift_synced}");

    write_file(&skill_dir, "scripts/check.sh", b"#!/bin/sh\necho changed\n");
    let drift_stale = h
        .ok(&ops(), "skill_registry", json!({ "action": "drift", "params": { "surface_dir": "skills" } }))
        .await;
    assert_eq!(drift_stale["stale"][0]["name"], "release-check", "{drift_stale}");
}

#[tokio::test]
async fn same_content_is_idempotent_and_one_byte_change_mints_new_hash() {
    let h = Harness::new();
    let dir = h.ws().join("skills/hash-test");
    write_file(&dir, "SKILL.md", valid_skill_md("hash-test", "").as_bytes());
    write_file(&dir, "references/notes.md", b"version one\n");

    let v1 = h.publish_skill("hash-test", "skills/hash-test").await;
    assert_eq!(v1["skill"]["version"], 1);
    let h1 = v1["skill"]["content_hash"].as_str().unwrap().to_string();

    // Toggling the execute bit on a supporting file produces the exact same hash and is idempotent.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join("references/notes.md"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
    let again = h.publish_skill("hash-test", "skills/hash-test").await;
    assert_eq!(again["idempotent"], true, "{again}");
    assert_eq!(again["skill"]["version"], 1);
    assert_eq!(again["skill"]["content_hash"], h1);

    // Changing one byte in a supporting file yields a different hash and version 2.
    write_file(&dir, "references/notes.md", b"version One\n");
    let v2 = h.publish_skill("hash-test", "skills/hash-test").await;
    assert_eq!(v2["idempotent"], false, "{v2}");
    assert_eq!(v2["skill"]["version"], 2);
    assert_ne!(v2["skill"]["content_hash"], h1);
}

#[tokio::test]
async fn tampered_stored_file_is_refused_on_get_resolve_and_bundle() {
    let h = Harness::new();
    h.register_node().await;
    h.publish_bundle(json!({ "version": "v1" })).await;

    let dir = h.ws().join("skills/tamper-check");
    write_file(&dir, "SKILL.md", valid_skill_md("tamper-check", "").as_bytes());
    write_file(&dir, "scripts/helper.sh", b"echo original\n");
    h.publish_skill("tamper-check", "skills/tamper-check").await;
    h.gated(
        &ops(),
        "skill_registry",
        json!({ "action": "assign", "params": { "skill_name": "tamper-check", "target": "builder-1" } }),
    )
    .await;

    // Sanity: reads pass before tampering.
    h.ok(&ops(), "skill_registry", json!({ "action": "get", "params": { "name": "tamper-check" } })).await;
    h.ok(
        &device(),
        "skill_registry",
        json!({ "action": "resolve", "params": { "agent_label": "builder-1" } }),
    )
    .await;
    h.ok(&device(), "node_config", json!({ "node": NODE })).await;

    // Simulate direct database tampering of a supporting file inside package_payload.
    h.hub
        .db()
        .write(|tx| {
            tx.execute_batch("DROP TRIGGER skill_versions_immutable_update;")?;
            let raw: String = tx.query_row(
                "SELECT package_payload FROM skill_versions WHERE name = 'tamper-check' AND version = 1",
                [],
                |r| r.get(0),
            )?;
            let mut payload: serde_json::Map<String, Value> = serde_json::from_str(&raw)?;
            payload.insert("scripts/helper.sh".into(), json!(BASE64.encode(b"echo tampered!\n")));
            tx.execute(
                "UPDATE skill_versions SET package_payload = ?1 WHERE name = 'tamper-check' AND version = 1",
                [serde_json::to_string(&payload)?],
            )?;
            Ok(())
        })
        .unwrap();

    // Every read path refuses the tampered package instead of serving it.
    let e_get = h
        .call(&ops(), "skill_registry", json!({ "action": "get", "params": { "name": "tamper-check" } }))
        .await
        .unwrap_err();
    assert!(matches!(e_get, UaError::Conflict { .. }), "{e_get:?}");

    let e_resolve = h
        .call(
            &device(),
            "skill_registry",
            json!({ "action": "resolve", "params": { "agent_label": "builder-1" } }),
        )
        .await
        .unwrap_err();
    assert!(matches!(e_resolve, UaError::Conflict { .. }), "{e_resolve:?}");

    let e_bundle = h.call(&device(), "node_config", json!({ "node": NODE })).await.unwrap_err();
    assert!(matches!(e_bundle, UaError::Conflict { .. }), "{e_bundle:?}");

    // Removing package_payload while package_manifest is present is also refused.
    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "UPDATE skill_versions SET package_payload = NULL WHERE name = 'tamper-check' AND version = 1",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    let e_null = h
        .call(&ops(), "skill_registry", json!({ "action": "get", "params": { "name": "tamper-check" } }))
        .await
        .unwrap_err();
    assert!(matches!(e_null, UaError::Conflict { .. }), "{e_null:?}");
}

#[tokio::test]
async fn path_escapes_symlinks_hidden_files_and_unsafe_supporting_content_refused() {
    let h = Harness::new();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), "outside\n").unwrap();

    // Symlinked supporting file.
    let d1 = h.ws().join("skills/sym-file");
    write_file(&d1, "SKILL.md", valid_skill_md("sym-file", "").as_bytes());
    std::fs::create_dir_all(d1.join("scripts")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path().join("secret.txt"), d1.join("scripts/escape.sh")).unwrap();
    #[cfg(unix)]
    {
        let e = h
            .call(
                &ops(),
                "skill_registry",
                json!({ "action": "publish", "params": { "name": "sym-file", "path": "skills/sym-file" } }),
            )
            .await
            .unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
    }

    // Symlinked supporting directory.
    let d2 = h.ws().join("skills/sym-dir");
    write_file(&d2, "SKILL.md", valid_skill_md("sym-dir", "").as_bytes());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.path(), d2.join("references")).unwrap();
        let e = h
            .call(
                &ops(),
                "skill_registry",
                json!({ "action": "publish", "params": { "name": "sym-dir", "path": "skills/sym-dir" } }),
            )
            .await
            .unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
    }

    // Hidden file and hidden directory.
    let d3 = h.ws().join("skills/hidden-file");
    write_file(&d3, "SKILL.md", valid_skill_md("hidden-file", "").as_bytes());
    write_file(&d3, "scripts/.hidden.sh", b"echo no\n");
    let e = h
        .call(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "hidden-file", "path": "skills/hidden-file" } }),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("hidden"), "{e}");

    let d4 = h.ws().join("skills/hidden-dir");
    write_file(&d4, "SKILL.md", valid_skill_md("hidden-dir", "").as_bytes());
    write_file(&d4, ".git/config", b"[core]\n");
    let e = h
        .call(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "hidden-dir", "path": "skills/hidden-dir" } }),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("hidden"), "{e}");

    // Path traversal and absolute paths outside the workspace.
    for bad_path in ["../escape", "/etc/passwd"] {
        let e = h
            .call(
                &ops(),
                "skill_registry",
                json!({ "action": "publish", "params": { "name": "bad-path", "path": bad_path } }),
            )
            .await
            .unwrap_err();
        assert!(matches!(e, UaError::NotFound(_)), "{bad_path}: {e:?}");
    }

    // Credential material in a supporting file is refused.
    let d5 = h.ws().join("skills/cred-file");
    write_file(&d5, "SKILL.md", valid_skill_md("cred-file", "").as_bytes());
    write_file(
        &d5,
        "scripts/key.pem",
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
    );
    let e = h
        .call(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "cred-file", "path": "skills/cred-file" } }),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("credential"), "{e}");

    // Hidden Unicode in a supporting text file blocks staging via review.
    let d6 = h.ws().join("skills/bidi-support");
    write_file(&d6, "SKILL.md", valid_skill_md("bidi-support", "").as_bytes());
    write_file(&d6, "references/guide.md", "Normal line.\nHidden \u{202E}override.\n".as_bytes());
    let blocked = h
        .ok(&ops(), "skill_registry", json!({ "action": "publish", "params": { "name": "bidi-support", "path": "skills/bidi-support" } }))
        .await;
    assert_eq!(blocked["blocked"], true, "{blocked}");
}

#[tokio::test]
async fn every_package_limit_is_refused_at_its_boundary() {
    let h = Harness::new();

    // 1. MAX_PACKAGE_FILES: 128 total files succeeds; 129 fails.
    let d_files = h.ws().join("skills/limit-files");
    write_file(&d_files, "SKILL.md", valid_skill_md("limit-files", "").as_bytes());
    for i in 0..(MAX_PACKAGE_FILES - 1) {
        write_file(&d_files, &format!("templates/f{i:03}.txt"), b"x\n");
    }
    let ok = h
        .ok(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "limit-files", "path": "skills/limit-files" } }),
        )
        .await;
    assert_eq!(ok["status"], "approval_pending", "{ok}");
    write_file(&d_files, "templates/extra.txt", b"x\n");
    let e = h
        .call(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "limit-files", "path": "skills/limit-files" } }),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains(&format!("{MAX_PACKAGE_FILES}-file")), "{e}");

    // 2. MAX_PACKAGE_ENTRIES: >512 directory entries refused.
    let d_entries = h.ws().join("skills/limit-entries");
    write_file(&d_entries, "SKILL.md", valid_skill_md("limit-entries", "").as_bytes());
    for i in 0..=MAX_PACKAGE_ENTRIES {
        std::fs::create_dir_all(d_entries.join(format!("d{i:04}"))).unwrap();
    }
    let e = h
        .call(&ops(), "skill_registry", json!({ "action": "publish", "params": { "name": "limit-entries", "path": "skills/limit-entries" } }))
        .await
        .unwrap_err();
    assert!(e.to_string().contains(&format!("{MAX_PACKAGE_ENTRIES}-entry")), "{e}");

    // 3. MAX_SKILL_FILE_BYTES: 64 KiB + 1 byte SKILL.md refused.
    let d_md = h.ws().join("skills/limit-md");
    let big_md = valid_skill_md("limit-md", &"a".repeat(MAX_SKILL_FILE_BYTES));
    assert!(big_md.len() > MAX_SKILL_FILE_BYTES);
    write_file(&d_md, "SKILL.md", big_md.as_bytes());
    let e = h
        .call(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "limit-md", "path": "skills/limit-md" } }),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains(&format!("{MAX_SKILL_FILE_BYTES}-byte")), "{e}");

    // 4. MAX_PACKAGE_FILE_BYTES: 512 KiB + 1 byte supporting file refused.
    let d_fsize = h.ws().join("skills/limit-fsize");
    write_file(&d_fsize, "SKILL.md", valid_skill_md("limit-fsize", "").as_bytes());
    let mut big_bin = vec![0u8; MAX_PACKAGE_FILE_BYTES + 1];
    big_bin[0] = 0;
    write_file(&d_fsize, "assets/blob.bin", &big_bin);
    let e = h
        .call(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "limit-fsize", "path": "skills/limit-fsize" } }),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains(&format!("{MAX_PACKAGE_FILE_BYTES}-byte")), "{e}");

    // 5. MAX_PACKAGE_BYTES: 5 × 500 KiB binary files (> 2 MiB) refused.
    let d_total = h.ws().join("skills/limit-total");
    write_file(&d_total, "SKILL.md", valid_skill_md("limit-total", "").as_bytes());
    let chunk = vec![0u8; 500 * 1024];
    for i in 0..5 {
        write_file(&d_total, &format!("assets/part-{i}.bin"), &chunk);
    }
    let e = h
        .call(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "limit-total", "path": "skills/limit-total" } }),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains(&format!("{MAX_PACKAGE_BYTES}-byte")), "{e}");

    // 6. MAX_PACKAGE_DEPTH: depth 8 accepted, depth 9 refused.
    let d_depth = h.ws().join("skills/limit-depth");
    write_file(&d_depth, "SKILL.md", valid_skill_md("limit-depth", "").as_bytes());
    let ok_path = format!(
        "{}/f.txt",
        (0..(MAX_PACKAGE_DEPTH - 1)).map(|i| format!("d{i}")).collect::<Vec<_>>().join("/")
    );
    write_file(&d_depth, &ok_path, b"ok\n");
    let staged = h
        .ok(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "limit-depth", "path": "skills/limit-depth" } }),
        )
        .await;
    assert_eq!(staged["status"], "approval_pending", "{staged}");
    let too_deep =
        format!("{}/f.txt", (0..MAX_PACKAGE_DEPTH).map(|i| format!("d{i}")).collect::<Vec<_>>().join("/"));
    write_file(&d_depth, &too_deep, b"deep\n");
    let e = h
        .call(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "limit-depth", "path": "skills/limit-depth" } }),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains(&format!("{MAX_PACKAGE_DEPTH}-level")), "{e}");

    // 7. MAX_PACKAGE_PATH: >240 byte relative path refused.
    let d_pathlen = h.ws().join("skills/limit-pathlen");
    write_file(&d_pathlen, "SKILL.md", valid_skill_md("limit-pathlen", "").as_bytes());
    let long_rel = format!("a/{}/{}/{}.txt", "x".repeat(80), "y".repeat(80), "z".repeat(85));
    assert!(long_rel.len() > MAX_PACKAGE_PATH);
    write_file(&d_pathlen, &long_rel, b"long\n");
    let e = h
        .call(&ops(), "skill_registry", json!({ "action": "publish", "params": { "name": "limit-pathlen", "path": "skills/limit-pathlen" } }))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("unsafe supporting file path"), "{e}");

    // 8. MAX_APPROVAL_TEXT_BYTES: supporting text >256 KiB refused at staging.
    let d_text = h.ws().join("skills/limit-text");
    write_file(&d_text, "SKILL.md", valid_skill_md("limit-text", "").as_bytes());
    write_file(&d_text, "references/huge.md", &"a".repeat(MAX_APPROVAL_TEXT_BYTES + 1).into_bytes());
    let e = h
        .call(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "limit-text", "path": "skills/limit-text" } }),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains(&format!("{MAX_APPROVAL_TEXT_BYTES}-byte")), "{e}");
}

#[tokio::test]
async fn org_b_sees_org_a_package_as_missing() {
    let h = Harness::new();
    h.add_org("org-b");

    let dir = h.ws().join("skills/tenant-pkg");
    write_file(&dir, "SKILL.md", valid_skill_md("tenant-pkg", "").as_bytes());
    write_file(&dir, "scripts/run.sh", b"echo org-a\n");
    h.publish_skill("tenant-pkg", "skills/tenant-pkg").await;
    h.gated(
        &ops(),
        "skill_registry",
        json!({ "action": "assign", "params": { "skill_name": "tenant-pkg", "target": "builder-1" } }),
    )
    .await;

    let org_b_agent = caller("builder-1", ActorKind::Agent, "org-b");
    let e_get = h
        .call(&org_b_agent, "skill_registry", json!({ "action": "get", "params": { "name": "tenant-pkg" } }))
        .await
        .unwrap_err();
    assert!(matches!(e_get, UaError::NotFound(_)), "{e_get:?}");

    let list = h.ok(&org_b_agent, "skill_registry", json!({ "action": "list", "params": {} })).await;
    assert_eq!(list["skills"], json!([]));

    let resolved = h
        .ok(
            &org_b_agent,
            "skill_registry",
            json!({ "action": "resolve", "params": { "agent_label": "builder-1" } }),
        )
        .await;
    assert_eq!(resolved["skills"], json!([]));
}

#[tokio::test]
async fn imported_python_hub_package_verifies_on_get_resolve_and_bundle() {
    let h = Harness::new();
    h.register_node().await;
    h.publish_bundle(json!({ "version": "v1" })).await;

    let md = valid_skill_md("py-imported", "");
    let script = "#!/bin/sh\necho from-python\n";
    let template = "Hello {{name}}\n";

    // Build an exact Python-hub package_manifest (including mode 0o755 = 493 on scripts/run.sh).
    let manifest = json!({
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "files": [
            {
                "path": "SKILL.md",
                "sha256": content_hash(&md),
                "bytes": md.len(),
                "mode": 420,
            },
            {
                "path": "scripts/run.sh",
                "sha256": content_hash(script),
                "bytes": script.len(),
                "mode": 493,
            },
            {
                "path": "templates/msg.txt",
                "sha256": content_hash(template),
                "bytes": template.len(),
                "mode": 420,
            },
        ],
    });
    let manifest_json = py_dumps(&manifest, None);
    let pkg_hash = content_hash(&manifest_json);
    let payload_json = py_dumps(
        &json!({
            "SKILL.md": BASE64.encode(md.as_bytes()),
            "scripts/run.sh": BASE64.encode(script.as_bytes()),
            "templates/msg.txt": BASE64.encode(template.as_bytes()),
        }),
        None,
    );

    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO skill_versions (org_id, name, version, content_hash, source, content, \
                 published_by, published_at, package_manifest, package_payload) \
                 VALUES ('default', 'py-imported', 1, ?1, 'skills/py-imported/SKILL.md', ?2, \
                 'operator', '2026-01-01T00:00:00+00:00', ?3, ?4)",
                params![pkg_hash, md, manifest_json, payload_json],
            )?;
            Ok(())
        })
        .unwrap();

    // get verifies every member of the imported Python package.
    let got =
        h.ok(&ops(), "skill_registry", json!({ "action": "get", "params": { "name": "py-imported" } })).await;
    assert_eq!(got["content_hash"], pkg_hash);
    assert_eq!(got["files"].as_array().unwrap().len(), 3);

    // Assign and verify resolve + harness_config bundle serve it cleanly.
    h.gated(
        &ops(),
        "skill_registry",
        json!({ "action": "assign", "params": { "skill_name": "py-imported", "target": "builder-1" } }),
    )
    .await;
    let resolved = h
        .ok(
            &device(),
            "skill_registry",
            json!({ "action": "resolve", "params": { "agent_label": "builder-1" } }),
        )
        .await;
    assert_eq!(resolved["skills"][0]["name"], "py-imported");
    assert_eq!(resolved["skills"][0]["hash"], pkg_hash);
    assert_eq!(resolved["skills"][0]["files"].as_array().unwrap().len(), 3);

    let cfg = h.ok(&device(), "node_config", json!({ "node": NODE })).await;
    assert_eq!(cfg["assigned_skills"][0]["included"], true, "{cfg}");
    assert_eq!(cfg["bundle"]["skills"][0]["files"].as_array().unwrap().len(), 3, "{cfg}");
}
