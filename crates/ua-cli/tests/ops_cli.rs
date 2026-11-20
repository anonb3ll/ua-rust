//! Integration tests for `ua init`, `ua doctor`, `ua backup`, and `ua restore`.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn ua_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ua"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("UA_HOME", home)
        .env("NO_COLOR", "1");
    cmd
}

fn parse_stdout_json(out: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON on stdout ({e}):\nstdout:\n{stdout}\nstderr:\n{stderr}"))
}

#[test]
fn init_creates_valid_config_policy_and_initial_token_and_force_backs_up() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("hub-home");
    let workspace = root.path().join("work");

    // Non-interactive `ua init --agent operator` (human identity) must fail BEFORE
    // leaving `config.toml` behind on disk.
    let human_fail = ua_cmd(root.path())
        .args([
            "init",
            "--home",
            home.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--with-policy",
            "--agent",
            "operator",
        ])
        .output()
        .unwrap();
    assert!(!human_fail.status.success());
    assert!(!home.join("config.toml").exists(), "config.toml must not be left half-written");
    assert!(!home.join("policy.yaml").exists(), "policy.yaml must not be left half-written");

    let out = ua_cmd(root.path())
        .args([
            "init",
            "--home",
            home.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--with-policy",
            "--agent",
            "builder-1",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "ua init failed: stderr={}", String::from_utf8_lossy(&out.stderr));

    let rep = parse_stdout_json(&out);
    assert_eq!(rep["operator"], "operator");
    let tok = rep["issued_token"]["token"].as_str().expect("token returned");
    assert!(tok.starts_with("ua_"), "{tok}");

    let cfg_path = home.join("config.toml");
    let policy_path = home.join("policy.yaml");
    let db_path = home.join("ua.db");
    assert!(cfg_path.is_file());
    assert!(policy_path.is_file());
    assert!(db_path.is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&home).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&cfg_path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&policy_path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&db_path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let cfg = ua_core::Config::load_from(&cfg_path).unwrap();
    assert_eq!(cfg.workspace_root(), workspace);
    assert_eq!(cfg.policy_file.as_deref(), Some(policy_path.as_path()));
    let loaded_policy = ua_tools::policy::load(&policy_path).unwrap();
    assert_eq!(loaded_policy.rules.len(), 1);

    // Re-running without --force refuses and keeps config unchanged.
    let before = fs::read_to_string(&cfg_path).unwrap();
    let rerun =
        ua_cmd(root.path()).args(["init", "--home", home.to_str().unwrap(), "--json"]).output().unwrap();
    assert!(!rerun.status.success());
    let stderr = String::from_utf8_lossy(&rerun.stderr);
    assert!(stderr.contains("already exists"), "{stderr}");
    assert_eq!(fs::read_to_string(&cfg_path).unwrap(), before);

    // Re-running with --force backs up existing config.toml and policy.yaml.
    let forced = ua_cmd(root.path())
        .args(["init", "--home", home.to_str().unwrap(), "--with-policy", "--force", "--json"])
        .output()
        .unwrap();
    assert!(forced.status.success(), "stderr={}", String::from_utf8_lossy(&forced.stderr));
    let forced_rep = parse_stdout_json(&forced);
    let baks = forced_rep["backed_up_files"].as_array().unwrap();
    assert_eq!(baks.len(), 2, "{forced_rep}");
    for b in baks {
        let p = Path::new(b.as_str().unwrap());
        assert!(p.is_file());
    }
}

#[test]
fn doctor_checks_permissions_schema_drift_pre_restore_and_non_loopback_flag() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("hub-home");

    // On an uninitialized home, doctor warns (does not create home or ua.db)
    // and fails under --strict.
    let pre = ua_cmd(&home).args(["doctor", "--json"]).output().unwrap();
    assert!(pre.status.success(), "stdout={}", String::from_utf8_lossy(&pre.stdout));
    assert!(!home.exists(), "ua doctor must never create a missing home or DB");

    let pre_strict = ua_cmd(&home).args(["doctor", "--json", "--strict"]).output().unwrap();
    assert!(!pre_strict.status.success());

    let init = ua_cmd(&home)
        .args(["init", "--home", home.to_str().unwrap(), "--with-policy", "--agent", "builder-1", "--json"])
        .output()
        .unwrap();
    assert!(init.status.success(), "stderr={}", String::from_utf8_lossy(&init.stderr));

    let ok_out = ua_cmd(&home).args(["doctor", "--json", "--strict"]).output().unwrap();
    assert!(ok_out.status.success(), "doctor --strict failed:\n{}", String::from_utf8_lossy(&ok_out.stdout));
    let ok_rep = parse_stdout_json(&ok_out);
    assert_eq!(ok_rep["ok"], true);
    assert!(
        ok_rep["checks"].as_array().unwrap().iter().any(|c| c["name"] == "schema" && c["status"] == "pass")
    );

    // Container bind (0.0.0.0:8765 with public_url and enforce_auth=true) warns by
    // default under --strict, and passes with --allow-non-loopback.
    let nl_warn = ua_cmd(&home)
        .env("UA_BIND", "0.0.0.0:8765")
        .env("UA_PUBLIC_URL", "https://hub.example.com")
        .args(["doctor", "--json", "--strict"])
        .output()
        .unwrap();
    assert!(!nl_warn.status.success());
    let nl_ok = ua_cmd(&home)
        .env("UA_BIND", "0.0.0.0:8765")
        .env("UA_PUBLIC_URL", "https://hub.example.com")
        .args(["doctor", "--json", "--strict", "--allow-non-loopback"])
        .output()
        .unwrap();
    assert!(nl_ok.status.success(), "stdout={}", String::from_utf8_lossy(&nl_ok.stdout));

    // Loose DB mode (0644) triggers permissions warning.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let db = home.join("ua.db");
        fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
        let loose = ua_cmd(&home).args(["doctor", "--json", "--strict"]).output().unwrap();
        assert!(!loose.status.success());
        let rep = parse_stdout_json(&loose);
        assert!(
            rep["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["name"] == "permissions" && c["status"] == "warn")
        );
        fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Broken policy_file fails fail-closed check (exit 1).
    let policy_path = home.join("policy.yaml");
    let orig_policy = fs::read_to_string(&policy_path).unwrap();
    fs::write(&policy_path, "not: [valid: yaml").unwrap();
    let bad_pol = ua_cmd(&home).args(["doctor", "--json"]).output().unwrap();
    assert!(!bad_pol.status.success());
    let bad_pol_rep = parse_stdout_json(&bad_pol);
    assert!(
        bad_pol_rep["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "policy_file" && c["status"] == "fail")
    );
    fs::write(&policy_path, orig_policy).unwrap();

    // Schema drift fails `schema` check.
    let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
    let orig_sum: String = conn
        .query_row("SELECT checksum FROM schema_parts WHERE name = 'ledger.v1'", [], |r| r.get(0))
        .unwrap();
    conn.execute("UPDATE schema_parts SET checksum = 'bad' WHERE name = 'ledger.v1'", []).unwrap();
    drop(conn);
    let drifted = ua_cmd(&home).args(["doctor", "--json"]).output().unwrap();
    assert!(!drifted.status.success());
    let drift_rep = parse_stdout_json(&drifted);
    assert!(
        drift_rep["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "schema" && c["status"] == "fail")
    );
    let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
    conn.execute("UPDATE schema_parts SET checksum = ?1 WHERE name = 'ledger.v1'", [&orig_sum]).unwrap();

    // Tampered ledger fails ledger check (exit 1).
    conn.execute_batch(
        "DROP TRIGGER event_log_no_update; \
         UPDATE event_log SET payload = '{\"tampered\":true}' WHERE seq = 1;",
    )
    .unwrap();
    drop(conn);

    let tampered = ua_cmd(&home).args(["doctor", "--json"]).output().unwrap();
    assert!(!tampered.status.success());
    let tamp_rep = parse_stdout_json(&tampered);
    assert_eq!(tamp_rep["ok"], false);
    assert!(
        tamp_rep["checks"].as_array().unwrap().iter().any(|c| c["name"] == "ledger" && c["status"] == "fail")
    );
}

#[test]
fn backup_manifest_and_lock_protected_restore_roundtrip() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("hub-home");
    let db_path = home.join("ua.db");

    let init = ua_cmd(&home)
        .args(["init", "--home", home.to_str().unwrap(), "--agent", "builder-1", "--json"])
        .output()
        .unwrap();
    assert!(init.status.success(), "stderr={}", String::from_utf8_lossy(&init.stderr));

    // Insert an active UI session so we can test `--revoke-sessions` on restore.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO ui_sessions (id_hash, label, csrf, method, created_at, expires_at) \
             VALUES ('sess1', 'operator', 'csrf1', 'passkey', '2026-11-20T00:00:00+00:00', '2026-11-21T00:00:00+00:00')",
            [],
        )
        .unwrap();
    }

    // Online backup works even while a shared HubLock (like `ua serve`) is held.
    let shared_lock = ua_import::HubLock::acquire_shared(&db_path, "serve").unwrap();
    let bak_path = root.path().join("backups/ua-snap.db");
    let bak_out =
        ua_cmd(&home).args(["backup", "--to", bak_path.to_str().unwrap(), "--manifest"]).output().unwrap();
    assert!(bak_out.status.success(), "backup failed: stderr={}", String::from_utf8_lossy(&bak_out.stderr));
    let bak_rep = parse_stdout_json(&bak_out);
    let sha = bak_rep["sha256"].as_str().unwrap().to_string();
    assert_eq!(sha.len(), 64);

    let manifest_path = root.path().join("backups/ua-snap.db.sha256.json");
    assert!(manifest_path.is_file());
    let manifest: Value = serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["sha256"].as_str().unwrap(), sha);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&bak_path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&manifest_path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // Non-dry-run restore must refuse while the shared HubLock is held.
    let blocked = ua_cmd(&home)
        .args(["restore", "--from", bak_path.to_str().unwrap(), "--force", "--expected-sha256", &sha])
        .output()
        .unwrap();
    assert!(!blocked.status.success());
    let blocked_err = String::from_utf8_lossy(&blocked.stderr);
    assert!(blocked_err.contains("Stop them first"), "{blocked_err}");

    // Dry-run succeeds even before stopping (does not touch ua.db).
    let dry = ua_cmd(&home)
        .args(["restore", "--from", bak_path.to_str().unwrap(), "--dry-run", "--expected-sha256", &sha])
        .output()
        .unwrap();
    assert!(dry.status.success(), "stderr={}", String::from_utf8_lossy(&dry.stderr));
    let dry_rep = parse_stdout_json(&dry);
    assert_eq!(dry_rep["dry_run"], true);

    drop(shared_lock);

    // Non-dry-run restore must refuse without `--expected-sha256` (unless `--allow-unpinned`).
    let unpinned =
        ua_cmd(&home).args(["restore", "--from", bak_path.to_str().unwrap(), "--force"]).output().unwrap();
    assert!(!unpinned.status.success());
    assert!(String::from_utf8_lossy(&unpinned.stderr).contains("--expected-sha256"));

    // Issue a second token so live DB diverges (2 ledger rows vs 1 in backup).
    let tok2 = ua_cmd(&home).args(["token", "issue", "builder-2"]).output().unwrap();
    assert!(tok2.status.success(), "stderr={}", String::from_utf8_lossy(&tok2.stderr));

    // Wrong SHA-256 fails cleanly without replacing live DB.
    let bad_sha = "f".repeat(64);
    let mismatch = ua_cmd(&home)
        .args(["restore", "--from", bak_path.to_str().unwrap(), "--force", "--expected-sha256", &bad_sha])
        .output()
        .unwrap();
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("SHA-256 mismatch"));

    // Real restore succeeds with `--revoke-sessions`, writes `ops.restored` (ledger
    // count = 1 + 1 = 2), creates 0600 safety backup, and revokes `sess1`.
    let restored = ua_cmd(&home)
        .args([
            "restore",
            "--from",
            bak_path.to_str().unwrap(),
            "--force",
            "--expected-sha256",
            &sha,
            "--revoke-sessions",
        ])
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "restore failed: stderr={}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let rest_rep = parse_stdout_json(&restored);
    assert_eq!(rest_rep["dry_run"], false);
    assert_eq!(rest_rep["restored_event_seq"], 2);
    assert_eq!(rest_rep["revoked_sessions"]["ui_sessions"], 1);
    let safety = Path::new(rest_rep["safety_backup"].as_str().unwrap());
    assert!(safety.is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&db_path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(safety).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // Verify `ua doctor --json` sees leftover `.pre-restore-*.bak` warning, and passes once pruned.
    let doc_warn = ua_cmd(&home).args(["doctor", "--json", "--strict"]).output().unwrap();
    assert!(!doc_warn.status.success());
    let doc_warn_rep = parse_stdout_json(&doc_warn);
    assert!(
        doc_warn_rep["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "pre_restore_backups" && c["status"] == "warn")
    );
    fs::remove_file(safety).unwrap();

    let doc_clean = ua_cmd(&home).args(["doctor", "--json", "--strict"]).output().unwrap();
    assert!(doc_clean.status.success(), "stdout={}", String::from_utf8_lossy(&doc_clean.stdout));

    // Also confirm `--allow-unpinned` opts out when desired.
    let unpinned_ok = ua_cmd(&home)
        .args([
            "restore",
            "--from",
            bak_path.to_str().unwrap(),
            "--force",
            "--allow-unpinned",
            "--no-safety-backup",
        ])
        .output()
        .unwrap();
    assert!(unpinned_ok.status.success(), "stderr={}", String::from_utf8_lossy(&unpinned_ok.stderr));
}
