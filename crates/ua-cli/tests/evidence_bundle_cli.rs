//! End-to-end CLI tests for `ua evidence export`, offline `ua evidence sign --bundle`,
//! and offline `ua evidence verify --bundle` (`docs/evidence-export.md`, S3 + S4).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;

fn ua_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ua")
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("ua-store/tests/fixtures/evidence_bundles")
}

fn run_ua(home: &Path, args: &[&str]) -> Output {
    Command::new(ua_bin())
        .env("UA_HOME", home)
        .env_remove("UA_CONFIG")
        .env_remove("UA_AGENT_LABEL")
        .args(args)
        .output()
        .expect("spawn ua")
}

fn json_stdout(out: &Output) -> Value {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!("stdout not JSON ({e}):\nstdout:\n{text}\nstderr:\n{}", String::from_utf8_lossy(&out.stderr))
    })
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Proves that `ua evidence verify --bundle` and `ua evidence sign --bundle`
/// never open or create a hub database or write anything into `$UA_HOME`.
#[test]
fn offline_verify_and_sign_bundle_never_open_or_create_hub_db() {
    let empty_home = tempdir().unwrap();
    let root = fixtures_root();
    let trust = root.join("trust.json");

    // 1. Verify good_hub completely offline against an empty UA_HOME.
    let out = run_ua(
        empty_home.path(),
        &[
            "evidence",
            "verify",
            "--bundle",
            root.join("good_hub").to_str().unwrap(),
            "--trust-file",
            trust.to_str().unwrap(),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json_stdout(&out);
    assert_eq!(v["ok"], true);
    assert_eq!(v["integrity"]["status"], "verified");
    assert_eq!(v["authorship"]["status"], "verified");
    assert_eq!(v["completeness"]["status"], "verified");
    assert!(
        std::fs::read_dir(empty_home.path()).unwrap().next().is_none(),
        "UA_HOME must remain completely empty after `ua evidence verify --bundle`"
    );

    // 2. Verify exit code 1 (refused) on flipped_byte, UA_HOME still empty.
    let out = run_ua(
        empty_home.path(),
        &[
            "evidence",
            "verify",
            "--bundle",
            root.join("flipped_byte").to_str().unwrap(),
            "--trust-file",
            trust.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json_stdout(&out)["reason"], "file_digest_mismatch");

    // 3. Verify exit code 2 (cannot verify) on unknown_key, unanchored, and revoked key.
    let out = run_ua(
        empty_home.path(),
        &[
            "evidence",
            "verify",
            "--bundle",
            root.join("unknown_key").to_str().unwrap(),
            "--trust-file",
            trust.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json_stdout(&out)["reason"], "unknown_key");

    let out = run_ua(
        empty_home.path(),
        &["evidence", "verify", "--bundle", root.join("good_hub").to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json_stdout(&out)["reason"], "unanchored");

    let out = run_ua(
        empty_home.path(),
        &[
            "evidence",
            "verify",
            "--bundle",
            root.join("good_hub").to_str().unwrap(),
            "--trust-file",
            trust.to_str().unwrap(),
            "--revoked-key-id",
            "k-fixture-1",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json_stdout(&out)["reason"], "key_revoked");

    // 4. Offline sign --bundle with an empty UA_HOME must also leave UA_HOME empty.
    let work = tempdir().unwrap();
    let key_path = work.path().join("op.key");
    let gen_out =
        run_ua(empty_home.path(), &["evidence", "key-generate", "--out", key_path.to_str().unwrap()]);
    assert_eq!(gen_out.status.code(), Some(0));

    let copied_bundle = work.path().join("bundle");
    copy_dir_recursive(&root.join("good_hub"), &copied_bundle);
    std::fs::remove_file(copied_bundle.join("manifest.sig")).unwrap();

    let signed = run_ua(
        empty_home.path(),
        &[
            "evidence",
            "sign",
            "--key-file",
            key_path.to_str().unwrap(),
            "--bundle",
            copied_bundle.to_str().unwrap(),
        ],
    );
    assert_eq!(
        signed.status.code(),
        Some(0),
        "offline sign --bundle failed:\nstderr:\n{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    assert!(copied_bundle.join("manifest.sig").exists());
    assert!(
        std::fs::read_dir(empty_home.path()).unwrap().next().is_none(),
        "UA_HOME must remain completely empty after offline key-generate, sign --bundle, and verify --bundle"
    );
}

/// Full end-to-end hub + org export -> offline sign -> offline verify workflow
/// across the real `ua` binary.
#[test]
fn end_to_end_export_offline_sign_and_verify_hub_and_org_bundles() {
    let hub_home = tempdir().unwrap();
    let offline_home = tempdir().unwrap();
    let work = tempdir().unwrap();

    // 1. Operator generates key offline.
    let key_file = work.path().join("operator.key");
    let gen_out =
        run_ua(offline_home.path(), &["evidence", "key-generate", "--out", key_file.to_str().unwrap()]);
    assert_eq!(gen_out.status.code(), Some(0));
    let pub_key = json_stdout(&gen_out)["public_key"].as_str().unwrap().to_string();

    // 2. Hub registers public key (this creates the hub DB and writes an event_log row).
    let add =
        run_ua(hub_home.path(), &["evidence", "key-add", "--key-id", "k-e2e-1", "--public-key", &pub_key]);
    assert_eq!(add.status.code(), Some(0));

    // Read latest ledger seq/hash from the hub DB via sqlite to create a hub checkpoint.
    let db_path = hub_home.path().join("ua.db");
    let (head_seq, head_hash): (i64, String) = {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.query_row("SELECT seq, entry_hash FROM event_log ORDER BY seq DESC LIMIT 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap()
    };

    // 3. Create + sign + attach `org` checkpoint using `--derive` (default org).
    let org_cp_file = work.path().join("org-cp.json");
    let org_cp_out = run_ua(
        hub_home.path(),
        &[
            "evidence",
            "checkpoint",
            "--id",
            "cp-e2e-org",
            "--class",
            "org",
            "--org",
            "default",
            "--key-id",
            "k-e2e-1",
            "--window-from",
            "2020-01-01T00:00:00Z",
            "--window-to",
            "2099-12-31T23:59:59Z",
            "--derive",
            "--out",
            org_cp_file.to_str().unwrap(),
        ],
    );
    assert_eq!(
        org_cp_out.status.code(),
        Some(0),
        "org checkpoint failed:\nstderr:\n{}",
        String::from_utf8_lossy(&org_cp_out.stderr)
    );
    // `ua evidence checkpoint` freezes the export snapshot in the same
    // transaction (review M04).
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM evidence_export_snapshot WHERE checkpoint_id = 'cp-e2e-org'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "the checkpoint command must freeze its export snapshot");
    }
    let org_sig_out = run_ua(
        offline_home.path(),
        &[
            "evidence",
            "sign",
            "--key-file",
            key_file.to_str().unwrap(),
            "--checkpoint-file",
            org_cp_file.to_str().unwrap(),
        ],
    );
    assert_eq!(org_sig_out.status.code(), Some(0));
    let org_sig = String::from_utf8_lossy(&org_sig_out.stdout).trim().to_string();
    let att_org = run_ua(
        hub_home.path(),
        &["evidence", "attach", "--checkpoint", "cp-e2e-org", "--signature", &org_sig],
    );
    assert_eq!(att_org.status.code(), Some(0));

    // 4. Create + sign + attach `hub` checkpoint covering the latest seq (after org checkpoint events).
    let (latest_seq, latest_hash): (i64, String) = {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.query_row("SELECT seq, entry_hash FROM event_log ORDER BY seq DESC LIMIT 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap()
    };
    assert!(latest_seq >= head_seq);
    let _ = head_hash;

    let hub_cp_file = work.path().join("hub-cp.json");
    let hub_cp_out = run_ua(
        hub_home.path(),
        &[
            "evidence",
            "checkpoint",
            "--id",
            "cp-e2e-hub",
            "--class",
            "hub",
            "--key-id",
            "k-e2e-1",
            "--seq",
            &latest_seq.to_string(),
            "--hash",
            &latest_hash,
            "--out",
            hub_cp_file.to_str().unwrap(),
        ],
    );
    assert_eq!(hub_cp_out.status.code(), Some(0));
    let hub_sig_out = run_ua(
        offline_home.path(),
        &[
            "evidence",
            "sign",
            "--key-file",
            key_file.to_str().unwrap(),
            "--checkpoint-file",
            hub_cp_file.to_str().unwrap(),
        ],
    );
    assert_eq!(hub_sig_out.status.code(), Some(0));
    let hub_sig = String::from_utf8_lossy(&hub_sig_out.stdout).trim().to_string();
    let att_hub = run_ua(
        hub_home.path(),
        &["evidence", "attach", "--checkpoint", "cp-e2e-hub", "--signature", &hub_sig],
    );
    assert_eq!(att_hub.status.code(), Some(0));

    // 5. Export both bundles on the hub (must NOT write manifest.sig!).
    let hub_bundle = work.path().join("bundle-hub");
    let org_bundle = work.path().join("bundle-org");
    let exp_hub = run_ua(
        hub_home.path(),
        &["evidence", "export", "--checkpoint", "cp-e2e-hub", "--out", hub_bundle.to_str().unwrap()],
    );
    assert_eq!(
        exp_hub.status.code(),
        Some(0),
        "hub export failed:\nstderr:\n{}",
        String::from_utf8_lossy(&exp_hub.stderr)
    );
    assert!(!hub_bundle.join("manifest.sig").exists(), "hub export must never write manifest.sig");

    let exp_org = run_ua(
        hub_home.path(),
        &["evidence", "export", "--checkpoint", "cp-e2e-org", "--out", org_bundle.to_str().unwrap()],
    );
    assert_eq!(
        exp_org.status.code(),
        Some(0),
        "org export failed:\nstderr:\n{}",
        String::from_utf8_lossy(&exp_org.stderr)
    );
    assert!(!org_bundle.join("manifest.sig").exists(), "hub export must never write manifest.sig");

    // 6. Sign both bundles offline.
    for dir in [&hub_bundle, &org_bundle] {
        let s = run_ua(
            offline_home.path(),
            &[
                "evidence",
                "sign",
                "--key-file",
                key_file.to_str().unwrap(),
                "--bundle",
                dir.to_str().unwrap(),
            ],
        );
        assert_eq!(s.status.code(), Some(0), "sign failed: {}", String::from_utf8_lossy(&s.stderr));
    }

    // 7. Verify hub bundle offline against pinned anchor key -> exit 0!
    let v_hub = run_ua(
        offline_home.path(),
        &[
            "evidence",
            "verify",
            "--bundle",
            hub_bundle.to_str().unwrap(),
            "--anchor-key",
            &pub_key,
            "--anchor-key-id",
            "k-e2e-1",
        ],
    );
    assert_eq!(
        v_hub.status.code(),
        Some(0),
        "hub verify failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&v_hub.stdout),
        String::from_utf8_lossy(&v_hub.stderr)
    );
    assert_eq!(json_stdout(&v_hub)["completeness"]["status"], "verified");

    // 8. Verify org bundle alone -> exit 0, completeness = unverified.
    let v_org = run_ua(
        offline_home.path(),
        &[
            "evidence",
            "verify",
            "--bundle",
            org_bundle.to_str().unwrap(),
            "--anchor-key",
            &pub_key,
            "--anchor-key-id",
            "k-e2e-1",
        ],
    );
    assert_eq!(v_org.status.code(), Some(0));
    assert_eq!(json_stdout(&v_org)["completeness"]["status"], "unverified");

    // 9. Verify org bundle WITH --hub-bundle -> exit 0, completeness = verified!
    let v_org_cc = run_ua(
        offline_home.path(),
        &[
            "evidence",
            "verify",
            "--bundle",
            org_bundle.to_str().unwrap(),
            "--anchor-key",
            &pub_key,
            "--anchor-key-id",
            "k-e2e-1",
            "--hub-bundle",
            hub_bundle.to_str().unwrap(),
        ],
    );
    assert_eq!(
        v_org_cc.status.code(),
        Some(0),
        "org verify with --hub-bundle failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&v_org_cc.stdout),
        String::from_utf8_lossy(&v_org_cc.stderr)
    );
    assert_eq!(json_stdout(&v_org_cc)["completeness"]["status"], "verified");

    // Offline UA_HOME stayed 100% empty through all offline steps!
    assert!(std::fs::read_dir(offline_home.path()).unwrap().next().is_none());
}

/// `sign --bundle` runs the verifier's non-authorship checks first and refuses
/// to sign a bundle the verifier would refuse (review B-B3): a private record,
/// or an extra file listed in the manifest. A refused sign leaves the old
/// `manifest.sig` untouched.
#[test]
fn sign_bundle_refuses_a_bundle_the_verifier_refuses() {
    let empty_home = tempdir().unwrap();
    let work = tempdir().unwrap();
    let root = fixtures_root();
    let key_path = work.path().join("op.key");
    let keygen =
        run_ua(empty_home.path(), &["evidence", "key-generate", "--out", key_path.to_str().unwrap()]);
    assert_eq!(keygen.status.code(), Some(0));

    // The checked-in private_record fixture has valid hashes but a private label.
    let private = work.path().join("private");
    copy_dir_recursive(&root.join("private_record"), &private);
    let sig_before = std::fs::read(private.join("manifest.sig")).unwrap();
    let out = run_ua(
        empty_home.path(),
        &[
            "evidence",
            "sign",
            "--key-file",
            key_path.to_str().unwrap(),
            "--bundle",
            private.to_str().unwrap(),
        ],
    );
    assert_ne!(out.status.code(), Some(0), "signing a refused bundle must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("forbidden_private_content"), "stderr: {stderr}");
    assert_eq!(std::fs::read(private.join("manifest.sig")).unwrap(), sig_before);

    // An extra file listed in the manifest with a correct hash.
    let extra = work.path().join("extra");
    copy_dir_recursive(&root.join("good_hub"), &extra);
    std::fs::create_dir_all(extra.join("notes")).unwrap();
    std::fs::write(extra.join("notes/ops.txt"), b"operator notes").unwrap();
    let mp = extra.join("manifest.json");
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&mp).unwrap()).unwrap();
    let sha = ua_store::evidence_bundle::sha256_hex(b"operator notes");
    manifest["files"]["notes/ops.txt"] = Value::String(sha);
    let m: ua_store::evidence_bundle::BundleManifest = serde_json::from_value(manifest).unwrap();
    let mut m = m;
    m.digest = m.recompute_digest().unwrap();
    std::fs::write(&mp, ua_store::evidence_bundle::to_canonical_bytes(&m).unwrap()).unwrap();
    let out = run_ua(
        empty_home.path(),
        &["evidence", "sign", "--key-file", key_path.to_str().unwrap(), "--bundle", extra.to_str().unwrap()],
    );
    assert_ne!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unexpected_bundle_file"));
}
