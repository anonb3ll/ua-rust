//! CLI integration tests for `ua evidence` (S2 + follow-ups):
//! - offline `key-generate` and `sign --checkpoint-file` never touch or create a hub DB;
//! - `sign --checkpoint-file` recomputes the digest locally, displays fields and previous
//!   signed checkpoint head, refuses tampered digests, and checks `--prev-checkpoint`
//!   continuity;
//! - `checkpoint` refuses `--org` on `hub`, refuses unknown `(seq, hash)` against the
//!   ledger, and refuses unknown orgs on `org`;
//! - `attach` verifies the signature before storing it (so a wrong signature does not
//!   lock the row);
//! - `verify` returns exit codes `0` (verified), `1` (refused), `2` (cannot verify),
//!   trims `--anchor-key`, supports `--revoked-key-id` and `--trust-file`, and refuses a
//!   database written by a newer build.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn ua(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ua"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("UA_HOME", home)
        .env("UA_ENFORCE_AUTH", "false")
        .env("UA_LOG", "warn")
        .env("NO_COLOR", "1");
    cmd
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn init_hub(home: &Path) {
    let init = ua(home).args(["init", "--home", home.to_str().unwrap(), "--json"]).output().unwrap();
    assert!(init.status.success(), "init: {}", text(&init.stderr));
    // Touch the hub once so the schema is applied and the ledger has at least one row.
    let task = ua(home).args(["call", "task_add", r#"{"title":"seed event"}"#]).output().unwrap();
    assert!(task.status.success(), "task_add: {}", text(&task.stderr));
}

fn latest_ledger_head(home: &Path) -> (i64, String) {
    let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
    conn.query_row(
        "SELECT seq, entry_hash FROM event_log WHERE entry_hash IS NOT NULL ORDER BY seq DESC LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap()
}

#[test]
fn offline_signing_continuity_and_exit_codes() {
    let root = tempfile::tempdir().unwrap();
    let hub_home = root.path().join("hub");
    let offline_home = root.path().join("offline-box");
    std::fs::create_dir_all(&offline_home).unwrap();
    init_hub(&hub_home);

    // 1. Offline key generation creates no hub database in offline_home.
    let key1_path = offline_home.join("op-k1.key");
    let keygen1 = ua(&offline_home)
        .args(["evidence", "key-generate", "--out", key1_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(keygen1.status.success(), "{}", text(&keygen1.stderr));
    assert!(!offline_home.join("ua.db").exists(), "key-generate must not create a hub DB");
    let pk1 =
        serde_json::from_slice::<Value>(&keygen1.stdout).unwrap()["public_key"].as_str().unwrap().to_string();

    let key2_path = offline_home.join("op-k2.key");
    let keygen2 = ua(&offline_home)
        .args(["evidence", "key-generate", "--out", key2_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(keygen2.status.success(), "{}", text(&keygen2.stderr));
    let pk2 =
        serde_json::from_slice::<Value>(&keygen2.stdout).unwrap()["public_key"].as_str().unwrap().to_string();

    // Register both public keys on the hub.
    for (id, pk) in [("k1", &pk1), ("k2", &pk2)] {
        let add =
            ua(&hub_home).args(["evidence", "key-add", "--key-id", id, "--public-key", pk]).output().unwrap();
        assert!(add.status.success(), "{}", text(&add.stderr));
    }

    let (seq1, hash1) = latest_ledger_head(&hub_home);

    // 2. Hub checkpoint refuses --org, and refuses a bogus seq/hash.
    let hub_with_org = ua(&hub_home)
        .args([
            "evidence",
            "checkpoint",
            "--class",
            "hub",
            "--org",
            "default",
            "--key-id",
            "k1",
            "--seq",
            &seq1.to_string(),
            "--hash",
            &hash1,
        ])
        .output()
        .unwrap();
    assert!(!hub_with_org.status.success());
    assert!(text(&hub_with_org.stderr).contains("--org is only valid for an org checkpoint"));

    let bad_seq = ua(&hub_home)
        .args([
            "evidence",
            "checkpoint",
            "--class",
            "hub",
            "--key-id",
            "k1",
            "--seq",
            "99999",
            "--hash",
            &hash1,
        ])
        .output()
        .unwrap();
    assert!(!bad_seq.status.success());
    assert!(text(&bad_seq.stderr).contains("no hashed row at seq 99999"));

    // Org checkpoint with unknown organization is refused.
    let bad_org = ua(&hub_home)
        .args([
            "evidence",
            "checkpoint",
            "--class",
            "org",
            "--org",
            "nonexistent-org",
            "--key-id",
            "k1",
            "--window-from",
            "2026-11-01T00:00:00Z",
            "--window-to",
            "2026-11-02T00:00:00Z",
            "--global-from",
            "g0",
            "--head",
            "g1",
            "--row-count",
            "1",
            "--chain",
            "c1",
        ])
        .output()
        .unwrap();
    assert!(!bad_org.status.success());
    assert!(text(&bad_org.stderr).contains("does not exist"));

    // 3. Create hub checkpoint #1 with --out.
    let cp1_file = root.path().join("cp1.json");
    let cp1_out = ua(&hub_home)
        .args([
            "evidence",
            "checkpoint",
            "--id",
            "cp-1",
            "--class",
            "hub",
            "--key-id",
            "k1",
            "--seq",
            &seq1.to_string(),
            "--hash",
            &hash1,
            "--out",
            cp1_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(cp1_out.status.success(), "{}", text(&cp1_out.stderr));
    let cp1_json: Value = serde_json::from_slice(&cp1_out.stdout).unwrap();
    let cp1_digest = cp1_json["digest"].as_str().unwrap().to_string();

    // Unsigned checkpoint exits 2 (cannot verify).
    let unsigned = ua(&hub_home).args(["evidence", "verify", "--checkpoint", "cp-1"]).output().unwrap();
    assert_eq!(unsigned.status.code(), Some(2), "{}", text(&unsigned.stdout));
    assert_eq!(serde_json::from_slice::<Value>(&unsigned.stdout).unwrap()["state"], "unsigned");

    // 4. Sign offline with --checkpoint-file: recomputes digest, displays fields, never creates DB.
    // First confirm tampered digest in file is refused before signing.
    let tampered_file = root.path().join("cp1-tampered.json");
    let mut tampered_val: Value = serde_json::from_slice(&std::fs::read(&cp1_file).unwrap()).unwrap();
    tampered_val["digest"] = Value::String("0".repeat(64));
    std::fs::write(&tampered_file, serde_json::to_vec_pretty(&tampered_val).unwrap()).unwrap();
    let tampered_sign = ua(&offline_home)
        .args([
            "evidence",
            "sign",
            "--key-file",
            key1_path.to_str().unwrap(),
            "--checkpoint-file",
            tampered_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!tampered_sign.status.success());
    assert!(text(&tampered_sign.stderr).contains("refusing to sign"));

    // Sign with the wrong key first to prove `attach` verifies before storing.
    let wrong_sign = ua(&offline_home)
        .args([
            "evidence",
            "sign",
            "--key-file",
            key2_path.to_str().unwrap(),
            "--checkpoint-file",
            cp1_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(wrong_sign.status.success(), "{}", text(&wrong_sign.stderr));
    let wrong_sig = text(&wrong_sign.stdout).trim().to_string();
    let bad_attach = ua(&hub_home)
        .args(["evidence", "attach", "--checkpoint", "cp-1", "--signature", &wrong_sig])
        .output()
        .unwrap();
    assert!(!bad_attach.status.success());
    assert!(text(&bad_attach.stderr).contains("signature does not verify"));

    // Sign with the real key offline.
    let sign1 = ua(&offline_home)
        .args([
            "evidence",
            "sign",
            "--key-file",
            key1_path.to_str().unwrap(),
            "--checkpoint-file",
            cp1_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(sign1.status.success(), "{}", text(&sign1.stderr));
    assert!(!offline_home.join("ua.db").exists(), "sign must not create a hub DB");
    let sign1_stderr = text(&sign1.stderr);
    assert!(sign1_stderr.contains("cp-1"), "{sign1_stderr}");
    assert!(sign1_stderr.contains(&hash1), "{sign1_stderr}");
    assert!(sign1_stderr.contains(&cp1_digest), "{sign1_stderr}");
    assert!(sign1_stderr.contains("previous signed checkpoint: none"), "{sign1_stderr}");
    let sig1 = text(&sign1.stdout).trim().to_string();

    // Attach real signature (still succeeds because the bad attach did not lock the row).
    let attach1 = ua(&hub_home)
        .args(["evidence", "attach", "--checkpoint", "cp-1", "--signature", &sig1])
        .output()
        .unwrap();
    assert!(attach1.status.success(), "{}", text(&attach1.stderr));

    // 5. Verify exit codes:
    // 2: missing checkpoint
    let missing = ua(&hub_home).args(["evidence", "verify", "--checkpoint", "no-such-cp"]).output().unwrap();
    assert_eq!(missing.status.code(), Some(2), "{}", text(&missing.stderr));

    // 2: valid_in_store_only (no anchor)
    let no_anchor = ua(&hub_home).args(["evidence", "verify", "--checkpoint", "cp-1"]).output().unwrap();
    assert_eq!(no_anchor.status.code(), Some(2), "{}", text(&no_anchor.stdout));
    assert_eq!(serde_json::from_slice::<Value>(&no_anchor.stdout).unwrap()["state"], "valid_in_store_only");

    // 0: valid with pinned anchor (with leading/trailing whitespace trimmed)
    let padded_pk1 = format!("  {} \n", pk1.to_uppercase());
    let ok_anchor = ua(&hub_home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-1",
            "--anchor-key",
            &padded_pk1,
            "--anchor-key-id",
            " k1 ",
        ])
        .output()
        .unwrap();
    assert_eq!(ok_anchor.status.code(), Some(0), "{}", text(&ok_anchor.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&ok_anchor.stdout).unwrap()["state"], "valid");

    // 1: refused (KeyMismatch: wrong anchor key; expected = anchor, found = store)
    let wrong_anchor = ua(&hub_home)
        .args(["evidence", "verify", "--checkpoint", "cp-1", "--anchor-key", &pk2, "--anchor-key-id", "k1"])
        .output()
        .unwrap();
    assert_eq!(wrong_anchor.status.code(), Some(1), "{}", text(&wrong_anchor.stdout));
    let mismatch_val: Value = serde_json::from_slice(&wrong_anchor.stdout).unwrap();
    assert_eq!(mismatch_val["state"], "key_mismatch");
    assert_eq!(mismatch_val["expected"], pk2);
    assert_eq!(mismatch_val["found"], pk1);

    // 2: verifier-side revocation via --revoked-key-id (even though DB key is not revoked)
    let revoked_flag = ua(&hub_home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-1",
            "--anchor-key",
            &pk1,
            "--anchor-key-id",
            "k1",
            "--revoked-key-id",
            "k1",
        ])
        .output()
        .unwrap();
    assert_eq!(revoked_flag.status.code(), Some(2), "{}", text(&revoked_flag.stdout));
    assert_eq!(serde_json::from_slice::<Value>(&revoked_flag.stdout).unwrap()["state"], "key_revoked");

    // 0 & 2: trust-file verification (rotation + revocation list + unknown key)
    let trust_ok = root.path().join("trust-ok.json");
    std::fs::write(
        &trust_ok,
        serde_json::to_vec_pretty(&serde_json::json!({
            "keys": [
                { "key_id": "k1", "public_key": pk1 },
                { "key_id": "k2", "public_key": pk2 }
            ],
            "revoked_key_ids": []
        }))
        .unwrap(),
    )
    .unwrap();
    let via_trust = ua(&hub_home)
        .args(["evidence", "verify", "--checkpoint", "cp-1", "--trust-file", trust_ok.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(via_trust.status.code(), Some(0), "{}", text(&via_trust.stderr));

    let trust_revoked = root.path().join("trust-revoked.json");
    std::fs::write(
        &trust_revoked,
        serde_json::to_vec_pretty(&serde_json::json!({
            "keys": [{ "key_id": "k1", "public_key": pk1 }],
            "revoked_key_ids": ["k1"]
        }))
        .unwrap(),
    )
    .unwrap();
    let via_trust_rev = ua(&hub_home)
        .args(["evidence", "verify", "--checkpoint", "cp-1", "--trust-file", trust_revoked.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(via_trust_rev.status.code(), Some(2), "{}", text(&via_trust_rev.stdout));
    assert_eq!(serde_json::from_slice::<Value>(&via_trust_rev.stdout).unwrap()["state"], "key_revoked");

    let trust_unknown = root.path().join("trust-unknown.json");
    std::fs::write(
        &trust_unknown,
        serde_json::to_vec_pretty(&serde_json::json!({
            "keys": [{ "key_id": "k2", "public_key": pk2 }]
        }))
        .unwrap(),
    )
    .unwrap();
    let via_trust_unk = ua(&hub_home)
        .args(["evidence", "verify", "--checkpoint", "cp-1", "--trust-file", trust_unknown.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(via_trust_unk.status.code(), Some(2), "{}", text(&via_trust_unk.stdout));
    assert_eq!(serde_json::from_slice::<Value>(&via_trust_unk.stdout).unwrap()["state"], "unknown_key");

    // 6. Continuity: create checkpoint #2 after new ledger event, verify `previous_signed` and `--prev-checkpoint`.
    let (seq2, hash2) = latest_ledger_head(&hub_home);
    assert!(seq2 > seq1);
    let cp2_file = root.path().join("cp2.json");
    let cp2_out = ua(&hub_home)
        .args([
            "evidence",
            "checkpoint",
            "--id",
            "cp-2",
            "--class",
            "hub",
            "--key-id",
            "k1",
            "--seq",
            &seq2.to_string(),
            "--hash",
            &hash2,
            "--out",
            cp2_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(cp2_out.status.success(), "{}", text(&cp2_out.stderr));
    let cp2_json: Value = serde_json::from_slice(&cp2_out.stdout).unwrap();
    assert_eq!(cp2_json["previous_signed"]["checkpoint_id"], "cp-1");
    assert_eq!(cp2_json["previous_signed"]["seq"], seq1);

    let sign2 = ua(&offline_home)
        .args([
            "evidence",
            "sign",
            "--key-file",
            key1_path.to_str().unwrap(),
            "--checkpoint-file",
            cp2_file.to_str().unwrap(),
            "--prev-checkpoint",
            cp1_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(sign2.status.success(), "{}", text(&sign2.stderr));
    let sign2_stderr = text(&sign2.stderr);
    assert!(sign2_stderr.contains("verified against --prev-checkpoint"), "{sign2_stderr}");
    assert!(sign2_stderr.contains("cp-1"), "{sign2_stderr}");
    assert!(sign2_stderr.contains(&hash1), "{sign2_stderr}");

    // Continuity refusal: signing cp1 with --prev-checkpoint cp2 (seq regression) fails.
    let regressed = ua(&offline_home)
        .args([
            "evidence",
            "sign",
            "--key-file",
            key1_path.to_str().unwrap(),
            "--checkpoint-file",
            cp1_file.to_str().unwrap(),
            "--prev-checkpoint",
            cp2_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!regressed.status.success());
    assert!(text(&regressed.stderr).contains("does not advance past previous seq"));

    // 7. Org checkpoint verifies as org_class_not_verifiable (exit 2).
    let org_cp = ua(&hub_home)
        .args([
            "evidence",
            "checkpoint",
            "--id",
            "cp-org-1",
            "--class",
            "org",
            "--org",
            "default",
            "--key-id",
            "k1",
            "--window-from",
            "2026-11-01T00:00:00Z",
            "--window-to",
            "2026-11-02T00:00:00Z",
            "--global-from",
            "g0",
            "--head",
            "g1",
            "--row-count",
            "1",
            "--chain",
            "c1",
        ])
        .output()
        .unwrap();
    assert!(org_cp.status.success(), "{}", text(&org_cp.stderr));
    let verify_org = ua(&hub_home).args(["evidence", "verify", "--checkpoint", "cp-org-1"]).output().unwrap();
    assert_eq!(verify_org.status.code(), Some(2), "{}", text(&verify_org.stdout));
    assert_eq!(
        serde_json::from_slice::<Value>(&verify_org.stdout).unwrap()["state"],
        "org_class_not_verifiable"
    );

    // 8. Tampered checkpoint row exits 1 (DigestMismatch).
    {
        let conn = rusqlite::Connection::open(hub_home.join("ua.db")).unwrap();
        conn.execute_batch(
            "DROP TRIGGER evidence_checkpoint_immutable;
             UPDATE evidence_checkpoint SET seq = seq + 1 WHERE checkpoint_id = 'cp-1';",
        )
        .unwrap();
    }
    let tampered = ua(&hub_home)
        .args(["evidence", "verify", "--checkpoint", "cp-1", "--anchor-key", &pk1, "--anchor-key-id", "k1"])
        .output()
        .unwrap();
    assert_eq!(tampered.status.code(), Some(1), "{}", text(&tampered.stdout));
    assert_eq!(serde_json::from_slice::<Value>(&tampered.stdout).unwrap()["state"], "digest_mismatch");
}

#[test]
fn newer_schema_refuses_db_evidence_commands_but_allows_offline_sign() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("hub");
    init_hub(&home);

    let key_path = root.path().join("op.key");
    let keygen =
        ua(&home).args(["evidence", "key-generate", "--out", key_path.to_str().unwrap()]).output().unwrap();
    assert!(keygen.status.success(), "{}", text(&keygen.stderr));
    let pk =
        serde_json::from_slice::<Value>(&keygen.stdout).unwrap()["public_key"].as_str().unwrap().to_string();
    assert!(
        ua(&home)
            .args(["evidence", "key-add", "--key-id", "k1", "--public-key", &pk])
            .output()
            .unwrap()
            .status
            .success()
    );
    let (seq, hash) = latest_ledger_head(&home);
    let cp_file = root.path().join("cp.json");
    assert!(
        ua(&home)
            .args([
                "evidence",
                "checkpoint",
                "--id",
                "cp-1",
                "--key-id",
                "k1",
                "--seq",
                &seq.to_string(),
                "--hash",
                &hash,
                "--out",
                cp_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Upgrade the DB with an unknown schema part.
    {
        let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
        conn.execute_batch(
            "INSERT INTO schema_parts (name, checksum, applied_at) \
             VALUES ('future.evidence.v9', 'x', '2026-11-26T00:00:00Z');",
        )
        .unwrap();
    }

    // DB-backed evidence commands are refused by the schema fence; `verify` specifically exits 2.
    for (args, want_code) in [
        (vec!["evidence", "key-list"], None),
        (vec!["evidence", "verify", "--checkpoint", "cp-1"], Some(2)),
        (vec!["evidence", "attach", "--checkpoint", "cp-1", "--signature", &"0".repeat(128)], None),
    ] {
        let out = ua(&home).args(&args).output().unwrap();
        let err = text(&out.stderr);
        assert!(!out.status.success(), "{args:?} must refuse: {err}");
        if let Some(code) = want_code {
            assert_eq!(out.status.code(), Some(code), "{args:?} must exit {code}: {err}");
        }
        assert!(err.contains("written by a newer build"), "{args:?}: {err}");
        assert!(err.contains("[future.evidence.v9]"), "{args:?}: {err}");
    }

    // Offline `sign --checkpoint-file` still works even with UA_HOME pointing at the newer DB.
    let sign = ua(&home)
        .args([
            "evidence",
            "sign",
            "--key-file",
            key_path.to_str().unwrap(),
            "--checkpoint-file",
            cp_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(sign.status.success(), "offline sign must ignore hub DB: {}", text(&sign.stderr));
}

#[test]
fn trust_file_unknown_anchor_field_exits_2_and_verify_catches_rewritten_history_under_newer_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("hub");
    init_hub(&home);

    let key_path = root.path().join("op.key");
    let keygen =
        ua(&home).args(["evidence", "key-generate", "--out", key_path.to_str().unwrap()]).output().unwrap();
    assert!(keygen.status.success(), "{}", text(&keygen.stderr));
    let pk =
        serde_json::from_slice::<Value>(&keygen.stdout).unwrap()["public_key"].as_str().unwrap().to_string();
    assert!(
        ua(&home)
            .args(["evidence", "key-add", "--key-id", "k1", "--public-key", &pk])
            .output()
            .unwrap()
            .status
            .success()
    );

    // 1. Write, sign, and attach cp-1 at seq1.
    let (seq1, hash1) = latest_ledger_head(&home);
    let cp1_file = root.path().join("cp1.json");
    assert!(
        ua(&home)
            .args([
                "evidence",
                "checkpoint",
                "--id",
                "cp-1",
                "--key-id",
                "k1",
                "--seq",
                &seq1.to_string(),
                "--hash",
                &hash1,
                "--out",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let sig1 = text(
        &ua(&home)
            .args([
                "evidence",
                "sign",
                "--key-file",
                key_path.to_str().unwrap(),
                "--checkpoint-file",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert!(
        ua(&home)
            .args(["evidence", "attach", "--checkpoint", "cp-1", "--signature", &sig1])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Unknown field inside a `TrustAnchor` entry in `--trust-file` is refused (exit 2).
    let bad_trust = root.path().join("bad-trust.json");
    std::fs::write(
        &bad_trust,
        serde_json::to_vec_pretty(&serde_json::json!({
            "keys": [{ "key_id": "k1", "public_key": pk, "revoked": true }]
        }))
        .unwrap(),
    )
    .unwrap();
    let bad_trust_out = ua(&home)
        .args(["evidence", "verify", "--checkpoint", "cp-1", "--trust-file", bad_trust.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(bad_trust_out.status.code(), Some(2), "{}", text(&bad_trust_out.stderr));
    assert!(text(&bad_trust_out.stderr).contains("unknown field"), "{}", text(&bad_trust_out.stderr));

    // 2. Attacker with SQL access rewrites `event_log` at seq1 and recomputes the entire hash
    //    chain through a newer seq2, then tricks the operator into signing cp-2 at seq2.
    {
        struct EventRow {
            seq: i64,
            ulid: String,
            channel: String,
            payload: String,
            originator: Option<String>,
            episode_id: Option<String>,
            causal_parent_id: Option<String>,
            created_at: String,
            dedupe_key: Option<String>,
        }
        let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
        conn.execute_batch("DROP TRIGGER event_log_no_update;").unwrap();
        let rows: Vec<EventRow> = {
            let mut stmt = conn
                .prepare(
                    "SELECT seq, ulid, channel, payload, originator, episode_id, causal_parent_id, \
                            created_at, dedupe_key \
                     FROM event_log ORDER BY seq ASC",
                )
                .unwrap();
            stmt.query_map([], |r| {
                Ok(EventRow {
                    seq: r.get(0)?,
                    ulid: r.get(1)?,
                    channel: r.get(2)?,
                    payload: r.get(3)?,
                    originator: r.get(4)?,
                    episode_id: r.get(5)?,
                    causal_parent_id: r.get(6)?,
                    created_at: r.get(7)?,
                    dedupe_key: r.get(8)?,
                })
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
        };
        let mut prev: Option<String> = None;
        for mut row in rows {
            if row.seq == seq1 {
                row.payload = r#"{"rewritten":true}"#.to_string();
            }
            let prev_val = prev.as_deref().unwrap_or(ua_store::ledger::GENESIS_HASH);
            let entry_hash = ua_store::ledger::compute_entry_hash(
                Some(prev_val),
                &row.ulid,
                &row.channel,
                &row.payload,
                row.originator.as_deref(),
                row.episode_id.as_deref(),
                row.causal_parent_id.as_deref(),
                &row.created_at,
                row.dedupe_key.as_deref(),
            );
            conn.execute(
                "UPDATE event_log SET payload = ?1, prev_hash = ?2, entry_hash = ?3 WHERE seq = ?4",
                rusqlite::params![row.payload, prev_val, entry_hash, row.seq],
            )
            .unwrap();
            prev = Some(entry_hash);
        }
    }

    let (seq2, hash2) = latest_ledger_head(&home);
    assert!(seq2 > seq1);
    let cp2_file = root.path().join("cp2.json");
    assert!(
        ua(&home)
            .args([
                "evidence",
                "checkpoint",
                "--id",
                "cp-2",
                "--key-id",
                "k1",
                "--seq",
                &seq2.to_string(),
                "--hash",
                &hash2,
                "--out",
                cp2_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let sig2 = text(
        &ua(&home)
            .args([
                "evidence",
                "sign",
                "--key-file",
                key_path.to_str().unwrap(),
                "--checkpoint-file",
                cp2_file.to_str().unwrap(),
                "--prev-checkpoint",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert!(
        ua(&home)
            .args(["evidence", "attach", "--checkpoint", "cp-2", "--signature", &sig2])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Even though cp-2's own signature and the rewritten event_log[1..=seq2] hash chain check out,
    // `verify --checkpoint cp-2` re-checks earlier signed hub checkpoint cp-1 against event_log[seq1]
    // and refuses with `ledger_mismatch` (exit 1).
    let verify_cp2 = ua(&home)
        .args(["evidence", "verify", "--checkpoint", "cp-2", "--anchor-key", &pk, "--anchor-key-id", "k1"])
        .output()
        .unwrap();
    assert_eq!(verify_cp2.status.code(), Some(1), "{}", text(&verify_cp2.stdout));
    let v2: Value = serde_json::from_slice(&verify_cp2.stdout).unwrap();
    assert_eq!(v2["state"], "ledger_mismatch", "{v2}");
    assert!(v2["reason"].as_str().unwrap().contains("cp-1"), "{v2}");

    // Read cp1's original fields from cp1.json for out-of-band `--trust-file` signed_checkpoints.
    let cp1_json: Value = serde_json::from_slice(&std::fs::read(&cp1_file).unwrap()).unwrap();
    let cp1_digest = cp1_json["digest"].as_str().unwrap().to_string();
    let trust_with_pinned = root.path().join("trust-pinned.json");
    std::fs::write(
        &trust_with_pinned,
        serde_json::to_vec_pretty(&serde_json::json!({
            "keys": [{ "key_id": "k1", "public_key": pk }],
            "signed_checkpoints": [{
                "checkpoint_id": "cp-1",
                "seq": seq1,
                "hash": hash1,
                "digest": cp1_digest,
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    // Variant A: attacker drops immutable trigger and rewrites cp-1.hash + cp-1.digest to match
    // the rewritten event_log[seq1]. Even WITHOUT `--prev-checkpoint`, `verify` checks cp-1's
    // signature against the pinned key and refuses (exit 1).
    {
        let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
        let rewritten_hash1: String =
            conn.query_row("SELECT entry_hash FROM event_log WHERE seq = ?1", [seq1], |r| r.get(0)).unwrap();
        let mut cp1: ua_store::evidence::Checkpoint =
            serde_json::from_value(cp1_json["checkpoint"].clone()).unwrap();
        cp1.hash = Some(rewritten_hash1.clone());
        let rewritten_digest1 = cp1.digest();
        conn.execute_batch("DROP TRIGGER evidence_checkpoint_immutable;").unwrap();
        conn.execute(
            "UPDATE evidence_checkpoint SET hash = ?1, digest = ?2 WHERE checkpoint_id = 'cp-1'",
            rusqlite::params![rewritten_hash1, rewritten_digest1],
        )
        .unwrap();
    }
    let var_a = ua(&home)
        .args(["evidence", "verify", "--checkpoint", "cp-2", "--anchor-key", &pk, "--anchor-key-id", "k1"])
        .output()
        .unwrap();
    assert_eq!(var_a.status.code(), Some(1), "Variant A must fail: {}", text(&var_a.stdout));
    let va_json: Value = serde_json::from_slice(&var_a.stdout).unwrap();
    assert_eq!(va_json["state"], "ledger_mismatch", "{va_json}");
    assert!(va_json["reason"].as_str().unwrap().contains("signature"), "{va_json}");

    // Variant C: attacker NULLs cp-1's signature. Refused when the operator supplies
    // `--prev-checkpoint cp1.json` OR `--trust-file` with `signed_checkpoints`.
    {
        let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
        conn.execute("UPDATE evidence_checkpoint SET signature = NULL WHERE checkpoint_id = 'cp-1'", [])
            .unwrap();
    }
    let var_c_flag = ua(&home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-2",
            "--anchor-key",
            &pk,
            "--anchor-key-id",
            "k1",
            "--prev-checkpoint",
            cp1_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        var_c_flag.status.code(),
        Some(1),
        "Variant C (--prev-checkpoint): {}",
        text(&var_c_flag.stdout)
    );
    let var_c_tf = ua(&home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-2",
            "--trust-file",
            trust_with_pinned.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(var_c_tf.status.code(), Some(1), "Variant C (trust file): {}", text(&var_c_tf.stdout));

    // Variant B: attacker drops delete trigger and deletes cp-1 entirely. Still refused when
    // `--prev-checkpoint cp1.json` OR `--trust-file` with `signed_checkpoints` is supplied.
    {
        let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
        conn.execute_batch("DROP TRIGGER evidence_checkpoint_no_delete;").unwrap();
        conn.execute("DELETE FROM evidence_checkpoint WHERE checkpoint_id = 'cp-1'", []).unwrap();
    }
    let var_b_flag = ua(&home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-2",
            "--anchor-key",
            &pk,
            "--anchor-key-id",
            "k1",
            "--prev-checkpoint",
            cp1_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        var_b_flag.status.code(),
        Some(1),
        "Variant B (--prev-checkpoint): {}",
        text(&var_b_flag.stdout)
    );
    let var_b_tf = ua(&home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-2",
            "--trust-file",
            trust_with_pinned.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(var_b_tf.status.code(), Some(1), "Variant B (trust file): {}", text(&var_b_tf.stdout));
}

#[test]
fn verify_with_prev_checkpoint_and_trust_file_signed_checkpoints_succeeds_when_intact_and_catches_delete_or_null()
 {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let key_path = root.path().join("op.key");

    let keygen =
        ua(&home).args(["evidence", "key-generate", "--out", key_path.to_str().unwrap()]).output().unwrap();
    assert!(keygen.status.success(), "{}", text(&keygen.stderr));
    let pk =
        serde_json::from_slice::<Value>(&keygen.stdout).unwrap()["public_key"].as_str().unwrap().to_string();

    assert!(ua(&home).args(["init"]).output().unwrap().status.success());
    assert!(
        ua(&home)
            .args(["evidence", "key-add", "--key-id", "k1", "--public-key", &pk])
            .output()
            .unwrap()
            .status
            .success()
    );

    let (seq1, hash1) = latest_ledger_head(&home);
    let cp1_file = root.path().join("cp1.json");
    assert!(
        ua(&home)
            .args([
                "evidence",
                "checkpoint",
                "--id",
                "cp-1",
                "--key-id",
                "k1",
                "--seq",
                &seq1.to_string(),
                "--hash",
                &hash1,
                "--out",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let sig1 = text(
        &ua(&home)
            .args([
                "evidence",
                "sign",
                "--key-file",
                key_path.to_str().unwrap(),
                "--checkpoint-file",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert!(
        ua(&home)
            .args(["evidence", "attach", "--checkpoint", "cp-1", "--signature", &sig1])
            .output()
            .unwrap()
            .status
            .success()
    );

    let (seq2, hash2) = latest_ledger_head(&home);
    assert!(seq2 > seq1);
    let cp2_file = root.path().join("cp2.json");
    assert!(
        ua(&home)
            .args([
                "evidence",
                "checkpoint",
                "--id",
                "cp-2",
                "--key-id",
                "k1",
                "--seq",
                &seq2.to_string(),
                "--hash",
                &hash2,
                "--out",
                cp2_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let sig2 = text(
        &ua(&home)
            .args([
                "evidence",
                "sign",
                "--key-file",
                key_path.to_str().unwrap(),
                "--checkpoint-file",
                cp2_file.to_str().unwrap(),
                "--prev-checkpoint",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert!(
        ua(&home)
            .args(["evidence", "attach", "--checkpoint", "cp-2", "--signature", &sig2])
            .output()
            .unwrap()
            .status
            .success()
    );

    let cp1_digest = serde_json::from_slice::<Value>(&std::fs::read(&cp1_file).unwrap()).unwrap()["digest"]
        .as_str()
        .unwrap()
        .to_string();
    let trust_file = root.path().join("trust.json");
    std::fs::write(
        &trust_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "keys": [{ "key_id": "k1", "public_key": pk }],
            "signed_checkpoints": [{
                "checkpoint_id": "cp-1",
                "seq": seq1,
                "hash": hash1,
                "digest": cp1_digest,
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    // Happy path: intact ledger + intact cp-1 passes with both `--prev-checkpoint` and `--trust-file`.
    let ok_flag = ua(&home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-2",
            "--anchor-key",
            &pk,
            "--anchor-key-id",
            "k1",
            "--prev-checkpoint",
            cp1_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(ok_flag.status.code(), Some(0), "{}", text(&ok_flag.stdout));
    let ok_tf = ua(&home)
        .args(["evidence", "verify", "--checkpoint", "cp-2", "--trust-file", trust_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(ok_tf.status.code(), Some(0), "{}", text(&ok_tf.stdout));

    // NULLing cp-1.signature without rewriting event_log is caught (exit 1).
    {
        let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
        conn.execute_batch("DROP TRIGGER evidence_checkpoint_immutable;").unwrap();
        conn.execute("UPDATE evidence_checkpoint SET signature = NULL WHERE checkpoint_id = 'cp-1'", [])
            .unwrap();
    }
    let nulled = ua(&home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-2",
            "--anchor-key",
            &pk,
            "--anchor-key-id",
            "k1",
            "--prev-checkpoint",
            cp1_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(nulled.status.code(), Some(1), "{}", text(&nulled.stdout));
    let nulled_v: Value = serde_json::from_slice(&nulled.stdout).unwrap();
    assert_eq!(nulled_v["state"], "ledger_mismatch", "{nulled_v}");
    assert!(nulled_v["reason"].as_str().unwrap().contains("no signature"), "{nulled_v}");

    // Deleting cp-1 without rewriting event_log is also caught (exit 1).
    {
        let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
        conn.execute_batch("DROP TRIGGER evidence_checkpoint_no_delete;").unwrap();
        conn.execute("DELETE FROM evidence_checkpoint WHERE checkpoint_id = 'cp-1'", []).unwrap();
    }
    let deleted = ua(&home)
        .args(["evidence", "verify", "--checkpoint", "cp-2", "--trust-file", trust_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(deleted.status.code(), Some(1), "{}", text(&deleted.stdout));
    let deleted_v: Value = serde_json::from_slice(&deleted.stdout).unwrap();
    assert_eq!(deleted_v["state"], "ledger_mismatch", "{deleted_v}");
    assert!(deleted_v["reason"].as_str().unwrap().contains("missing"), "{deleted_v}");
}

#[test]
fn anchor_mode_verify_succeeds_after_key_rotation_and_revocation_and_pinned_revoked_fails() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let key1_path = root.path().join("op1.key");
    let key2_path = root.path().join("op2.key");

    let g1 =
        ua(&home).args(["evidence", "key-generate", "--out", key1_path.to_str().unwrap()]).output().unwrap();
    assert!(g1.status.success(), "{}", text(&g1.stderr));
    let pk1 =
        serde_json::from_slice::<Value>(&g1.stdout).unwrap()["public_key"].as_str().unwrap().to_string();

    let g2 =
        ua(&home).args(["evidence", "key-generate", "--out", key2_path.to_str().unwrap()]).output().unwrap();
    assert!(g2.status.success(), "{}", text(&g2.stderr));
    let pk2 =
        serde_json::from_slice::<Value>(&g2.stdout).unwrap()["public_key"].as_str().unwrap().to_string();

    assert!(ua(&home).args(["init"]).output().unwrap().status.success());
    assert!(
        ua(&home)
            .args(["evidence", "key-add", "--key-id", "k1", "--public-key", &pk1])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Sign cp-1 with k1.
    let (seq1, hash1) = latest_ledger_head(&home);
    let cp1_file = root.path().join("cp1.json");
    assert!(
        ua(&home)
            .args([
                "evidence",
                "checkpoint",
                "--id",
                "cp-1",
                "--key-id",
                "k1",
                "--seq",
                &seq1.to_string(),
                "--hash",
                &hash1,
                "--out",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let sig1 = text(
        &ua(&home)
            .args([
                "evidence",
                "sign",
                "--key-file",
                key1_path.to_str().unwrap(),
                "--checkpoint-file",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert!(
        ua(&home)
            .args(["evidence", "attach", "--checkpoint", "cp-1", "--signature", &sig1])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Rotate: retire k1, add k2, sign cp-2 with k2.
    assert!(ua(&home).args(["evidence", "key-retire", "--key-id", "k1"]).output().unwrap().status.success());
    assert!(
        ua(&home)
            .args(["evidence", "key-add", "--key-id", "k2", "--public-key", &pk2])
            .output()
            .unwrap()
            .status
            .success()
    );
    let (seq2, hash2) = latest_ledger_head(&home);
    assert!(seq2 > seq1);
    let cp2_file = root.path().join("cp2.json");
    assert!(
        ua(&home)
            .args([
                "evidence",
                "checkpoint",
                "--id",
                "cp-2",
                "--key-id",
                "k2",
                "--seq",
                &seq2.to_string(),
                "--hash",
                &hash2,
                "--out",
                cp2_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let sig2 = text(
        &ua(&home)
            .args([
                "evidence",
                "sign",
                "--key-file",
                key2_path.to_str().unwrap(),
                "--checkpoint-file",
                cp2_file.to_str().unwrap(),
                "--prev-checkpoint",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert!(
        ua(&home)
            .args(["evidence", "attach", "--checkpoint", "cp-2", "--signature", &sig2])
            .output()
            .unwrap()
            .status
            .success()
    );

    // 1. Anchor-mode verify of cp-2 with only k2 succeeds (exit 0) and warns about cp-1 / k1.
    let v_rot = ua(&home)
        .args(["evidence", "verify", "--checkpoint", "cp-2", "--anchor-key", &pk2, "--anchor-key-id", "k2"])
        .output()
        .unwrap();
    assert_eq!(v_rot.status.code(), Some(0), "stdout={} stderr={}", text(&v_rot.stdout), text(&v_rot.stderr));
    let v_rot_json: Value = serde_json::from_slice(&v_rot.stdout).unwrap();
    assert_eq!(v_rot_json["state"], "valid", "{v_rot_json}");
    assert!(
        v_rot_json["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("cp-1")),
        "{v_rot_json}"
    );

    // 2. Trust file with both {k1, k2} verifies cp-2 with zero warnings (no warnings field in JSON).
    let trust_both = root.path().join("trust-both.json");
    std::fs::write(
        &trust_both,
        serde_json::to_vec_pretty(&serde_json::json!({
            "keys": [
                { "key_id": "k1", "public_key": pk1 },
                { "key_id": "k2", "public_key": pk2 }
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let v_both = ua(&home)
        .args(["evidence", "verify", "--checkpoint", "cp-2", "--trust-file", trust_both.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(v_both.status.code(), Some(0), "{}", text(&v_both.stdout));
    let v_both_json: Value = serde_json::from_slice(&v_both.stdout).unwrap();
    assert_eq!(v_both_json, serde_json::json!({ "state": "valid" }));

    // 3. Revoke k1 in DB only (without --revoked-key-id): anchor-mode verify of cp-2 with k2
    //    exits 2 (`witness_skipped`) because DB state alone must never relax a check.
    assert!(ua(&home).args(["evidence", "key-revoke", "--key-id", "k1"]).output().unwrap().status.success());
    let v_db_rev_only = ua(&home)
        .args(["evidence", "verify", "--checkpoint", "cp-2", "--anchor-key", &pk2, "--anchor-key-id", "k2"])
        .output()
        .unwrap();
    assert_eq!(
        v_db_rev_only.status.code(),
        Some(2),
        "stdout={} stderr={}",
        text(&v_db_rev_only.stdout),
        text(&v_db_rev_only.stderr)
    );
    let v_db_rev_json: Value = serde_json::from_slice(&v_db_rev_only.stdout).unwrap();
    assert_eq!(v_db_rev_json["state"], "witness_skipped", "{v_db_rev_json}");
    assert_eq!(v_db_rev_json["checkpoint_id"], "cp-1", "{v_db_rev_json}");
    assert_eq!(v_db_rev_json["key_id"], "k1", "{v_db_rev_json}");

    // 4. When the verifier explicitly revokes k1 (--revoked-key-id k1), anchor-mode verify of
    //    cp-2 with k2 succeeds (exit 0) with a warning that cp-1 was skipped by verifier trust.
    let v_rev = ua(&home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-2",
            "--anchor-key",
            &pk2,
            "--anchor-key-id",
            "k2",
            "--revoked-key-id",
            "k1",
        ])
        .output()
        .unwrap();
    assert_eq!(v_rev.status.code(), Some(0), "stdout={} stderr={}", text(&v_rev.stdout), text(&v_rev.stderr));
    let v_rev_json: Value = serde_json::from_slice(&v_rev.stdout).unwrap();
    assert_eq!(v_rev_json["state"], "valid", "{v_rev_json}");
    assert!(
        v_rev_json["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("cp-1") && w.as_str().unwrap().contains("verifier")),
        "{v_rev_json}"
    );

    // 5. Pinning cp-1 via `--prev-checkpoint` after k1 is revoked STILL fails hard (exit 2 key_revoked),
    //    even when `--revoked-key-id k1` is passed.
    let v_pinned_rev = ua(&home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-2",
            "--trust-file",
            trust_both.to_str().unwrap(),
            "--revoked-key-id",
            "k1",
            "--prev-checkpoint",
            cp1_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(v_pinned_rev.status.code(), Some(2), "{}", text(&v_pinned_rev.stdout));
    let v_pinned_rev_json: Value = serde_json::from_slice(&v_pinned_rev.stdout).unwrap();
    assert_eq!(v_pinned_rev_json["state"], "key_revoked", "{v_pinned_rev_json}");
    assert_eq!(v_pinned_rev_json["key_id"], "k1", "{v_pinned_rev_json}");
}

#[test]
fn db_revoked_key_cannot_hide_careless_rewrite_or_variant_a_over_cli() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let key1_path = root.path().join("op1.key");
    let key2_path = root.path().join("op2.key");

    let g1 =
        ua(&home).args(["evidence", "key-generate", "--out", key1_path.to_str().unwrap()]).output().unwrap();
    assert!(g1.status.success());
    let pk1 =
        serde_json::from_slice::<Value>(&g1.stdout).unwrap()["public_key"].as_str().unwrap().to_string();
    let g2 =
        ua(&home).args(["evidence", "key-generate", "--out", key2_path.to_str().unwrap()]).output().unwrap();
    assert!(g2.status.success());
    let pk2 =
        serde_json::from_slice::<Value>(&g2.stdout).unwrap()["public_key"].as_str().unwrap().to_string();

    assert!(ua(&home).args(["init"]).output().unwrap().status.success());
    assert!(
        ua(&home)
            .args(["evidence", "key-add", "--key-id", "k1", "--public-key", &pk1])
            .output()
            .unwrap()
            .status
            .success()
    );
    let (seq1, hash1) = latest_ledger_head(&home);
    let cp1_file = root.path().join("cp1.json");
    assert!(
        ua(&home)
            .args([
                "evidence",
                "checkpoint",
                "--id",
                "cp-1",
                "--key-id",
                "k1",
                "--seq",
                &seq1.to_string(),
                "--hash",
                &hash1,
                "--out",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let sig1 = text(
        &ua(&home)
            .args([
                "evidence",
                "sign",
                "--key-file",
                key1_path.to_str().unwrap(),
                "--checkpoint-file",
                cp1_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert!(
        ua(&home)
            .args(["evidence", "attach", "--checkpoint", "cp-1", "--signature", &sig1])
            .output()
            .unwrap()
            .status
            .success()
    );

    assert!(ua(&home).args(["evidence", "key-retire", "--key-id", "k1"]).output().unwrap().status.success());
    assert!(
        ua(&home)
            .args(["evidence", "key-add", "--key-id", "k2", "--public-key", &pk2])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Rewrite event_log at seq1, sign cp-2 with k2, and mark k1 revoked in SQLite (no trigger drop needed for revoked_at).
    {
        struct EventRow {
            seq: i64,
            ulid: String,
            channel: String,
            payload: String,
            originator: Option<String>,
            episode_id: Option<String>,
            causal_parent_id: Option<String>,
            created_at: String,
            dedupe_key: Option<String>,
        }
        let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
        conn.execute_batch("DROP TRIGGER event_log_no_update;").unwrap();
        let rows: Vec<EventRow> = {
            let mut stmt = conn
                .prepare(
                    "SELECT seq, ulid, channel, payload, originator, episode_id, causal_parent_id, \
                            created_at, dedupe_key \
                     FROM event_log ORDER BY seq ASC",
                )
                .unwrap();
            stmt.query_map([], |r| {
                Ok(EventRow {
                    seq: r.get(0)?,
                    ulid: r.get(1)?,
                    channel: r.get(2)?,
                    payload: r.get(3)?,
                    originator: r.get(4)?,
                    episode_id: r.get(5)?,
                    causal_parent_id: r.get(6)?,
                    created_at: r.get(7)?,
                    dedupe_key: r.get(8)?,
                })
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
        };
        let mut prev: Option<String> = None;
        for mut row in rows {
            if row.seq == seq1 {
                row.payload = r#"{"rewritten":true}"#.to_string();
            }
            let prev_val = prev.as_deref().unwrap_or(ua_store::ledger::GENESIS_HASH);
            let entry_hash = ua_store::ledger::compute_entry_hash(
                Some(prev_val),
                &row.ulid,
                &row.channel,
                &row.payload,
                row.originator.as_deref(),
                row.episode_id.as_deref(),
                row.causal_parent_id.as_deref(),
                &row.created_at,
                row.dedupe_key.as_deref(),
            );
            conn.execute(
                "UPDATE event_log SET payload = ?1, prev_hash = ?2, entry_hash = ?3 WHERE seq = ?4",
                rusqlite::params![row.payload, prev_val, entry_hash, row.seq],
            )
            .unwrap();
            prev = Some(entry_hash);
        }
        conn.execute("UPDATE evidence_key SET revoked_at = '2026-01-01T00:00:00Z' WHERE key_id = 'k1'", [])
            .unwrap();
    }

    let (seq2, hash2) = latest_ledger_head(&home);
    let cp2_file = root.path().join("cp2.json");
    assert!(
        ua(&home)
            .args([
                "evidence",
                "checkpoint",
                "--id",
                "cp-2",
                "--key-id",
                "k2",
                "--seq",
                &seq2.to_string(),
                "--hash",
                &hash2,
                "--out",
                cp2_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let sig2 = text(
        &ua(&home)
            .args([
                "evidence",
                "sign",
                "--key-file",
                key2_path.to_str().unwrap(),
                "--checkpoint-file",
                cp2_file.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert!(
        ua(&home)
            .args(["evidence", "attach", "--checkpoint", "cp-2", "--signature", &sig2])
            .output()
            .unwrap()
            .status
            .success()
    );

    let trust_both = root.path().join("trust-both.json");
    std::fs::write(
        &trust_both,
        serde_json::to_vec_pretty(&serde_json::json!({
            "keys": [
                { "key_id": "k1", "public_key": pk1 },
                { "key_id": "k2", "public_key": pk2 }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    // Careless rewrite with DB-revoked k1 MUST still exit 1 (`ledger_mismatch`), even if the
    // verifier passes `--revoked-key-id k1`!
    let careless = ua(&home)
        .args(["evidence", "verify", "--checkpoint", "cp-2", "--trust-file", trust_both.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(careless.status.code(), Some(1), "{}", text(&careless.stdout));
    assert_eq!(serde_json::from_slice::<Value>(&careless.stdout).unwrap()["state"], "ledger_mismatch");

    let careless_with_rev = ua(&home)
        .args([
            "evidence",
            "verify",
            "--checkpoint",
            "cp-2",
            "--anchor-key",
            &pk2,
            "--anchor-key-id",
            "k2",
            "--revoked-key-id",
            "k1",
        ])
        .output()
        .unwrap();
    assert_eq!(careless_with_rev.status.code(), Some(1), "{}", text(&careless_with_rev.stdout));
    assert_eq!(
        serde_json::from_slice::<Value>(&careless_with_rev.stdout).unwrap()["state"],
        "ledger_mismatch"
    );

    // Variant A with DB-revoked k1 MUST still exit 1 (`ledger_mismatch`) under trust {k1, k2}.
    {
        let conn = rusqlite::Connection::open(home.join("ua.db")).unwrap();
        let rewritten_hash1: String =
            conn.query_row("SELECT entry_hash FROM event_log WHERE seq = ?1", [seq1], |r| r.get(0)).unwrap();
        let cp1_json: Value = serde_json::from_slice(&std::fs::read(&cp1_file).unwrap()).unwrap();
        let mut cp1: ua_store::evidence::Checkpoint =
            serde_json::from_value(cp1_json["checkpoint"].clone()).unwrap();
        cp1.hash = Some(rewritten_hash1.clone());
        let rewritten_digest1 = cp1.digest();
        conn.execute_batch("DROP TRIGGER evidence_checkpoint_immutable;").unwrap();
        conn.execute(
            "UPDATE evidence_checkpoint SET hash = ?1, digest = ?2 WHERE checkpoint_id = 'cp-1'",
            rusqlite::params![rewritten_hash1, rewritten_digest1],
        )
        .unwrap();
    }
    let var_a = ua(&home)
        .args(["evidence", "verify", "--checkpoint", "cp-2", "--trust-file", trust_both.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(var_a.status.code(), Some(1), "{}", text(&var_a.stdout));
    assert_eq!(serde_json::from_slice::<Value>(&var_a.stdout).unwrap()["state"], "ledger_mismatch");
}
