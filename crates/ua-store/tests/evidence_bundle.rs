//! Integration, fixture, mutation, and property tests for signed evidence
//! bundles and the standalone offline verifier (`docs/evidence-export.md`, S3+S4).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use rusqlite::params;
use serde_json::{Value, json};
use tempfile::tempdir;
use ua_store::db::Db;
use ua_store::evidence::{
    CHECKPOINT_CHECKS_PART, Checkpoint, CheckpointClass, KEY_STORE_PART, TrustAnchor, TrustFile, Window,
    checkpoint_attach, checkpoint_write, key_add,
};
use ua_store::evidence_bundle::{
    ApprovalReceipt, ArtifactIndexEntry, BundleCheckpointFile, BundleLedgerEvent, BundleManifest,
    BundleVerifyTrust, CLASS_APPROVALS_IN_DEFAULT_LEDGER, CLASS_CROSS_ORG_EVENTS, CLASS_FREE_TEXT_PAYLOAD,
    CLASS_PRIVATE_MESSAGES, CLASS_PRIVATE_RECORDS, CLASS_SCANNER_WITHHELD, CLASS_UNLISTED_PAYLOAD,
    CLASS_UNPARSEABLE_PAYLOAD, ClaimStatus, EXPORT_SNAPSHOT_PART, EvidenceRow, ExportBundleOptions,
    LABEL_PLACEHOLDER, PinnedHubHead, PinnedOrgHead, PolicyRevisionRecord, ProducerInfo, REDACTED_CHANNEL,
    WithheldReport, compute_org_window_checkpoint, export_bundle, load_verified_hub_cross_check,
    org_chain_fold, sha256_hex, snapshot_checkpoint, to_canonical_bytes, verify_bundle_dir,
    verify_bundle_dir_with_limits,
};
use ua_store::ledger::{
    self, EventInput, GENESIS_HASH, HASH_V1, HASH_V2, compute_entry_hash, compute_entry_hash_v2,
};

const FIXTURE_KEY_ID: &str = "k-fixture-1";
const FIXTURE_KEY_SEED: [u8; 32] = [0x42; 32];
const UNKNOWN_KEY_ID: &str = "k-unknown-99";
const UNKNOWN_KEY_SEED: [u8; 32] = [0x99; 32];

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/evidence_bundles")
}

fn signing_key(seed: [u8; 32]) -> (SigningKey, String) {
    let sk = SigningKey::from_bytes(&seed);
    let pk = hex::encode(sk.verifying_key().to_bytes());
    (sk, pk)
}

fn sign_hex_digest(sk: &SigningKey, digest_hex: &str) -> String {
    let bytes: [u8; 32] = hex::decode(digest_hex).unwrap().try_into().unwrap();
    hex::encode(sk.sign(&bytes).to_bytes())
}

fn sign_bundle_offline(bundle_dir: &Path, sk: &SigningKey) {
    let manifest_bytes = std::fs::read(bundle_dir.join("manifest.json")).unwrap();
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes).unwrap();
    let digest = manifest.recompute_digest().unwrap();
    assert_eq!(digest, manifest.digest);
    let sig = sign_hex_digest(sk, &digest);
    std::fs::write(bundle_dir.join("manifest.sig"), sig.as_bytes()).unwrap();
}

/// Recompute manifest file hashes, counts, manifest digest, and re-sign
/// `manifest.sig` (and `ledger/checkpoint.json` if requested) after mutating a
/// bundle in place. Used by mutation tests to bypass check 2 so deeper checks
/// (5, 6, 7, 8, 9, 10) are proven directly.
fn remanifest_and_resign(bundle_dir: &Path, sk: &SigningKey, resign_checkpoint: bool) {
    if resign_checkpoint {
        let cp_path = bundle_dir.join("ledger/checkpoint.json");
        let mut cp_file: BundleCheckpointFile =
            serde_json::from_slice(&std::fs::read(&cp_path).unwrap()).unwrap();
        let d = cp_file.checkpoint.digest();
        cp_file.digest = d.clone();
        cp_file.signature = Some(sign_hex_digest(sk, &d));
        std::fs::write(&cp_path, to_canonical_bytes(&cp_file).unwrap()).unwrap();
    }

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: BundleManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();

    // Refresh counts from disk files.
    let ev_text = std::fs::read_to_string(bundle_dir.join("ledger/events.jsonl")).unwrap();
    let ev_lines: Vec<BundleLedgerEvent> =
        ev_text.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect();
    manifest.counts.events = ev_lines.len() as u64;
    manifest.counts.redacted_events = ev_lines.iter().filter(|e| e.redacted).count() as u64;
    let mut legacy = 0u64;
    for ev in &ev_lines {
        if ev.entry_hash.is_none() {
            legacy += 1;
        } else {
            break;
        }
    }
    manifest.counts.unhashed_legacy_prefix = legacy;

    let pol: Vec<PolicyRevisionRecord> =
        serde_json::from_slice(&std::fs::read(bundle_dir.join("policy/revisions.json")).unwrap()).unwrap();
    manifest.counts.policy_revisions = pol.len() as u64;
    let arts: Vec<ArtifactIndexEntry> =
        serde_json::from_slice(&std::fs::read(bundle_dir.join("artifacts/index.json")).unwrap()).unwrap();
    manifest.counts.artifacts = arts.len() as u64;
    let rows_text = std::fs::read_to_string(bundle_dir.join("evidence/rows.jsonl")).unwrap();
    manifest.counts.evidence_rows = rows_text.lines().filter(|l| !l.trim().is_empty()).count() as u64;

    // Refresh files map (keeping all existing listed files plus any approvals/*.json on disk).
    let mut new_files = BTreeMap::new();
    for rel in manifest.files.keys() {
        let p = bundle_dir.join(rel);
        if p.exists() {
            let bytes = std::fs::read(&p).unwrap();
            new_files.insert(rel.clone(), sha256_hex(&bytes));
        }
    }
    if let Ok(entries) = std::fs::read_dir(bundle_dir.join("approvals")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".json") {
                let rel = format!("approvals/{name}");
                let bytes = std::fs::read(entry.path()).unwrap();
                new_files.insert(rel, sha256_hex(&bytes));
            }
        }
    }
    manifest.counts.approvals = new_files.keys().filter(|k| k.starts_with("approvals/")).count() as u64;
    manifest.files = new_files;
    manifest.digest = manifest.recompute_digest().unwrap();
    std::fs::write(&manifest_path, to_canonical_bytes(&manifest).unwrap()).unwrap();
    sign_bundle_offline(bundle_dir, sk);
}

/// Rewrite every line of a JSONL bundle file through `f`.
fn rewrite_jsonl<T: serde::de::DeserializeOwned + serde::Serialize>(path: &Path, mut f: impl FnMut(&mut T)) {
    let mut out = Vec::new();
    for line in std::fs::read_to_string(path).unwrap().lines().filter(|l| !l.trim().is_empty()) {
        let mut item: T = serde_json::from_str(line).unwrap();
        f(&mut item);
        out.extend_from_slice(&to_canonical_bytes(&item).unwrap());
        out.push(b'\n');
    }
    std::fs::write(path, out).unwrap();
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

/// Minimal test schema matching the hub's real tables used by the bundle exporter.
fn open_test_db() -> (tempfile::TempDir, Db) {
    let dir = tempdir().unwrap();
    let extra = ua_store::SchemaPart {
        name: "evidence_bundle_test_tables.v1",
        sql: "
CREATE TABLE IF NOT EXISTS config_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    revision INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    document TEXT NOT NULL DEFAULT '{}',
    document_sha256 TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    approval_id INTEGER,
    event_ulid TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL DEFAULT 'default',
    title TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL DEFAULT 'default',
    tool TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    requested_by TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    reason TEXT,
    resolved_by TEXT,
    resolved_transport TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    consumed_at TEXT,
    run_id TEXT
);
CREATE TABLE IF NOT EXISTS dispatch_runs (
    run_id TEXT PRIMARY KEY,
    task_id INTEGER NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliverables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL,
    task_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    repo TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliverable_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL,
    deliverable_id INTEGER NOT NULL,
    rev_no INTEGER NOT NULL,
    identity TEXT NOT NULL,
    repo TEXT,
    summary TEXT,
    producer TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliverable_files (
    revision_id INTEGER PRIMARY KEY,
    org_id TEXT NOT NULL,
    source_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deliverable_releases (
    approval_id INTEGER PRIMARY KEY,
    revision_id INTEGER NOT NULL,
    org_id TEXT NOT NULL,
    requester TEXT NOT NULL,
    approver TEXT NOT NULL,
    destination TEXT NOT NULL,
    root_identity TEXT NOT NULL,
    staging_id TEXT NOT NULL,
    workflow_revision INTEGER NOT NULL,
    ownership_generation INTEGER NOT NULL,
    payload BLOB,
    released_at TEXT,
    cancelled_at TEXT,
    cancelled_by TEXT
);
CREATE TABLE IF NOT EXISTS managed_secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT '2026-11-20T00:00:00Z'
);
CREATE TABLE IF NOT EXISTS agent_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL,
    agent_label TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    issued_at TEXT NOT NULL DEFAULT '2026-11-20T00:00:00Z'
);
CREATE TABLE IF NOT EXISTS session_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    issued_at TEXT NOT NULL DEFAULT '2026-11-20T00:00:00Z'
);
CREATE TABLE IF NOT EXISTS message_index (
    message_id TEXT PRIMARY KEY,
    recipient TEXT NOT NULL,
    sender TEXT NOT NULL,
    act TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    event_ulid TEXT NOT NULL UNIQUE,
    event_seq INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
",
    };
    let parts: Vec<ua_store::Part> = vec![
        ledger::SCHEMA.into(),
        ua_store::org::STORE_PART.into(),
        KEY_STORE_PART.into(),
        CHECKPOINT_CHECKS_PART.into(),
        ua_store::evidence::NO_REPLACE_PART.into(),
        EXPORT_SNAPSHOT_PART.into(),
        extra.into(),
    ];
    let db = Db::open(&dir.path().join("hub.db"), &parts).unwrap();
    (dir, db)
}

/// Populate a deterministic DB with two orgs (`default`, `acme`), a policy
/// revision, a dispatch run, a deliverable artifact, an approved release with
/// matching `agent.approval.resolved` event, withheld table rows, and signed
/// `hub` and `org` checkpoints.
fn populate_sample_db(db: &Db, sk: &SigningKey, key_id: &str) -> (String, String) {
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let payload_obj = json!({
        "deliverable_id": 1,
        "revision": 1,
        "destination": "release/report.md"
    });
    let canon_payload = ua_core::canonical::to_string(&payload_obj);
    let action_digest = sha256_hex(canon_payload.as_bytes());
    let artifact_sha = "a".repeat(64);

    let (hub_cp_id, org_cp_id) = db
        .write(|tx| {
            tx.execute(
                "INSERT OR IGNORE INTO orgs (id, slug, display_name, created_at) VALUES ('acme', 'acme', 'Acme Org', '2026-11-20T00:00:00Z')",
                [],
            )?;
            key_add(tx, key_id, &pk, "2026-11-20T00:00:00Z", Some("fixture key"))?;

            // Withheld records (must be counted in withheld.json, never leaked).
            tx.execute(
                "INSERT INTO managed_secrets (org_id, name, ciphertext) VALUES ('default', 'deploy_key', 'enc:topsecret')",
                [],
            )?;
            tx.execute(
                "INSERT INTO agent_tokens (org_id, agent_label, token_hash) VALUES ('default', 'builder-1', 'hash1'), ('acme', 'acme-bot', 'hash2')",
                [],
            )?;
            tx.execute(
                "INSERT INTO session_credentials (org_id, token_hash) VALUES ('default', 'sesshash1')",
                [],
            )?;
            tx.execute(
                "INSERT INTO message_index (message_id, recipient, sender, act, conversation_id, event_ulid, event_seq, created_at) \
                 VALUES ('m-1', 'builder-2', 'builder-1', 'inform', 'c-1', '01MSG00000000000000000000A', 1, '2026-11-20T00:00:00Z')",
                [],
            )?;

            // Policy revision 1 with real policy document carrying an explicit SoD rule.
            let policy_doc = json!({
                "version": 1,
                "enabled": true,
                "default_action": "allow",
                "rules": [
                    {
                        "name": "release_sod",
                        "type": "tool",
                        "tool": "deliverable_release",
                        "action": "require_approval",
                        "separation_of_duties": true
                    }
                ]
            });
            let policy_doc_canon = ua_core::canonical::to_string(&policy_doc);
            let policy_doc_sha = sha256_hex(policy_doc_canon.as_bytes());
            tx.execute(
                "INSERT INTO config_revisions (kind, revision, action, actor, document, document_sha256, raw_sha256, created_at) \
                 VALUES ('policy', 1, 'commit', 'operator', ?1, ?2, ?2, '2026-11-20T00:01:00Z')",
                params![policy_doc_canon, policy_doc_sha],
            )?;
            let profile_doc = json!({ "code_defaults": {}, "overlay": {} });
            let profile_doc_canon = ua_core::canonical::to_string(&profile_doc);
            let profile_doc_sha = sha256_hex(profile_doc_canon.as_bytes());
            tx.execute(
                "INSERT INTO config_revisions (kind, revision, action, actor, document, document_sha256, raw_sha256, created_at) \
                 VALUES ('profile', 1, 'capture', 'operator', ?1, ?2, ?2, '2026-11-20T00:01:00Z')",
                params![profile_doc_canon, profile_doc_sha],
            )?;

            // Tasks (42 in default, 101 in acme), dispatch run, deliverable + file + release.
            tx.execute(
                "INSERT INTO tasks (id, org_id, title, created_at) VALUES \
                 (42, 'default', 'Audit report', '2026-11-20T00:02:00Z'), \
                 (101, 'acme', 'Acme review', '2026-11-20T00:02:00Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO dispatch_runs (run_id, task_id, attempt, created_at) \
                 VALUES ('run-001', 42, 1, '2026-11-20T00:02:00Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO deliverables (id, org_id, task_id, kind, title, created_by, created_at) \
                 VALUES (1, 'default', 42, 'file', 'Audit report', 'builder-1', '2026-11-20T00:03:00Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO deliverable_revisions (id, org_id, deliverable_id, rev_no, identity, producer, recorded_at) \
                 VALUES (1, 'default', 1, 1, ?1, 'builder-1', '2026-11-20T00:03:00Z')",
                [&artifact_sha],
            )?;
            tx.execute(
                "INSERT INTO deliverable_files (revision_id, org_id, source_path, size_bytes) \
                 VALUES (1, 'default', 'reports/audit.md', 4096)",
                [],
            )?;
            tx.execute(
                "INSERT INTO approvals (id, org_id, tool, payload, requested_by, status, reason, resolved_by, resolved_transport, created_at, updated_at, resolved_at, run_id) \
                 VALUES (10, 'default', 'deliverable_release', ?1, 'builder-1', 'approved', 'verified report', 'operator', 'ui', '2026-11-20T00:04:00Z', '2026-11-20T00:05:00Z', '2026-11-20T00:05:00Z', 'run-001')",
                [&canon_payload],
            )?;
            tx.execute(
                "INSERT INTO deliverable_releases (approval_id, revision_id, org_id, requester, approver, destination, root_identity, staging_id, workflow_revision, ownership_generation, released_at) \
                 VALUES (10, 1, 'default', 'builder-1', 'operator', 'release/report.md', 'root-1', 'stage-1', 1, 1, '2026-11-20T00:06:00Z')",
                [],
            )?;

            // Ledger events across both default and acme orgs (all hash_v = 2).
            ledger::append(
                tx,
                EventInput::new(
                    "default",
                    "agent.config.revision",
                    json!({
                        "schema": 1, "kind": "policy", "revision": 1, "action": "commit", "actor": "operator",
                        "parent_revision": null, "restores_revision": null, "document_sha256": policy_doc_sha,
                        "raw_sha256": policy_doc_sha, "approval_id": null, "diff": ""
                    }),
                )
                .by("operator"),
            )?;
            ledger::append(
                tx,
                EventInput::new("default", "agent.task.created", json!({ "task_id": 42, "title": null }))
                    .by("builder-1"),
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "default",
                    "agent.deliverable.revised",
                    json!({
                        "org_id": "default", "task_id": 42, "deliverable_id": 1, "kind": "file", "revision_id": 1,
                        "rev_no": 1, "identity": artifact_sha, "size_bytes": 4096
                    }),
                )
                .by("builder-1"),
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "default",
                    "agent.approval.requested",
                    json!({
                        "approval_id": 10, "tool": "deliverable_release", "requested_by": "builder-1",
                        "payload_sha256": action_digest
                    }),
                )
                .by("builder-1"),
            )?;
            ledger::append(
                tx,
                EventInput::new("acme", "agent.task.created", json!({ "task_id": 101, "title": null }))
                    .by("acme-bot"),
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "default",
                    "agent.approval.resolved",
                    json!({
                        "approval_id": 10,
                        "tool": "deliverable_release",
                        "decision": "approve",
                        "resolved_by": "operator",
                        "transport": "ui",
                        "payload_sha256": action_digest,
                        "expires_at": "2026-11-21T00:05:00Z"
                    }),
                )
                .by("operator"),
            )?;
            ledger::append(
                tx,
                EventInput::new("acme", "agent.task.completed", json!({ "task_id": 101 }))
                    .by("acme-bot"),
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "default",
                    "agent.deliverable.released",
                    json!({
                        "task_id": 42, "deliverable_id": 1, "revision_id": 1, "sha256": artifact_sha,
                        "size_bytes": 4096, "approval_id": 10, "approver": "operator",
                        "destination": "release/report.md", "root_identity": "root-1"
                    }),
                )
                .by("builder-1"),
            )?;
            let last_ev = ledger::append(
                tx,
                EventInput::new(
                    "acme",
                    "agent.deliverable.created",
                    json!({ "org_id": "acme", "deliverable_id": 7, "task_id": 101, "kind": "file" }),
                )
                .by("acme-bot"),
            )?
            .unwrap();

            // Write and sign org checkpoint for acme.
            let org_sum = compute_org_window_checkpoint(
                tx,
                "acme",
                "2026-11-01T00:00:00Z",
                "2099-12-31T23:59:59Z",
                None,
            )?;
            let org_cp = Checkpoint {
                checkpoint_id: "cp-org-acme-1".into(),
                class: CheckpointClass::Org,
                org_id: Some("acme".into()),
                seq: None,
                hash: None,
                window: Some(Window {
                    start: "2026-11-01T00:00:00Z".into(),
                    end: "2099-12-31T23:59:59Z".into(),
                }),
                global_from_hash: Some(org_sum.global_from_hash),
                global_head_hash: Some(org_sum.global_head_hash),
                org_row_count: Some(org_sum.org_row_count),
                org_chain_hash: Some(org_sum.org_chain_hash),
                key_id: key_id.into(),
                signed_at: "2026-11-25T12:00:00Z".into(),
            };
            let org_digest = checkpoint_write(tx, &org_cp, "2026-11-25T12:00:00Z")?;
            let org_sig = sign_hex_digest(sk, &org_digest);
            checkpoint_attach(tx, &org_cp.checkpoint_id, &org_sig)?;

            // Write and sign hub checkpoint covering all events through the latest seq.
            let head_seq: i64 =
                tx.query_row("SELECT MAX(seq) FROM event_log", [], |r| r.get(0))?;
            let head_hash: String = tx.query_row(
                "SELECT entry_hash FROM event_log WHERE seq = ?1",
                [head_seq],
                |r| r.get(0),
            )?;
            assert!(head_seq >= last_ev.seq);
            let hub_cp = Checkpoint {
                checkpoint_id: "cp-hub-1".into(),
                class: CheckpointClass::Hub,
                org_id: None,
                seq: Some(head_seq),
                hash: Some(head_hash),
                window: None,
                global_from_hash: None,
                global_head_hash: None,
                org_row_count: None,
                org_chain_hash: None,
                key_id: key_id.into(),
                signed_at: "2026-11-25T12:05:00Z".into(),
            };
            let hub_digest = checkpoint_write(tx, &hub_cp, "2026-11-25T12:05:00Z")?;
            let hub_sig = sign_hex_digest(sk, &hub_digest);
            checkpoint_attach(tx, &hub_cp.checkpoint_id, &hub_sig)?;

            Ok((hub_cp.checkpoint_id, org_cp.checkpoint_id))
        })
        .unwrap();

    (hub_cp_id, org_cp_id)
}

fn export_opts(cp_id: &str) -> ExportBundleOptions {
    ExportBundleOptions {
        checkpoint_id: cp_id.into(),
        from_seq: None,
        from_org_seq: None,
        exported_at: "2026-11-25T12:10:00Z".into(),
        host: "fixture-host.example.com".into(),
        tool_version: "0.1.0-fixture".into(),
    }
}

/// Regenerate all checked-in fixtures under
/// `crates/ua-store/tests/fixtures/evidence_bundles/`. Run manually with
/// `cargo test -p ua-store --test evidence_bundle regenerate_checked_in_fixtures -- --ignored`.
#[test]
#[ignore]
fn regenerate_checked_in_fixtures() {
    let root = fixtures_root();
    if root.exists() {
        std::fs::remove_dir_all(&root).unwrap();
    }
    std::fs::create_dir_all(&root).unwrap();

    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let (unk_sk, _unk_pk) = signing_key(UNKNOWN_KEY_SEED);

    // 0. Verifier trust file (knows FIXTURE_KEY_ID, does NOT know UNKNOWN_KEY_ID).
    let trust_file = TrustFile {
        keys: vec![TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk }],
        revoked_key_ids: Vec::new(),
        signed_checkpoints: Vec::new(),
    };
    std::fs::write(root.join("trust.json"), serde_json::to_vec_pretty(&trust_file).unwrap()).unwrap();

    // Build source DB and export good_hub + good_org.
    let (_tmp, db) = open_test_db();
    let (hub_cp_id, org_cp_id) = populate_sample_db(&db, &sk, FIXTURE_KEY_ID);

    let good_hub = root.join("good_hub");
    db.read(|c| export_bundle(c, &good_hub, &export_opts(&hub_cp_id))).unwrap();
    sign_bundle_offline(&good_hub, &sk);

    let good_org = root.join("good_org");
    db.read(|c| export_bundle(c, &good_org, &export_opts(&org_cp_id))).unwrap();
    sign_bundle_offline(&good_org, &sk);

    // 3. flipped_byte: flip one byte in ledger/events.jsonl without updating manifest.
    let flipped = root.join("flipped_byte");
    copy_dir_recursive(&good_hub, &flipped);
    let ev_path = flipped.join("ledger/events.jsonl");
    let mut bytes = std::fs::read(&ev_path).unwrap();
    bytes[10] ^= 0x01;
    std::fs::write(&ev_path, bytes).unwrap();

    // 4. dropped_event: remove the second event, re-manifest & re-sign so check 5 catches sequence_gap.
    let dropped = root.join("dropped_event");
    copy_dir_recursive(&good_hub, &dropped);
    let ev_path = dropped.join("ledger/events.jsonl");
    let mut lines: Vec<String> =
        std::fs::read_to_string(&ev_path).unwrap().lines().map(String::from).collect();
    lines.remove(1);
    std::fs::write(&ev_path, format!("{}\n", lines.join("\n"))).unwrap();
    remanifest_and_resign(&dropped, &sk, false);

    // 5. reordered_pair: swap events 1 and 2, re-manifest & re-sign so check 5 catches sequence_out_of_order.
    let reordered = root.join("reordered_pair");
    copy_dir_recursive(&good_hub, &reordered);
    let ev_path = reordered.join("ledger/events.jsonl");
    let mut lines: Vec<String> =
        std::fs::read_to_string(&ev_path).unwrap().lines().map(String::from).collect();
    lines.swap(1, 2);
    std::fs::write(&ev_path, format!("{}\n", lines.join("\n"))).unwrap();
    remanifest_and_resign(&reordered, &sk, false);

    // 6. org_missing_row: remove middle row from good_org, re-manifest & re-sign.
    let org_missing = root.join("org_missing_row");
    copy_dir_recursive(&good_org, &org_missing);
    let ev_path = org_missing.join("ledger/events.jsonl");
    let mut lines: Vec<String> =
        std::fs::read_to_string(&ev_path).unwrap().lines().map(String::from).collect();
    assert!(lines.len() >= 3);
    lines.remove(1);
    std::fs::write(&ev_path, format!("{}\n", lines.join("\n"))).unwrap();
    remanifest_and_resign(&org_missing, &sk, false);

    // 7. unknown_key: valid hub bundle signed by UNKNOWN_KEY_ID.
    let (_tmp2, db2) = open_test_db();
    let (unk_hub_cp, _) = populate_sample_db(&db2, &unk_sk, UNKNOWN_KEY_ID);
    let unknown_dir = root.join("unknown_key");
    db2.read(|c| export_bundle(c, &unknown_dir, &export_opts(&unk_hub_cp))).unwrap();
    sign_bundle_offline(&unknown_dir, &unk_sk);

    // 8. receipt_wrong_payload: modify receipt action_digest + recompute receipt_id, re-manifest & re-sign.
    let wrong_payload = root.join("receipt_wrong_payload");
    copy_dir_recursive(&good_hub, &wrong_payload);
    let rec_path = wrong_payload.join("approvals/10.json");
    let mut rec: ApprovalReceipt = serde_json::from_slice(&std::fs::read(&rec_path).unwrap()).unwrap();
    rec.action_digest = "f".repeat(64);
    rec.receipt_id = rec.compute_receipt_id().unwrap();
    std::fs::write(&rec_path, to_canonical_bytes(&rec).unwrap()).unwrap();
    remanifest_and_resign(&wrong_payload, &sk, false);

    // 9. private_record: inject a private label on an evidence row, re-manifest & re-sign.
    let private_dir = root.join("private_record");
    copy_dir_recursive(&good_hub, &private_dir);
    let rows_path = private_dir.join("evidence/rows.jsonl");
    let mut row_lines: Vec<Value> = std::fs::read_to_string(&rows_path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    row_lines[0]["labels"] = json!(["audit", "private"]);
    let mut new_rows = Vec::new();
    for v in &row_lines {
        new_rows.extend_from_slice(&to_canonical_bytes(v).unwrap());
        new_rows.push(b'\n');
    }
    std::fs::write(&rows_path, new_rows).unwrap();
    remanifest_and_resign(&private_dir, &sk, false);
}

fn fixture_trust() -> BundleVerifyTrust {
    let tf: TrustFile =
        serde_json::from_slice(&std::fs::read(fixtures_root().join("trust.json")).unwrap()).unwrap();
    BundleVerifyTrust { trust_keys: tf.keys, ..BundleVerifyTrust::default() }
}

#[test]
fn checked_in_fixtures_match_expected_verdicts() {
    let root = fixtures_root();
    let trust = fixture_trust();

    // 1. good_hub -> exit 0, all claims verified, withheld reported, producer reported.
    let v = verify_bundle_dir(&root.join("good_hub"), &trust).unwrap();
    assert!(v.ok, "good_hub failed: {v:?}");
    assert_eq!(v.exit_code, 0);
    assert_eq!(v.class, Some(CheckpointClass::Hub));
    assert_eq!(v.integrity.status, ClaimStatus::Verified);
    assert_eq!(v.authorship.status, ClaimStatus::Verified);
    assert_eq!(v.completeness.status, ClaimStatus::Verified);
    assert_eq!(v.separation_of_duties.status, ClaimStatus::Verified);
    assert!(v.withheld.as_ref().unwrap().total >= 5);
    assert!(v.producer.is_some());

    // 2a. good_org alone -> exit 0, integrity + authorship verified, completeness explicitly unverified.
    let v = verify_bundle_dir(&root.join("good_org"), &trust).unwrap();
    assert!(v.ok, "good_org failed: {v:?}");
    assert_eq!(v.exit_code, 0);
    assert_eq!(v.class, Some(CheckpointClass::Org));
    assert_eq!(v.org_id.as_deref(), Some("acme"));
    assert_eq!(v.integrity.status, ClaimStatus::Verified);
    assert_eq!(v.authorship.status, ClaimStatus::Verified);
    assert_eq!(v.completeness.status, ClaimStatus::Unverified);
    assert_eq!(v.separation_of_duties.status, ClaimStatus::NotApplicable);

    // 2b. good_org with verified hub cross-check -> completeness upgrades to verified!
    let hub_cc = load_verified_hub_cross_check(&root.join("good_hub"), &trust).unwrap().unwrap();
    let mut org_cc_trust = trust.clone();
    org_cc_trust.hub_cross_check = Some(hub_cc);
    let v = verify_bundle_dir(&root.join("good_org"), &org_cc_trust).unwrap();
    assert!(v.ok, "good_org with hub cross-check failed: {v:?}");
    assert_eq!(v.completeness.status, ClaimStatus::Verified);

    // 3. flipped_byte -> exit 1 (file_digest_mismatch).
    let v = verify_bundle_dir(&root.join("flipped_byte"), &trust).unwrap();
    assert_eq!(v.exit_code, 1);
    assert_eq!(v.reason.as_deref(), Some("file_digest_mismatch"));

    // 4. dropped_event -> exit 1 (sequence_gap).
    let v = verify_bundle_dir(&root.join("dropped_event"), &trust).unwrap();
    assert_eq!(v.exit_code, 1);
    assert_eq!(v.reason.as_deref(), Some("sequence_gap"));

    // 5. reordered_pair -> exit 1 (sequence_out_of_order).
    let v = verify_bundle_dir(&root.join("reordered_pair"), &trust).unwrap();
    assert_eq!(v.exit_code, 1);
    assert_eq!(v.reason.as_deref(), Some("sequence_out_of_order"));

    // 6. org_missing_row -> exit 1 (sequence_gap).
    let v = verify_bundle_dir(&root.join("org_missing_row"), &trust).unwrap();
    assert_eq!(v.exit_code, 1);
    assert_eq!(v.reason.as_deref(), Some("sequence_gap"));

    // 7. unknown_key -> exit 2 (unknown_key), integrity verified, authorship unverified.
    let v = verify_bundle_dir(&root.join("unknown_key"), &trust).unwrap();
    assert_eq!(v.exit_code, 2);
    assert_eq!(v.reason.as_deref(), Some("unknown_key"));
    assert_eq!(v.integrity.status, ClaimStatus::Verified);
    assert_eq!(v.authorship.status, ClaimStatus::Unverified);

    // 8. receipt_wrong_payload -> exit 1 (receipt_action_digest_mismatch).
    let v = verify_bundle_dir(&root.join("receipt_wrong_payload"), &trust).unwrap();
    assert_eq!(v.exit_code, 1);
    assert_eq!(v.reason.as_deref(), Some("receipt_action_digest_mismatch"));

    // 9. private_record -> exit 1 (forbidden_private_content).
    let v = verify_bundle_dir(&root.join("private_record"), &trust).unwrap();
    assert_eq!(v.exit_code, 1);
    assert_eq!(v.reason.as_deref(), Some("forbidden_private_content"));
}

#[test]
fn property_flipping_any_byte_in_any_hashed_file_refuses_while_producer_json_is_unhashed() {
    let trust = fixture_trust();
    for fixture in ["good_hub", "good_org"] {
        let src = fixtures_root().join(fixture);
        let manifest: BundleManifest =
            serde_json::from_slice(&std::fs::read(src.join("manifest.json")).unwrap()).unwrap();

        for rel in manifest.files.keys() {
            let tmp = tempdir().unwrap();
            copy_dir_recursive(&src, tmp.path());
            let target = tmp.path().join(rel);
            let mut bytes = std::fs::read(&target).unwrap();
            if bytes.is_empty() {
                bytes.push(b' ');
            } else {
                let mid = bytes.len() / 2;
                bytes[mid] ^= 0x01;
            }
            std::fs::write(&target, bytes).unwrap();
            let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
            assert_eq!(v.exit_code, 1, "flipping byte in {fixture}/{rel} must refuse with exit 1, got {v:?}");
            assert_eq!(v.reason.as_deref(), Some("file_digest_mismatch"));
        }

        // Mutating producer.json and adding an unmanifested verify.json must STILL pass (exit 0),
        // with producer reported and unmanifested file warned/ignored as evidence.
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&src, tmp.path());
        let new_prod = ProducerInfo {
            exported_at: "2027-01-01T00:00:00Z".into(),
            host: "other-host.example.com".into(),
            tool_version: "9.9.9".into(),
        };
        std::fs::write(tmp.path().join("producer.json"), serde_json::to_vec(&new_prod).unwrap()).unwrap();
        std::fs::write(tmp.path().join("verify.json"), br#"{"ok":true,"forged":true}"#).unwrap();
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert!(v.ok, "{fixture} with edited producer.json should still verify: {v:?}");
        assert_eq!(v.producer, Some(new_prod));
        assert!(v.warnings.iter().any(|w| w.contains("verify.json")));
    }
}

#[test]
fn property_duplicate_sequence_and_wrong_key_resign_refuse() {
    let trust = fixture_trust();
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);
    let (other_sk, _) = signing_key([0x55; 32]);

    // Duplicate global seq (hub).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let ev_path = tmp.path().join("ledger/events.jsonl");
        let mut lines: Vec<String> =
            std::fs::read_to_string(&ev_path).unwrap().lines().map(String::from).collect();
        let dup = lines[1].clone();
        lines.insert(2, dup);
        std::fs::write(&ev_path, format!("{}\n", lines.join("\n"))).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("sequence_duplicate"));
    }

    // Duplicate org_seq (org).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_org"), tmp.path());
        let ev_path = tmp.path().join("ledger/events.jsonl");
        let mut lines: Vec<String> =
            std::fs::read_to_string(&ev_path).unwrap().lines().map(String::from).collect();
        let dup = lines[0].clone();
        lines.insert(1, dup);
        std::fs::write(&ev_path, format!("{}\n", lines.join("\n"))).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("sequence_duplicate"));
    }

    // Re-signing manifest.sig with a different key refuses (exit 1).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        sign_bundle_offline(tmp.path(), &other_sk);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("invalid_manifest_signature"));
    }

    // Re-signing checkpoint with a different key refuses (exit 1).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        remanifest_and_resign(tmp.path(), &other_sk, true);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("invalid_checkpoint_signature"));
    }
}

#[test]
fn trust_states_unanchored_revoked_unsigned_and_key_mismatch() {
    let hub = fixtures_root().join("good_hub");
    let trust = fixture_trust();

    // Unanchored -> exit 2, integrity verified, authorship unverified.
    let v = verify_bundle_dir(&hub, &BundleVerifyTrust::default()).unwrap();
    assert_eq!(v.exit_code, 2);
    assert_eq!(v.reason.as_deref(), Some("unanchored"));
    assert_eq!(v.integrity.status, ClaimStatus::Verified);
    assert_eq!(v.authorship.status, ClaimStatus::Unverified);

    // Revoked key -> exit 2.
    let mut rev_trust = trust.clone();
    rev_trust.revoked_key_ids.push(FIXTURE_KEY_ID.into());
    let v = verify_bundle_dir(&hub, &rev_trust).unwrap();
    assert_eq!(v.exit_code, 2);
    assert_eq!(v.reason.as_deref(), Some("key_revoked"));

    // Anchor key_id mismatch -> exit 1.
    let mismatch_trust = BundleVerifyTrust::from_anchor(TrustAnchor {
        key_id: "k-other".into(),
        public_key: trust.trust_keys[0].public_key.clone(),
    });
    let v = verify_bundle_dir(&hub, &mismatch_trust).unwrap();
    assert_eq!(v.exit_code, 1);
    assert_eq!(v.reason.as_deref(), Some("key_mismatch"));

    // Missing manifest.sig -> exit 2 (unsigned_bundle), integrity still verified!
    let tmp = tempdir().unwrap();
    copy_dir_recursive(&hub, tmp.path());
    std::fs::remove_file(tmp.path().join("manifest.sig")).unwrap();
    let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
    assert_eq!(v.exit_code, 2);
    assert_eq!(v.reason.as_deref(), Some("unsigned_bundle"));
    assert_eq!(v.integrity.status, ClaimStatus::Verified);
    assert_eq!(v.authorship.status, ClaimStatus::Unverified);
}

#[test]
fn receipts_sod_cross_links_and_artifact_trace_mutations() {
    let trust = fixture_trust();
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);

    // 1. Resolver not human -> exit 1.
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let p = tmp.path().join("approvals/10.json");
        let mut r: ApprovalReceipt = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        r.resolver.kind = "agent".into();
        r.receipt_id = r.compute_receipt_id().unwrap();
        std::fs::write(&p, to_canonical_bytes(&r).unwrap()).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("receipt_resolver_not_human"));
    }

    // 2. A receipt whose resolver label is rewritten to the requester's is
    //    refused against the hash-verified event's `resolved_by` (B-B1).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let p = tmp.path().join("approvals/10.json");
        let mut r: ApprovalReceipt = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        r.resolver.label = r.requester.label.clone();
        r.resolver_is_requester = true;
        r.receipt_id = r.compute_receipt_id().unwrap();
        std::fs::write(&p, to_canonical_bytes(&r).unwrap()).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("receipt_event_mismatch"));
    }

    // 3. Rewriting the policy document (and its digest) to drop the SoD rule
    //    is refused against the hash-verified agent.config.revision event
    //    (review B-S2).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let p = tmp.path().join("policy/revisions.json");
        let mut revs: Vec<PolicyRevisionRecord> =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let no_sod_doc = json!({
            "version": 1,
            "enabled": true,
            "default_action": "allow",
            "rules": [
                {
                    "name": "config_sod",
                    "type": "tool",
                    "tool": "config_revision_manage",
                    "action": "require_approval",
                    "separation_of_duties": true
                }
            ]
        });
        let doc_canon = ua_core::canonical::to_string(&no_sod_doc);
        let doc_sha = sha256_hex(doc_canon.as_bytes());
        let pol = revs.iter_mut().find(|r| r.kind == "policy" && r.revision == 1).unwrap();
        pol.document = Some(doc_canon);
        pol.document_sha256 = doc_sha.clone();
        pol.sod_tools = vec!["config_revision_manage".into()];
        std::fs::write(&p, to_canonical_bytes(&revs).unwrap()).unwrap();

        let rp = tmp.path().join("approvals/10.json");
        let mut rec: ApprovalReceipt = serde_json::from_slice(&std::fs::read(&rp).unwrap()).unwrap();
        rec.policy_digest = Some(doc_sha);
        rec.receipt_id = rec.compute_receipt_id().unwrap();
        std::fs::write(&rp, to_canonical_bytes(&rec).unwrap()).unwrap();

        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1, "{v:?}");
        assert_eq!(v.reason.as_deref(), Some("policy_ledger_mismatch"));
    }

    // 4. Missing receipt for approval event -> exit 1 (cross_link_missing_receipt).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        std::fs::remove_file(tmp.path().join("approvals/10.json")).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("cross_link_missing_receipt"));
    }

    // 5. Extra orphan receipt without ledger event -> exit 1 (cross_link_missing_event).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let mut r: ApprovalReceipt =
            serde_json::from_slice(&std::fs::read(tmp.path().join("approvals/10.json")).unwrap()).unwrap();
        r.approval_id = 999;
        r.receipt_id = r.compute_receipt_id().unwrap();
        std::fs::write(tmp.path().join("approvals/999.json"), to_canonical_bytes(&r).unwrap()).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("cross_link_missing_event"));
    }

    // 6. Broken artifact trace (missing run_id) -> exit 1 (broken_artifact_trace).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let p = tmp.path().join("artifacts/index.json");
        let mut arts: Vec<ArtifactIndexEntry> = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        arts[0].run_id = None;
        std::fs::write(&p, to_canonical_bytes(&arts).unwrap()).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("broken_artifact_trace"));
    }

    // 7. Artifact revision mismatch against receipt.covers -> exit 1 (receipt_covers_mismatch).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let p = tmp.path().join("artifacts/index.json");
        let mut arts: Vec<ArtifactIndexEntry> = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        arts[0].sha256 = "b".repeat(64);
        std::fs::write(&p, to_canonical_bytes(&arts).unwrap()).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("receipt_covers_mismatch"));
    }
}

#[test]
fn hash_v_downgrade_tampered_org_id_and_legacy_unhashed_prefix() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });

    // 1. Tampered org_id on hash_v = 2 row -> exit 1 (row_hash_mismatch).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let ev_path = tmp.path().join("ledger/events.jsonl");
        let mut evs: Vec<BundleLedgerEvent> = std::fs::read_to_string(&ev_path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        evs[0].org_id = "tampered-org".into();
        let mut out = Vec::new();
        for ev in &evs {
            out.extend_from_slice(&to_canonical_bytes(ev).unwrap());
            out.push(b'\n');
        }
        std::fs::write(&ev_path, out).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("row_hash_mismatch"));
    }

    // 2. hash_v = 2 -> 1 downgrade inside events.jsonl -> exit 1 (hash_v_downgrade).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let ev_path = tmp.path().join("ledger/events.jsonl");
        let mut evs: Vec<BundleLedgerEvent> = std::fs::read_to_string(&ev_path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let last = evs.last_mut().unwrap();
        assert_eq!(last.hash_v, HASH_V2);
        last.hash_v = HASH_V1;
        last.entry_hash = Some(compute_entry_hash(
            last.prev_hash.as_deref(),
            &last.ulid,
            &last.channel,
            &last.payload,
            last.originator.as_deref(),
            last.episode_id.as_deref(),
            last.causal_parent_id.as_deref(),
            &last.created_at,
            last.dedupe_key.as_deref(),
        ));
        let new_head = last.entry_hash.clone().unwrap();
        let mut out = Vec::new();
        for ev in &evs {
            out.extend_from_slice(&to_canonical_bytes(ev).unwrap());
            out.push(b'\n');
        }
        std::fs::write(&ev_path, out).unwrap();
        let cp_path = tmp.path().join("ledger/checkpoint.json");
        let mut cp_file: BundleCheckpointFile =
            serde_json::from_slice(&std::fs::read(&cp_path).unwrap()).unwrap();
        cp_file.checkpoint.hash = Some(new_head);
        std::fs::write(&cp_path, to_canonical_bytes(&cp_file).unwrap()).unwrap();
        remanifest_and_resign(tmp.path(), &sk, true);

        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("hash_v_downgrade"));
    }

    // 3. Unhashed legacy prefix (seq 1..=2) + v1 row (seq 3) + v2 row (seq 4) -> exit 0 with explicit report!
    {
        let (_dir, db) = open_test_db();
        let cp_id = db
            .write(|tx| {
                // Insert two unhashed legacy rows FIRST (seq 1..=2, entry_hash NULL).
                tx.execute(
                    "INSERT INTO event_log (ulid, channel, payload, originator, created_at, org_id, hash_v) \
                     VALUES ('01LEG000000000000000000001', 'legacy.event', '{\"n\":1}', 'sys', '2026-10-01T00:00:00Z', 'default', 1), \
                            ('01LEG000000000000000000002', 'legacy.event', '{\"n\":2}', 'sys', '2026-10-01T00:01:00Z', 'default', 1)",
                    [],
                )?;
                // Insert one hash_v = 1 row anchored to genesis (seq 3).
                let v1_hash = compute_entry_hash(
                    Some(GENESIS_HASH),
                    "01V10000000000000000000003",
                    "legacy.v1",
                    r#"{"n":3}"#,
                    Some("sys"),
                    None,
                    None,
                    "2026-10-02T00:00:00Z",
                    None,
                );
                tx.execute(
                    "INSERT INTO event_log (ulid, channel, payload, originator, created_at, prev_hash, entry_hash, org_id, hash_v) \
                     VALUES ('01V10000000000000000000003', 'legacy.v1', '{\"n\":3}', 'sys', '2026-10-02T00:00:00Z', ?1, ?2, 'default', 1)",
                    params![GENESIS_HASH, v1_hash],
                )?;
                // Add key (appends a hash_v = 2 row chaining off seq 3) and one more hash_v = 2 row.
                key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
                // Append a normal hash_v = 2 row chaining off the v1 row.
                let ev4 = ledger::append(
                    tx,
                    EventInput::new("default", "modern.v2", json!({ "n": 4 })).by("builder-1"),
                )?
                .unwrap();
                let cp = Checkpoint {
                    checkpoint_id: "cp-legacy-prefix".into(),
                    class: CheckpointClass::Hub,
                    org_id: None,
                    seq: Some(ev4.seq),
                    hash: ev4.entry_hash.clone(),
                    window: None,
                    global_from_hash: None,
                    global_head_hash: None,
                    org_row_count: None,
                    org_chain_hash: None,
                    key_id: FIXTURE_KEY_ID.into(),
                    signed_at: "2026-11-25T12:00:00Z".into(),
                };
                let d = checkpoint_write(tx, &cp, "2026-11-25T12:00:00Z")?;
                checkpoint_attach(tx, &cp.checkpoint_id, &sign_hex_digest(&sk, &d))?;
                Ok(cp.checkpoint_id)
            })
            .unwrap();

        let out_dir = tempdir().unwrap();
        let bundle_dir = out_dir.path().join("bundle");
        db.read(|c| export_bundle(c, &bundle_dir, &export_opts(&cp_id))).unwrap();
        // Exporter must never write manifest.sig.
        assert!(!bundle_dir.join("manifest.sig").exists());
        sign_bundle_offline(&bundle_dir, &sk);

        let v = verify_bundle_dir(&bundle_dir, &trust).unwrap();
        assert!(v.ok, "mixed legacy + v1 + v2 bundle should verify: {v:?}");
        assert_eq!(v.unhashed_legacy_prefix.count, 2);
        assert_eq!(v.unhashed_legacy_prefix.first_seq, Some(1));
        assert_eq!(v.unhashed_legacy_prefix.last_seq, Some(2));
    }
}

#[test]
fn exporter_refuses_forbidden_egress_and_non_empty_dir() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let (_dir, db) = open_test_db();
    let cp_id = db
        .write(|tx| {
            key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
            let ev = ledger::append(
                tx,
                EventInput::new(
                    "default",
                    "agent.log",
                    json!({ "msg": "oops leaked uas_0123456789abcdef9999 here" }),
                ),
            )?
            .unwrap();
            let cp = Checkpoint {
                checkpoint_id: "cp-leak".into(),
                class: CheckpointClass::Hub,
                org_id: None,
                seq: Some(ev.seq),
                hash: ev.entry_hash.clone(),
                window: None,
                global_from_hash: None,
                global_head_hash: None,
                org_row_count: None,
                org_chain_hash: None,
                key_id: FIXTURE_KEY_ID.into(),
                signed_at: "2026-11-25T12:00:00Z".into(),
            };
            let d = checkpoint_write(tx, &cp, "2026-11-25T12:00:00Z")?;
            checkpoint_attach(tx, &cp.checkpoint_id, &sign_hex_digest(&sk, &d))?;
            Ok(cp.checkpoint_id)
        })
        .unwrap();

    // A secret in a row never blocks the export: the row is a hash-only stub.
    let out = tempdir().unwrap();
    let bundle_dir = out.path().join("leaked");
    db.read(|c| export_bundle(c, &bundle_dir, &export_opts(&cp_id))).unwrap();
    let text = std::fs::read_to_string(bundle_dir.join("ledger/events.jsonl")).unwrap();
    assert!(!text.contains("uas_0123456789abcdef9999"));

    // Non-empty output directory is refused.
    let non_empty = tempdir().unwrap();
    std::fs::write(non_empty.path().join("existing.txt"), b"keep").unwrap();
    let err = db.read(|c| export_bundle(c, non_empty.path(), &export_opts(&cp_id))).unwrap_err();
    assert!(err.to_string().contains("non-empty"), "got: {err}");
}

#[test]
fn incremental_org_windows_and_hub_cross_check_catches_mid_window_omission() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });
    let (_dir, db) = open_test_db();

    let (cp_w1, cp_w2, cp_hub, w1_pin) = db
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, created_at) VALUES ('acme', 'acme', 'Acme', '2026-11-20T00:00:00Z')",
                [],
            )?;
            key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
            ledger::append(tx, EventInput::new("acme", "agent.task.completed", json!({ "task_id": 1 })))?;
            ledger::append(tx, EventInput::new("default", "agent.task.completed", json!({ "task_id": 1 })))?;
            ledger::append(tx, EventInput::new("acme", "agent.task.completed", json!({ "task_id": 2 })))?;

            let s1 = compute_org_window_checkpoint(
                tx,
                "acme",
                "2026-11-01T00:00:00Z",
                "2099-12-31T00:00:00Z",
                None,
            )?;
            let c1 = Checkpoint {
                checkpoint_id: "cp-acme-w1".into(),
                class: CheckpointClass::Org,
                org_id: Some("acme".into()),
                seq: None,
                hash: None,
                window: Some(s1.window.clone()),
                global_from_hash: Some(s1.global_from_hash.clone()),
                global_head_hash: Some(s1.global_head_hash.clone()),
                org_row_count: Some(s1.org_row_count),
                org_chain_hash: Some(s1.org_chain_hash.clone()),
                key_id: FIXTURE_KEY_ID.into(),
                signed_at: "2026-11-25T12:00:00Z".into(),
            };
            let d1 = checkpoint_write(tx, &c1, "2026-11-25T12:00:00Z")?;
            checkpoint_attach(tx, &c1.checkpoint_id, &sign_hex_digest(&sk, &d1))?;

            // Window 2 events.
            ledger::append(tx, EventInput::new("acme", "agent.task.completed", json!({ "task_id": 3 })))?;
            ledger::append(tx, EventInput::new("acme", "agent.task.completed", json!({ "task_id": 4 })))?;
            let s2 = compute_org_window_checkpoint(
                tx,
                "acme",
                "2026-11-25T12:00:00Z",
                "2099-12-31T23:59:59Z",
                Some(&s1.global_head_hash),
            )?;
            let c2 = Checkpoint {
                checkpoint_id: "cp-acme-w2".into(),
                class: CheckpointClass::Org,
                org_id: Some("acme".into()),
                seq: None,
                hash: None,
                window: Some(s2.window.clone()),
                global_from_hash: Some(s2.global_from_hash),
                global_head_hash: Some(s2.global_head_hash),
                org_row_count: Some(s2.org_row_count),
                org_chain_hash: Some(s2.org_chain_hash),
                key_id: FIXTURE_KEY_ID.into(),
                signed_at: "2026-11-25T13:00:00Z".into(),
            };
            let d2 = checkpoint_write(tx, &c2, "2026-11-25T13:00:00Z")?;
            checkpoint_attach(tx, &c2.checkpoint_id, &sign_hex_digest(&sk, &d2))?;

            // Full hub checkpoint for cross-checking.
            let head_seq: i64 = tx.query_row("SELECT MAX(seq) FROM event_log", [], |r| r.get(0))?;
            let head_hash: String =
                tx.query_row("SELECT entry_hash FROM event_log WHERE seq = ?1", [head_seq], |r| r.get(0))?;
            let ch = Checkpoint {
                checkpoint_id: "cp-hub-full".into(),
                class: CheckpointClass::Hub,
                org_id: None,
                seq: Some(head_seq),
                hash: Some(head_hash),
                window: None,
                global_from_hash: None,
                global_head_hash: None,
                org_row_count: None,
                org_chain_hash: None,
                key_id: FIXTURE_KEY_ID.into(),
                signed_at: "2026-11-25T13:05:00Z".into(),
            };
            let dh = checkpoint_write(tx, &ch, "2026-11-25T13:05:00Z")?;
            checkpoint_attach(tx, &ch.checkpoint_id, &sign_hex_digest(&sk, &dh))?;

            let pin = PinnedOrgHead {
                org_id: "acme".into(),
                global_head_hash: s1.global_head_hash,
                org_row_count: s1.org_row_count,
                org_chain_hash: s1.org_chain_hash,
            };
            Ok((c1.checkpoint_id, c2.checkpoint_id, ch.checkpoint_id, pin))
        })
        .unwrap();

    let out = tempdir().unwrap();
    let w1_dir = out.path().join("w1");
    let w2_dir = out.path().join("w2");
    let hub_dir = out.path().join("hub");

    db.read(|c| export_bundle(c, &w1_dir, &export_opts(&cp_w1))).unwrap();
    sign_bundle_offline(&w1_dir, &sk);

    let mut w2_opts = export_opts(&cp_w2);
    w2_opts.from_org_seq = Some(w1_pin.org_row_count);
    db.read(|c| export_bundle(c, &w2_dir, &w2_opts)).unwrap();
    sign_bundle_offline(&w2_dir, &sk);

    db.read(|c| export_bundle(c, &hub_dir, &export_opts(&cp_hub))).unwrap();
    sign_bundle_offline(&hub_dir, &sk);

    // Window 2 without pinned_org -> exit 2 (cannot refold org_chain_hash).
    let v = verify_bundle_dir(&w2_dir, &trust).unwrap();
    assert_eq!(v.exit_code, 2);
    assert_eq!(v.reason.as_deref(), Some("missing_pinned_checkpoint"));

    // Window 2 with pinned_org -> exit 0!
    let mut w2_trust = trust.clone();
    w2_trust.pinned_org = Some(w1_pin);
    let v = verify_bundle_dir(&w2_dir, &w2_trust).unwrap();
    assert!(v.ok, "w2 with pinned_org failed: {v:?}");
    assert_eq!(v.completeness.status, ClaimStatus::Verified);

    // Simulate a dishonest hub omitting acme row 2 from window 1 and signing a self-consistent org bundle:
    // alone it passes internal checks, but with hub_cross_check it is caught and refused (exit 1)!
    let omitted_dir = out.path().join("w1_omitted");
    copy_dir_recursive(&w1_dir, &omitted_dir);
    let ev_path = omitted_dir.join("ledger/events.jsonl");
    let mut evs: Vec<BundleLedgerEvent> = std::fs::read_to_string(&ev_path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(evs.len(), 2);
    evs.pop(); // Omit acme row 2 while keeping global_head_hash at the window end!
    let mut folded = String::new();
    for ev in &evs {
        folded = ua_store::evidence_bundle::org_chain_fold(&folded, ev.entry_hash.as_deref().unwrap());
    }
    let mut buf = Vec::new();
    for ev in &evs {
        buf.extend_from_slice(&to_canonical_bytes(ev).unwrap());
        buf.push(b'\n');
    }
    std::fs::write(&ev_path, buf).unwrap();
    let cp_path = omitted_dir.join("ledger/checkpoint.json");
    let mut cp_file: BundleCheckpointFile =
        serde_json::from_slice(&std::fs::read(&cp_path).unwrap()).unwrap();
    cp_file.checkpoint.org_row_count = Some(1);
    cp_file.checkpoint.org_chain_hash = Some(folded);
    std::fs::write(&cp_path, to_canonical_bytes(&cp_file).unwrap()).unwrap();
    remanifest_and_resign(&omitted_dir, &sk, true);

    // Without hub cross-check: internally consistent (completeness is explicitly Unverified).
    let v_alone = verify_bundle_dir(&omitted_dir, &trust).unwrap();
    assert!(v_alone.ok);
    assert_eq!(v_alone.completeness.status, ClaimStatus::Unverified);

    // With hub cross-check: omission is detected and REFUSED (exit 1)!
    let hub_cc = load_verified_hub_cross_check(&hub_dir, &trust).unwrap().unwrap();
    let mut cc_trust = trust.clone();
    cc_trust.hub_cross_check = Some(hub_cc);
    let v_cc = verify_bundle_dir(&omitted_dir, &cc_trust).unwrap();
    assert_eq!(v_cc.exit_code, 1);
    assert_eq!(v_cc.reason.as_deref(), Some("hub_cross_check_mismatch"));

    // Incremental hub bundle with pinned_hub head.
    let inc_hub_dir = out.path().join("hub_inc");
    let mut inc_opts = export_opts(&cp_hub);
    inc_opts.from_seq = Some(2);
    db.read(|c| export_bundle(c, &inc_hub_dir, &inc_opts)).unwrap();
    sign_bundle_offline(&inc_hub_dir, &sk);

    let seq2_hash: String = db
        .read(|c| Ok(c.query_row("SELECT entry_hash FROM event_log WHERE seq = 2", [], |r| r.get(0))?))
        .unwrap();
    let v_unpinned = verify_bundle_dir(&inc_hub_dir, &trust).unwrap();
    assert_eq!(v_unpinned.exit_code, 2);
    assert_eq!(v_unpinned.reason.as_deref(), Some("missing_pinned_checkpoint"));

    let mut pinned_hub_trust = trust;
    pinned_hub_trust.pinned_hub = Some(PinnedHubHead { seq: 2, hash: seq2_hash });
    let v_pinned = verify_bundle_dir(&inc_hub_dir, &pinned_hub_trust).unwrap();
    assert!(v_pinned.ok, "incremental hub bundle with pin failed: {v_pinned:?}");
    assert_eq!(v_pinned.completeness.status, ClaimStatus::Verified);
}

fn write_hub_cp_at_head(
    tx: &mut ua_store::WriteTx<'_>,
    cp_id: &str,
    sk: &SigningKey,
    key_id: &str,
) -> ua_core::UaResult<String> {
    let (seq, hash): (i64, String) = tx.query_row(
        "SELECT seq, entry_hash FROM event_log WHERE entry_hash IS NOT NULL ORDER BY seq DESC LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let cp = Checkpoint {
        checkpoint_id: cp_id.into(),
        class: CheckpointClass::Hub,
        org_id: None,
        seq: Some(seq),
        hash: Some(hash),
        window: None,
        global_from_hash: None,
        global_head_hash: None,
        org_row_count: None,
        org_chain_hash: None,
        key_id: key_id.into(),
        signed_at: "2026-11-25T12:05:00Z".into(),
    };
    let d = checkpoint_write(tx, &cp, "2026-11-25T12:05:00Z")?;
    checkpoint_attach(tx, &cp.checkpoint_id, &sign_hex_digest(sk, &d))?;
    Ok(cp.checkpoint_id)
}

/// Pins all 12 red-tier review egress probes end-to-end:
/// - The 8 secret/token/PEM/nested-JSON probes refuse export outright and fail
///   verify (exit 1, `forbidden_private_content`) if injected into a bundle.
/// - The 4 restricted-channel probes (`agent.lifecycle.handoff_hook`,
///   `agent.mailbox.read`, `agent.message.inform` with `text`,
///   `agent.conversation.handoff`) plus `agent.message.request` with `body` are
///   exported ONLY as hash-only stubs (`redacted: true`, zero content leaked),
///   verify cleanly (exit 0) with explicit per-row `integrity.basis` and
///   `redacted_events`, and refuse verify (exit 1) if present unredacted.
#[test]
fn all_twelve_review_egress_probes_are_blocked_or_hash_only_redacted() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });

    let secret_probes: &[(&str, &str, Value)] = &[
        ("gh_token_key", "agent.log", json!({ "token": "ghp_0123456789abcdef0123456789abcdef0123" })),
        (
            "gh_pat_free_text",
            "agent.log",
            json!({ "notes": "pushed with github_pat_11ABCDEF0123456789_xyz9876543210abcdef" }),
        ),
        (
            "nested_bearer_header",
            "sdk.http",
            json!({ "headers": { "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig1234567890" } }),
        ),
        ("password_object", "sdk.auth", json!({ "password": { "raw": "hunter2" } })),
        ("api_key_array", "sdk.auth", json!({ "api_key": ["k1", "k2"] })),
        ("camel_access_token", "sdk.auth", json!({ "accessToken": "opaque-token-12345" })),
        ("json_in_string_secret", "sdk.raw", json!({ "blob": r#"{"clientSecret":"embedded-secret-xyz"}"# })),
        (
            "pem_private_key",
            "sdk.key",
            json!({ "pem": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQ==\n-----END PRIVATE KEY-----" }),
        ),
    ];

    for (label, channel, payload) in secret_probes {
        let (_dir, db) = open_test_db();
        let cp_id = db
            .write(|tx| {
                key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
                ledger::append(tx, EventInput::new("default", *channel, payload.clone()).by("builder-1"))?;
                write_hub_cp_at_head(tx, "cp-secret-probe", &sk, FIXTURE_KEY_ID)
            })
            .unwrap();
        // Client payloads are never exported in clear: the row is a counted
        // hash-only stub, and its content never blocks the export.
        let out = tempdir().unwrap();
        let bundle_dir = out.path().join("bundle");
        db.read(|c| export_bundle(c, &bundle_dir, &export_opts(&cp_id)))
            .unwrap_or_else(|e| panic!("probe {label} must export (stubbed), got: {e}"));
        sign_bundle_offline(&bundle_dir, &sk);
        let evs = read_events(&bundle_dir);
        assert!(evs.iter().all(|e| e.channel != *channel), "probe {label} channel left in clear");
        assert!(
            evs.iter().any(|e| e.redacted_class.as_deref() == Some(CLASS_UNLISTED_PAYLOAD)),
            "probe {label}"
        );
        let v = verify_bundle_dir(&bundle_dir, &trust).unwrap();
        assert!(v.ok, "probe {label} bundle must verify: {v:?}");

        // Also prove verifier refuses if the same secret is injected into an existing bundle.
        let vtmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), vtmp.path());
        let ev_path = vtmp.path().join("ledger/events.jsonl");
        let mut evs: Vec<BundleLedgerEvent> = std::fs::read_to_string(&ev_path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        evs[0].channel = (*channel).to_string();
        evs[0].payload = payload.to_string();
        let mut buf = Vec::new();
        for ev in &evs {
            buf.extend_from_slice(&to_canonical_bytes(ev).unwrap());
            buf.push(b'\n');
        }
        std::fs::write(&ev_path, buf).unwrap();
        remanifest_and_resign(vtmp.path(), &sk, false);
        let v = verify_bundle_dir(vtmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1, "verifier must refuse probe {label}: {v:?}");
        assert!(
            matches!(v.reason.as_deref(), Some("forbidden_private_content" | "unlisted_payload_in_clear")),
            "probe {label}: {v:?}"
        );
    }

    // The 4 restricted-channel probes + a default message event with a body:
    // export MUST succeed by emitting hash-only stubs (zero content leaked) and
    // verify MUST pass (exit 0) while reporting redacted_events & per-row integrity.
    let restricted_probes: &[(&str, Value, &str)] = &[
        (
            "agent.lifecycle.handoff_hook",
            json!({ "session_id": "s1", "secret_note": "private-hook-content" }),
            CLASS_PRIVATE_RECORDS,
        ),
        ("agent.mailbox.read", json!({ "message_id": "m-1", "reader": "builder-1" }), CLASS_PRIVATE_MESSAGES),
        (
            "agent.message.inform",
            json!({ "text": "private-inform-text", "to": "builder-2" }),
            CLASS_PRIVATE_MESSAGES,
        ),
        (
            "agent.conversation.handoff",
            json!({ "conversation_id": "conv-1", "summary": "private-handoff-summary" }),
            CLASS_PRIVATE_RECORDS,
        ),
        (
            "agent.message.request",
            json!({ "body": "private-dm-body", "to": "builder-2" }),
            CLASS_PRIVATE_MESSAGES,
        ),
    ];

    let (_dir, db) = open_test_db();
    let cp_id = db
        .write(|tx| {
            key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
            ledger::append(tx, EventInput::new("default", "agent.task.created", json!({ "task_id": 1 })))?;
            for (ch, pl, _) in restricted_probes {
                ledger::append(tx, EventInput::new("default", *ch, pl.clone()).by("builder-1"))?;
            }
            ledger::append(tx, EventInput::new("default", "agent.task.completed", json!({ "task_id": 1 })))?;
            write_hub_cp_at_head(tx, "cp-restricted", &sk, FIXTURE_KEY_ID)
        })
        .unwrap();

    let out = tempdir().unwrap();
    let bundle_dir = out.path().join("restricted_hub");
    db.read(|c| export_bundle(c, &bundle_dir, &export_opts(&cp_id))).unwrap();
    sign_bundle_offline(&bundle_dir, &sk);

    // Zero private text/channel leaked anywhere in the exported ledger file.
    let raw_events = std::fs::read_to_string(bundle_dir.join("ledger/events.jsonl")).unwrap();
    for needle in [
        "private-hook-content",
        "private-inform-text",
        "private-handoff-summary",
        "private-dm-body",
        "agent.lifecycle.handoff_hook",
        "agent.mailbox.read",
        "agent.message.inform",
        "agent.conversation.handoff",
        "agent.message.request",
    ] {
        assert!(!raw_events.contains(needle), "exported bundle leaked {needle:?}:\n{raw_events}");
    }

    let evs: Vec<BundleLedgerEvent> = raw_events
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let redacted_evs: Vec<&BundleLedgerEvent> = evs.iter().filter(|e| e.redacted).collect();
    assert_eq!(redacted_evs.len(), restricted_probes.len());
    for (ev, (_, _, expected_class)) in redacted_evs.iter().zip(restricted_probes.iter()) {
        assert_eq!(ev.channel, REDACTED_CHANNEL);
        assert!(ev.payload.is_empty());
        assert!(ev.originator.is_none());
        assert_eq!(ev.redacted_class.as_deref(), Some(*expected_class));
        assert!(ev.entry_hash.is_some());
    }

    let v = verify_bundle_dir(&bundle_dir, &trust).unwrap();
    assert!(v.ok, "bundle with hash-only redacted restricted channels must verify: {v:?}");
    assert_eq!(v.redacted_events.count, restricted_probes.len() as u64);
    assert!(
        v.integrity.basis.contains("redacted hash-only")
            && v.integrity.basis.contains("payload-hash-verified"),
        "integrity basis must report per-row coverage explicitly: {}",
        v.integrity.basis
    );

    // If any of the 4 restricted channels appears UNREDACTED in a bundle, verifier MUST refuse (exit 1).
    for (ch, pl, _) in restricted_probes {
        let vtmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), vtmp.path());
        let ev_path = vtmp.path().join("ledger/events.jsonl");
        let mut lines: Vec<BundleLedgerEvent> = std::fs::read_to_string(&ev_path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        lines[0].channel = (*ch).to_string();
        lines[0].payload = pl.to_string();
        lines[0].redacted = false;
        lines[0].redacted_class = None;
        let mut buf = Vec::new();
        for ev in &lines {
            buf.extend_from_slice(&to_canonical_bytes(ev).unwrap());
            buf.push(b'\n');
        }
        std::fs::write(&ev_path, buf).unwrap();
        remanifest_and_resign(vtmp.path(), &sk, false);
        let v = verify_bundle_dir(vtmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1, "unredacted {ch} must be refused: {v:?}");
        assert_eq!(v.reason.as_deref(), Some("forbidden_private_content"), "{v:?}");
    }
}

/// Real-hub compatibility tests:
/// 1. ORG-EVENT-DEFAULT: another org's (`acme`) `agent.approval.resolved` sits
///    in the `default` ledger -> `default`'s `org` bundle redacts it to a
///    hash-only stub (`cross_org_events`) and exits 0 (no
///    `cross_link_missing_receipt`); `hub` bundle exports its receipt with
///    pseudonymized labels and `reason: None` (respecting `ledger_label`) and
///    exits 0 with SoD verified.
/// 2. `org` bundle over a DB containing unhashed legacy rows (`entry_hash NULL`)
///    reports `unhashed_legacy_prefix = 0` and verifies cleanly.
/// 3. Unreleased deliverables (no release row, no dispatch run) verify cleanly,
///    while deliverables recorded after the checkpoint are excluded.
#[test]
fn real_hub_org_event_default_unhashed_org_and_unreleased_deliverables() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });
    let (_dir, db) = open_test_db();

    let acme_payload = json!({ "action": "acme-deploy" });
    let acme_canon = ua_core::canonical::to_string(&acme_payload);
    let acme_digest = sha256_hex(acme_canon.as_bytes());
    let policy_doc = json!({
        "version": 1,
        "rules": [{
            "name": "deploy_sod",
            "type": "tool",
            "tool": "deploy_prod",
            "action": "require_approval",
            "separation_of_duties": true
        }]
    });
    let policy_canon = ua_core::canonical::to_string(&policy_doc);
    let policy_sha = sha256_hex(policy_canon.as_bytes());

    let (default_org_cp, hub_cp) = db
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, created_at) VALUES ('acme', 'acme', 'Acme', '2026-11-20T00:00:00Z')",
                [],
            )?;
            // Insert an unhashed legacy row FIRST on default org.
            tx.execute(
                "INSERT INTO event_log (ulid, channel, payload, originator, created_at, org_id, hash_v) \
                 VALUES ('01LEG000000000000000000001', 'legacy.init', '{}', 'sys', '2026-10-01T00:00:00Z', 'default', 1)",
                [],
            )?;
            key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
            tx.execute(
                "INSERT INTO config_revisions (kind, revision, action, actor, document, document_sha256, raw_sha256, created_at) \
                 VALUES ('policy', 1, 'commit', 'operator', ?1, ?2, ?2, '2026-11-20T00:01:00Z')",
                params![policy_canon, policy_sha],
            )?;
            tx.execute(
                "INSERT INTO tasks (id, org_id, title, created_at) VALUES (7, 'default', 'Draft doc', '2026-11-20T00:02:00Z')",
                [],
            )?;
            // Unreleased deliverable (no dispatch_runs, no deliverable_releases).
            tx.execute(
                "INSERT INTO deliverables (id, org_id, task_id, kind, title, created_by, created_at) \
                 VALUES (1, 'default', 7, 'commit', 'Draft PR', 'builder-1', '2026-11-20T00:03:00Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO deliverable_revisions (id, org_id, deliverable_id, rev_no, identity, producer, recorded_at) \
                 VALUES (1, 'default', 1, 1, ?1, 'builder-1', '2026-11-20T00:03:00Z')",
                ["c".repeat(40)],
            )?;
            // Acme's approval row + ORG-EVENT-DEFAULT event written to default's ledger!
            tx.execute(
                "INSERT INTO approvals (id, org_id, tool, payload, requested_by, status, reason, resolved_by, resolved_transport, created_at, updated_at, resolved_at) \
                 VALUES (55, 'acme', 'deploy_prod', ?1, 'acme-secret-bot', 'approved', 'acme-confidential-reason', 'acme-secret-human', 'ui', '2026-11-20T00:04:00Z', '2026-11-20T00:05:00Z', '2026-11-20T00:05:00Z')",
                [&acme_canon],
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "default",
                    "agent.approval.resolved",
                    json!({
                        "approval_id": 55,
                        "tool": "deploy_prod",
                        "decision": "approve",
                        "resolved_by": Value::Null,
                        "transport": "ui",
                        "payload_sha256": acme_digest
                    }),
                )
                .by("system"),
            )?;

            let def_sum = compute_org_window_checkpoint(
                tx,
                "default",
                "2026-11-01T00:00:00Z",
                "2099-12-31T23:59:59Z",
                None,
            )?;
            let def_cp = Checkpoint {
                checkpoint_id: "cp-default-org".into(),
                class: CheckpointClass::Org,
                org_id: Some("default".into()),
                seq: None,
                hash: None,
                window: Some(def_sum.window),
                global_from_hash: Some(def_sum.global_from_hash),
                global_head_hash: Some(def_sum.global_head_hash),
                org_row_count: Some(def_sum.org_row_count),
                org_chain_hash: Some(def_sum.org_chain_hash),
                key_id: FIXTURE_KEY_ID.into(),
                signed_at: "2026-11-25T12:00:00Z".into(),
            };
            let d = checkpoint_write(tx, &def_cp, "2026-11-25T12:00:00Z")?;
            checkpoint_attach(tx, &def_cp.checkpoint_id, &sign_hex_digest(&sk, &d))?;

            let hub_cp_id = write_hub_cp_at_head(tx, "cp-hub-real", &sk, FIXTURE_KEY_ID)?;
            Ok((def_cp.checkpoint_id, hub_cp_id))
        })
        .unwrap();

    // 1. Default-org bundle verifies cleanly: ORG-EVENT-DEFAULT row is hash-only stub,
    //    unhashed legacy prefix is 0, unreleased deliverable is allowed!
    let out = tempdir().unwrap();
    let def_dir = out.path().join("default_org");
    db.read(|c| export_bundle(c, &def_dir, &export_opts(&default_org_cp))).unwrap();
    sign_bundle_offline(&def_dir, &sk);

    let v_def = verify_bundle_dir(&def_dir, &trust).unwrap();
    assert!(v_def.ok, "default org bundle with ORG-EVENT-DEFAULT + unhashed + unreleased failed: {v_def:?}");
    assert_eq!(v_def.unhashed_legacy_prefix.count, 0);
    assert_eq!(v_def.redacted_events.count, 1);
    let def_events = std::fs::read_to_string(def_dir.join("ledger/events.jsonl")).unwrap();
    assert!(def_events.contains(CLASS_CROSS_ORG_EVENTS));
    assert!(!def_events.contains("acme-secret"));
    assert!(!def_events.contains("acme-confidential-reason"));

    // 2. Hub bundle verifies cleanly and pseudonymizes acme's labels & drops acme's free-text reason.
    let hub_dir = out.path().join("hub");
    db.read(|c| export_bundle(c, &hub_dir, &export_opts(&hub_cp))).unwrap();
    sign_bundle_offline(&hub_dir, &sk);

    let v_hub = verify_bundle_dir(&hub_dir, &trust).unwrap();
    assert!(v_hub.ok, "hub bundle with acme approval + unreleased deliverable failed: {v_hub:?}");
    // Acme's resolver is `null` in the ledger (ORG-EVENT-DEFAULT): the resolver
    // and separation of duties are the hub's word, never "verified".
    assert_eq!(v_hub.separation_of_duties.status, ClaimStatus::HubAsserted);
    assert_eq!(v_hub.approvals.status, ClaimStatus::HubAsserted);
    let receipt_raw = std::fs::read_to_string(hub_dir.join("approvals/55.json")).unwrap();
    assert!(!receipt_raw.contains("acme-secret-bot"), "requester label bypassed ledger_label redaction");
    assert!(!receipt_raw.contains("acme-secret-human"), "resolver label bypassed ledger_label redaction");
    assert!(!receipt_raw.contains("acme-confidential-reason"), "tenant reason leaked");
    let rec: ApprovalReceipt = serde_json::from_str(&receipt_raw).unwrap();
    // A fixed placeholder, not a guessable hash of the label (A-S-NEW-6).
    assert_eq!(rec.requester.label, LABEL_PLACEHOLDER);
    assert_eq!(rec.resolver.label, LABEL_PLACEHOLDER);
    assert!(!rec.resolver_is_requester);
    assert!(!receipt_raw.contains("\"reason\""), "receipts carry no free-text reason");
}

/// Proves policy revisions match strictly on `(kind, revision)`, `sod_tools` is
/// derived from the hashed policy `document`, and tampering either is refused.
#[test]
fn policy_kind_revision_collision_and_document_derived_sod_verification() {
    let trust = fixture_trust();
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);

    // 1. Replace kind="policy" with kind="profile" for revision 1 -> MUST REFUSE (no collision!).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let p = tmp.path().join("policy/revisions.json");
        let mut revs: Vec<PolicyRevisionRecord> =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        revs.retain(|r| r.kind != "policy");
        assert!(revs.iter().any(|r| r.kind == "profile" && r.revision == 1));
        std::fs::write(&p, to_canonical_bytes(&revs).unwrap()).unwrap();
        // Rev 1's agent.config.revision event is still in the bundle: the
        // list is incomplete (review NS2).
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("policy_revision_missing"));
    }

    // 2. Claiming extra `sod_tools` not backed by `document` -> MUST REFUSE (`policy_sod_mismatch`).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let p = tmp.path().join("policy/revisions.json");
        let mut revs: Vec<PolicyRevisionRecord> =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let pol = revs.iter_mut().find(|r| r.kind == "policy" && r.revision == 1).unwrap();
        pol.sod_tools.push("fabricated_tool".into());
        std::fs::write(&p, to_canonical_bytes(&revs).unwrap()).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("policy_sod_mismatch"));
    }

    // 3. Tampering `document` without matching `document_sha256` -> MUST REFUSE (`policy_document_digest_mismatch`).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_hub"), tmp.path());
        let p = tmp.path().join("policy/revisions.json");
        let mut revs: Vec<PolicyRevisionRecord> =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let pol = revs.iter_mut().find(|r| r.kind == "policy" && r.revision == 1).unwrap();
        pol.document = Some(r#"{"rules":[],"version":1}"#.into());
        std::fs::write(&p, to_canonical_bytes(&revs).unwrap()).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1);
        assert_eq!(v.reason.as_deref(), Some("policy_document_digest_mismatch"));
    }
}

/// Proves:
/// 1. Re-exporting the same checkpoint AFTER later writes (new policy revisions,
///    new secrets, new tokens, new messages, new deliverable revisions, new
///    ledger events) yields the EXACT same bundle digest and file hashes.
/// 2. RFC 3339 timestamp normalization (`Z` vs `+00:00` at the exact same
///    instant) does not suffer off-by-one boundary exclusion.
#[test]
fn reexport_determinism_after_later_writes_and_timestamp_normalization() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let (_dir, db) = open_test_db();
    let (hub_cp, org_cp) = populate_sample_db(&db, &sk, FIXTURE_KEY_ID);

    let out = tempdir().unwrap();
    let hub_before = out.path().join("hub_before");
    let org_before = out.path().join("org_before");
    let res_hub_1 = db.read(|c| export_bundle(c, &hub_before, &export_opts(&hub_cp))).unwrap();
    let res_org_1 = db.read(|c| export_bundle(c, &org_before, &export_opts(&org_cp))).unwrap();

    // Perform later writes across EVERY table with timestamps AFTER the checkpoint.
    let later = "2099-01-01T00:00:00+00:00";
    db.write(|tx| {
        tx.execute(
            "INSERT INTO config_revisions (kind, revision, action, actor, document, document_sha256, raw_sha256, created_at) \
             VALUES ('policy', 2, 'commit', 'operator', '{}', ?1, ?1, ?2)",
            params![sha256_hex(b"{}"), later],
        )?;
        tx.execute(
            "INSERT INTO managed_secrets (org_id, name, ciphertext, created_at) VALUES ('default', 'later_sec', 'enc', ?1)",
            [later],
        )?;
        tx.execute(
            "INSERT INTO agent_tokens (org_id, agent_label, token_hash, issued_at) VALUES ('acme', 'late-bot', 'h99', ?1)",
            [later],
        )?;
        tx.execute(
            "INSERT INTO message_index (message_id, recipient, sender, act, conversation_id, event_ulid, event_seq, created_at) \
             VALUES ('m-late', 'builder-2', 'builder-1', 'inform', 'c-1', '01MSGLATE0000000000000000A', 9999, ?1)",
            [later],
        )?;
        tx.execute(
            "INSERT INTO deliverable_revisions (id, org_id, deliverable_id, rev_no, identity, producer, recorded_at) \
             VALUES (99, 'default', 1, 2, ?1, 'builder-1', ?2)",
            params!["d".repeat(64), later],
        )?;
        ledger::append(tx, EventInput::new("default", "agent.task.updated", json!({ "late": true })))?;
        ledger::append(tx, EventInput::new("acme", "agent.task.updated", json!({ "late": true })))?;
        Ok(())
    })
    .unwrap();

    let hub_after = out.path().join("hub_after");
    let org_after = out.path().join("org_after");
    let res_hub_2 = db.read(|c| export_bundle(c, &hub_after, &export_opts(&hub_cp))).unwrap();
    let res_org_2 = db.read(|c| export_bundle(c, &org_after, &export_opts(&org_cp))).unwrap();

    assert_eq!(res_hub_1.manifest, res_hub_2.manifest, "hub bundle manifest drifted after later writes");
    assert_eq!(res_hub_1.withheld, res_hub_2.withheld, "hub withheld.json drifted after later writes");
    assert_eq!(res_org_1.manifest, res_org_2.manifest, "org bundle manifest drifted after later writes");
    assert_eq!(res_org_1.withheld, res_org_2.withheld, "org withheld.json drifted after later writes");

    // Timestamp boundary check: event with `+00:00` at the exact same instant as `Z` window_start
    // MUST be included (not skipped due to `'+' < 'Z'` lexical ordering).
    let (_dir2, db2) = open_test_db();
    let exact_sum = db2
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, created_at) VALUES ('acme', 'acme', 'Acme', '2026-11-20T00:00:00Z')",
                [],
            )?;
            key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00+00:00", None)?;
            let prev: String = tx.query_row(
                "SELECT entry_hash FROM event_log ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )?;
            let ts_plus = "2026-11-25T12:00:00+00:00";
            let ulid = "01EXACT0000000000000000001";
            let eh = compute_entry_hash_v2(
                Some(&prev),
                ulid,
                "acme.boundary",
                r#"{"n":1}"#,
                None,
                None,
                None,
                ts_plus,
                None,
                "acme",
            );
            tx.execute(
                "INSERT INTO event_log (ulid, channel, payload, created_at, prev_hash, entry_hash, org_id, hash_v) \
                 VALUES (?1, 'acme.boundary', '{\"n\":1}', ?2, ?3, ?4, 'acme', 2)",
                params![ulid, ts_plus, prev, eh],
            )?;
            compute_org_window_checkpoint(tx, "acme", "2026-11-25T12:00:00Z", "2026-11-25T12:00:00Z", None)
        })
        .unwrap();
    assert_eq!(exact_sum.window_org_rows, 1, "event at +00:00 matching Z boundary must be included");
    assert_eq!(exact_sum.org_row_count, 1);
}

/// Proves that `org`-class bundles map task, deliverable, and approval IDs to
/// dense per-organization ordinals (`1, 2, ...`) and omit global
/// `config_revisions.id`, so gaps created by other orgs never reveal volume.
#[test]
fn org_bundle_uses_dense_local_ids_without_hub_volume_gaps() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });
    let (_dir, db) = open_test_db();

    let cp_id = db
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, created_at) VALUES ('acme', 'acme', 'Acme', '2026-11-20T00:00:00Z')",
                [],
            )?;
            key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
            // Insert 50 default tasks & deliverables to create huge autoincrement gaps before acme's rows.
            for i in 1..=50i64 {
                tx.execute(
                    "INSERT INTO tasks (id, org_id, title, created_at) VALUES (?1, 'default', 'def', '2026-11-20T00:01:00Z')",
                    [i],
                )?;
                tx.execute(
                    "INSERT INTO deliverables (id, org_id, task_id, kind, title, created_by, created_at) \
                     VALUES (?1, 'default', ?1, 'commit', 'd', 'builder-1', '2026-11-20T00:01:00Z')",
                    [i],
                )?;
            }
            // Acme gets hub task_id=51 and task_id=80 (with more default rows in between),
            // and deliverable_id=51 and deliverable_id=80.
            tx.execute(
                "INSERT INTO tasks (id, org_id, title, created_at) VALUES \
                 (51, 'acme', 'a1', '2026-11-20T00:02:00Z'), \
                 (80, 'acme', 'a2', '2026-11-20T00:03:00Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO deliverables (id, org_id, task_id, kind, title, created_by, created_at) VALUES \
                 (51, 'acme', 51, 'commit', 'd1', 'acme-bot', '2026-11-20T00:02:00Z'), \
                 (80, 'acme', 80, 'commit', 'd2', 'acme-bot', '2026-11-20T00:03:00Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO deliverable_revisions (id, org_id, deliverable_id, rev_no, identity, producer, recorded_at) VALUES \
                 (51, 'acme', 51, 1, ?1, 'acme-bot', '2026-11-20T00:02:00Z'), \
                 (80, 'acme', 80, 1, ?2, 'acme-bot', '2026-11-20T00:03:00Z')",
                params!["a".repeat(40), "b".repeat(40)],
            )?;
            ledger::append(tx, EventInput::new("acme", "evidence.attestation", json!({ "task_id": 51 })))?;
            ledger::append(tx, EventInput::new("acme", "evidence.attestation", json!({ "task_id": 80 })))?;

            let s = compute_org_window_checkpoint(
                tx,
                "acme",
                "2026-11-01T00:00:00Z",
                "2099-12-31T23:59:59Z",
                None,
            )?;
            let cp = Checkpoint {
                checkpoint_id: "cp-acme-dense".into(),
                class: CheckpointClass::Org,
                org_id: Some("acme".into()),
                seq: None,
                hash: None,
                window: Some(s.window),
                global_from_hash: Some(s.global_from_hash),
                global_head_hash: Some(s.global_head_hash),
                org_row_count: Some(s.org_row_count),
                org_chain_hash: Some(s.org_chain_hash),
                key_id: FIXTURE_KEY_ID.into(),
                signed_at: "2026-11-25T12:00:00Z".into(),
            };
            let d = checkpoint_write(tx, &cp, "2026-11-25T12:00:00Z")?;
            checkpoint_attach(tx, &cp.checkpoint_id, &sign_hex_digest(&sk, &d))?;
            Ok(cp.checkpoint_id)
        })
        .unwrap();

    let out = tempdir().unwrap();
    let dir = out.path().join("acme_dense");
    db.read(|c| export_bundle(c, &dir, &export_opts(&cp_id))).unwrap();
    sign_bundle_offline(&dir, &sk);

    let v = verify_bundle_dir(&dir, &trust).unwrap();
    assert!(v.ok, "dense org bundle failed verify: {v:?}");

    let arts: Vec<ArtifactIndexEntry> =
        serde_json::from_slice(&std::fs::read(dir.join("artifacts/index.json")).unwrap()).unwrap();
    assert_eq!(arts.len(), 2);
    assert_eq!(arts[0].id, "deliverable:1");
    assert_eq!(arts[0].task_id, 1);
    assert_eq!(arts[1].id, "deliverable:2");
    assert_eq!(arts[1].task_id, 2);

    let pol: Vec<PolicyRevisionRecord> =
        serde_json::from_slice(&std::fs::read(dir.join("policy/revisions.json")).unwrap()).unwrap();
    assert!(pol.is_empty(), "uncited hub policy revisions must not appear in org bundle");
}

/// Hardening tests: symlinks (hashed file symlinked outside bundle, self-pointing
/// directory symlink loop) and oversized files are refused immediately (exit 1).
#[test]
fn verifier_refuses_symlinks_loops_and_oversized_files() {
    let trust = fixture_trust();

    // 1. Oversized file refused by byte cap (exit 1, `file_too_large`).
    let v_big = verify_bundle_dir_with_limits(&fixtures_root().join("good_hub"), &trust, 64, 1024).unwrap();
    assert_eq!(v_big.exit_code, 1);
    assert_eq!(v_big.reason.as_deref(), Some("file_too_large"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        // 2. Hashed file symlinked outside the bundle -> REFUSED (`symlink_not_allowed`).
        let tmp = tempdir().unwrap();
        let outside = tmp.path().join("outside_withheld.json");
        let bundle = tmp.path().join("bundle");
        copy_dir_recursive(&fixtures_root().join("good_hub"), &bundle);
        std::fs::copy(bundle.join("withheld.json"), &outside).unwrap();
        std::fs::remove_file(bundle.join("withheld.json")).unwrap();
        symlink(&outside, bundle.join("withheld.json")).unwrap();

        let v = verify_bundle_dir(&bundle, &trust).unwrap();
        assert_eq!(v.exit_code, 1, "symlinked hashed file must refuse: {v:?}");
        assert_eq!(v.reason.as_deref(), Some("symlink_not_allowed"));

        // 3. Self-pointing directory symlink (`loop -> .`) -> terminates immediately and REFUSES.
        let tmp_loop = tempdir().unwrap();
        let bundle_loop = tmp_loop.path().join("bundle");
        copy_dir_recursive(&fixtures_root().join("good_hub"), &bundle_loop);
        symlink(".", bundle_loop.join("loop")).unwrap();

        let v_loop = verify_bundle_dir(&bundle_loop, &trust).unwrap();
        assert_eq!(v_loop.exit_code, 1, "self-pointing dir symlink must refuse: {v_loop:?}");
        assert_eq!(v_loop.reason.as_deref(), Some("symlink_not_allowed"));
    }
}

/// Kills the four mutations reported surviving in review:
/// - V11: foreign `org_id` in an `org` bundle
/// - V12: global `seq` leaked into an `org` bundle
/// - V16: tampered `org_chain_hash` in a signed `org` checkpoint
/// - V18: path traversal (`../`) in `manifest.files`
#[test]
fn mutations_v11_v12_v16_v18_are_all_refused() {
    let trust = fixture_trust();
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);

    // V11: foreign `org_id` in an `org` bundle (even with valid recomputed hash and re-signed checkpoint).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_org"), tmp.path());
        let ev_path = tmp.path().join("ledger/events.jsonl");
        let mut evs: Vec<BundleLedgerEvent> = std::fs::read_to_string(&ev_path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        evs[0].org_id = "foreign-org".into();
        evs[0].entry_hash = Some(compute_entry_hash_v2(
            evs[0].prev_hash.as_deref(),
            &evs[0].ulid,
            &evs[0].channel,
            &evs[0].payload,
            evs[0].originator.as_deref(),
            evs[0].episode_id.as_deref(),
            evs[0].causal_parent_id.as_deref(),
            &evs[0].created_at,
            evs[0].dedupe_key.as_deref(),
            &evs[0].org_id,
        ));
        let mut folded = String::new();
        let mut buf = Vec::new();
        for ev in &evs {
            folded = org_chain_fold(&folded, ev.entry_hash.as_deref().unwrap());
            buf.extend_from_slice(&to_canonical_bytes(ev).unwrap());
            buf.push(b'\n');
        }
        std::fs::write(&ev_path, buf).unwrap();
        let cp_path = tmp.path().join("ledger/checkpoint.json");
        let mut cp_file: BundleCheckpointFile =
            serde_json::from_slice(&std::fs::read(&cp_path).unwrap()).unwrap();
        cp_file.checkpoint.org_chain_hash = Some(folded);
        std::fs::write(&cp_path, to_canonical_bytes(&cp_file).unwrap()).unwrap();
        remanifest_and_resign(tmp.path(), &sk, true);

        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1, "V11 foreign org_id must refuse: {v:?}");
        assert_eq!(v.reason.as_deref(), Some("org_scope_violation"));
    }

    // V12: global `seq` leaked into an `org` bundle.
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_org"), tmp.path());
        let ev_path = tmp.path().join("ledger/events.jsonl");
        let mut evs: Vec<BundleLedgerEvent> = std::fs::read_to_string(&ev_path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        evs[0].seq = Some(42);
        let mut buf = Vec::new();
        for ev in &evs {
            buf.extend_from_slice(&to_canonical_bytes(ev).unwrap());
            buf.push(b'\n');
        }
        std::fs::write(&ev_path, buf).unwrap();
        remanifest_and_resign(tmp.path(), &sk, false);

        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1, "V12 global seq in org bundle must refuse: {v:?}");
        assert_eq!(v.reason.as_deref(), Some("org_scope_violation"));
    }

    // V16: tampered `org_chain_hash` in a signed `org` checkpoint (all rows valid, count matches).
    {
        let tmp = tempdir().unwrap();
        copy_dir_recursive(&fixtures_root().join("good_org"), tmp.path());
        let cp_path = tmp.path().join("ledger/checkpoint.json");
        let mut cp_file: BundleCheckpointFile =
            serde_json::from_slice(&std::fs::read(&cp_path).unwrap()).unwrap();
        cp_file.checkpoint.org_chain_hash = Some("0".repeat(64));
        std::fs::write(&cp_path, to_canonical_bytes(&cp_file).unwrap()).unwrap();
        remanifest_and_resign(tmp.path(), &sk, true);

        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1, "V16 tampered org_chain_hash must refuse: {v:?}");
        assert_eq!(v.reason.as_deref(), Some("org_chain_hash_mismatch"));
    }

    // V18: path traversal (`../escape.txt`) listed in `manifest.files`.
    {
        let tmp = tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        copy_dir_recursive(&fixtures_root().join("good_hub"), &bundle);
        let escape = tmp.path().join("escape.txt");
        std::fs::write(&escape, b"outside").unwrap();
        let manifest_path = bundle.join("manifest.json");
        let mut manifest: BundleManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest.files.insert("../escape.txt".into(), sha256_hex(b"outside"));
        manifest.digest = manifest.recompute_digest().unwrap();
        std::fs::write(&manifest_path, to_canonical_bytes(&manifest).unwrap()).unwrap();
        sign_bundle_offline(&bundle, &sk);

        let v = verify_bundle_dir(&bundle, &trust).unwrap();
        assert_eq!(v.exit_code, 1, "V18 path traversal must refuse: {v:?}");
        assert_eq!(v.reason.as_deref(), Some("invalid_manifest_path"));
    }
}

// ---------------------------------------------------------------------------
// Fix round on #2716 S3b+S3c (reviews A and B at 1177b19d)
// ---------------------------------------------------------------------------

fn read_events(dir: &Path) -> Vec<BundleLedgerEvent> {
    std::fs::read_to_string(dir.join("ledger/events.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn write_events(dir: &Path, evs: &[BundleLedgerEvent]) {
    let mut out = Vec::new();
    for ev in evs {
        out.extend_from_slice(&to_canonical_bytes(ev).unwrap());
        out.push(b'\n');
    }
    std::fs::write(dir.join("ledger/events.jsonl"), out).unwrap();
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn write_json<T: serde::Serialize>(path: &Path, v: &T) {
    std::fs::write(path, to_canonical_bytes(v).unwrap()).unwrap();
}

fn make_stub(ev: &mut BundleLedgerEvent, class: &str) {
    ev.channel = REDACTED_CHANNEL.into();
    ev.payload = String::new();
    ev.originator = None;
    ev.episode_id = None;
    ev.causal_parent_id = None;
    ev.dedupe_key = None;
    ev.redacted = true;
    ev.redacted_class = Some(class.into());
}

/// Add `n` to `withheld.json` class `class` and the manifest's
/// `withheld_total` (the caller re-manifests afterwards).
fn bump_withheld(dir: &Path, class: &str, n: u64) {
    let wp = dir.join("withheld.json");
    let mut w: WithheldReport = read_json(&wp);
    w.record(class, n);
    write_json(&wp, &w);
    let mp = dir.join("manifest.json");
    let mut m: BundleManifest = read_json(&mp);
    m.counts.withheld_total = w.total;
    write_json(&mp, &m);
}

/// Edit `manifest.json` in place, recompute its digest and re-sign.
fn edit_manifest(dir: &Path, sk: &SigningKey, f: impl FnOnce(&mut BundleManifest)) {
    let mp = dir.join("manifest.json");
    let mut m: BundleManifest = read_json(&mp);
    f(&mut m);
    m.digest = m.recompute_digest().unwrap();
    write_json(&mp, &m);
    sign_bundle_offline(dir, sk);
}

fn edit_receipt(dir: &Path, id: i64, f: impl FnOnce(&mut ApprovalReceipt)) {
    let p = dir.join(format!("approvals/{id}.json"));
    let mut r: ApprovalReceipt = read_json(&p);
    f(&mut r);
    r.receipt_id = r.compute_receipt_id().unwrap();
    write_json(&p, &r);
}

fn good_copy(name: &str) -> tempfile::TempDir {
    let tmp = tempdir().unwrap();
    copy_dir_recursive(&fixtures_root().join(name), tmp.path());
    tmp
}

fn export_signed(db: &Db, cp: &str, dir: &Path, sk: &SigningKey) {
    db.read(|c| export_bundle(c, dir, &export_opts(cp))).unwrap();
    sign_bundle_offline(dir, sk);
}

fn assert_refused(v: &ua_store::evidence_bundle::BundleVerdict, reason: &str) {
    assert_eq!(v.exit_code, 1, "expected refusal {reason}, got {v:?}");
    assert_eq!(v.reason.as_deref(), Some(reason), "{v:?}");
}

/// Blocker 2 (A-B2, B-S1): a redaction stub is the exporter's assertion.
/// It must be counted in withheld.json under its class, `cross_org_events`
/// exists only in default-organization org bundles, a stub of a row the hub
/// bundle shows in clear is refused, and the verdict says receipts,
/// cross-links and SoD cover unredacted rows only. Pins mutations N09-N13.
#[test]
fn redaction_stubs_are_counted_scoped_cross_checked_and_reported() {
    let trust = fixture_trust();
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);
    let note = "covers unredacted ledger rows only";
    let idx_of = |evs: &[BundleLedgerEvent], ch: &str| evs.iter().position(|e| e.channel == ch).unwrap();

    // S1: an ordinary row stubbed as private_records without a withheld count refuses.
    let tmp = good_copy("good_hub");
    let mut evs = read_events(tmp.path());
    let i = idx_of(&evs, "agent.task.created");
    make_stub(&mut evs[i], CLASS_PRIVATE_RECORDS);
    write_events(tmp.path(), &evs);
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "withheld_count_mismatch");
    // Counted, it verifies, but the verdict says what a stub cannot prove.
    bump_withheld(tmp.path(), CLASS_PRIVATE_RECORDS, 1);
    remanifest_and_resign(tmp.path(), &sk, false);
    let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
    assert!(v.ok, "{v:?}");
    assert!(v.warnings.iter().any(|w| w.contains(note)), "{:?}", v.warnings);
    assert!(v.completeness.basis.contains(note));
    assert!(v.separation_of_duties.basis.contains(note));
    assert!(v.approvals.basis.contains(note));

    // S2: cross_org_events in a hub bundle refuses, even when counted.
    let tmp = good_copy("good_hub");
    let mut evs = read_events(tmp.path());
    let i = idx_of(&evs, "agent.task.created");
    make_stub(&mut evs[i], CLASS_CROSS_ORG_EVENTS);
    write_events(tmp.path(), &evs);
    bump_withheld(tmp.path(), CLASS_CROSS_ORG_EVENTS, 1);
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "invalid_redacted_event");

    // S3: an evidence row whose event is stubbed no longer matches the rebuilt rows.
    let tmp = good_copy("good_hub");
    let mut evs = read_events(tmp.path());
    let i = idx_of(&evs, "agent.deliverable.revised");
    make_stub(&mut evs[i], CLASS_PRIVATE_MESSAGES);
    write_events(tmp.path(), &evs);
    bump_withheld(tmp.path(), CLASS_PRIVATE_MESSAGES, 1);
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "evidence_row_mismatch");

    // S4: stubbing the approval and dropping its receipt is the documented
    // limit of the stub form: it verifies, and the verdict says the approval
    // claims cover unredacted rows only (follow-up: commit H(payload)).
    let tmp = good_copy("good_hub");
    let mut evs = read_events(tmp.path());
    let i = idx_of(&evs, "agent.approval.resolved");
    let ulid = evs[i].ulid.clone();
    make_stub(&mut evs[i], CLASS_PRIVATE_RECORDS);
    write_events(tmp.path(), &evs);
    std::fs::remove_file(tmp.path().join("approvals/10.json")).unwrap();
    let ap = tmp.path().join("artifacts/index.json");
    let mut arts: Vec<ArtifactIndexEntry> = read_json(&ap);
    arts[0].release_status = "unreleased".into();
    arts[0].approval_id = None;
    write_json(&ap, &arts);
    let rows_path = tmp.path().join("evidence/rows.jsonl");
    let kept: Vec<String> = std::fs::read_to_string(&rows_path)
        .unwrap()
        .lines()
        .filter(|l| !l.contains(&ulid))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&rows_path, kept.concat()).unwrap();
    {
        let mut m: BundleManifest = read_json(&tmp.path().join("manifest.json"));
        m.files.remove("approvals/10.json");
        write_json(&tmp.path().join("manifest.json"), &m);
    }
    bump_withheld(tmp.path(), CLASS_PRIVATE_RECORDS, 1);
    remanifest_and_resign(tmp.path(), &sk, false);
    let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.redacted_events.count, 1);
    assert!(v.approvals.basis.contains(note), "{:?}", v.approvals);
    assert!(v.warnings.iter().any(|w| w.contains(note)));

    // N09: a stub that keeps its payload refuses.
    let tmp = good_copy("good_hub");
    let mut evs = read_events(tmp.path());
    let i = idx_of(&evs, "agent.task.created");
    make_stub(&mut evs[i], CLASS_PRIVATE_RECORDS);
    evs[i].payload = "{\"kept\":true}".into();
    write_events(tmp.path(), &evs);
    bump_withheld(tmp.path(), CLASS_PRIVATE_RECORDS, 1);
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "invalid_redacted_event");

    // N10: an unknown redacted_class refuses.
    let tmp = good_copy("good_hub");
    let mut evs = read_events(tmp.path());
    let i = idx_of(&evs, "agent.task.created");
    make_stub(&mut evs[i], "bogus_class");
    write_events(tmp.path(), &evs);
    bump_withheld(tmp.path(), "bogus_class", 1);
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "invalid_redacted_event");

    // N11: manifest counts.redacted_events must equal the stubs.
    let tmp = good_copy("good_org");
    edit_manifest(tmp.path(), &sk, |m| m.counts.redacted_events += 1);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "count_mismatch");

    // N12: an unredacted row must not carry redacted_class.
    let tmp = good_copy("good_hub");
    let mut evs = read_events(tmp.path());
    evs[0].redacted_class = Some(CLASS_PRIVATE_RECORDS.into());
    write_events(tmp.path(), &evs);
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "invalid_redacted_event");

    // N13: a stub's entry_hash must be 64 hex characters.
    let tmp = good_copy("good_org");
    let mut evs = read_events(tmp.path());
    make_stub(&mut evs[0], CLASS_PRIVATE_RECORDS);
    evs[0].entry_hash = Some("zz".into());
    write_events(tmp.path(), &evs);
    bump_withheld(tmp.path(), CLASS_PRIVATE_RECORDS, 1);
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "invalid_redacted_event");

    // B-S1: an org bundle stub of a row the verified hub bundle shows in clear
    // on a non-restricted channel is refused under --hub-bundle.
    let tmp = good_copy("good_org");
    let mut evs = read_events(tmp.path());
    let i = idx_of(&evs, "agent.task.completed");
    make_stub(&mut evs[i], CLASS_PRIVATE_RECORDS);
    write_events(tmp.path(), &evs);
    bump_withheld(tmp.path(), CLASS_PRIVATE_RECORDS, 1);
    remanifest_and_resign(tmp.path(), &sk, false);
    let alone = verify_bundle_dir(tmp.path(), &trust).unwrap();
    assert!(alone.ok, "{alone:?}");
    assert!(alone.warnings.iter().any(|w| w.contains(note)));
    let hub_cc = load_verified_hub_cross_check(&fixtures_root().join("good_hub"), &trust).unwrap().unwrap();
    let mut cc_trust = trust.clone();
    cc_trust.hub_cross_check = Some(hub_cc);
    assert_refused(&verify_bundle_dir(tmp.path(), &cc_trust).unwrap(), "unjustified_redaction");
}

/// Blocker 3 (B-B1): every field the hash-verified `agent.approval.resolved`
/// event records binds the receipt, and the verifier picks the policy in force.
#[test]
fn receipts_bind_every_field_to_the_hash_verified_approval_event() {
    let trust = fixture_trust();
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);
    let base = verify_bundle_dir(&fixtures_root().join("good_hub"), &trust).unwrap();
    assert!(base.ok);
    assert_eq!(base.approvals.status, ClaimStatus::Verified);
    assert_eq!(base.separation_of_duties.status, ClaimStatus::Verified);

    type Mutation = (&'static str, Box<dyn Fn(&mut ApprovalReceipt)>);
    let cases: Vec<(Mutation, &str)> = vec![
        (("tool", Box::new(|r| r.tool = "harmless_tool".into())), "receipt_event_mismatch"),
        (("decision", Box::new(|r| r.decision = "denied".into())), "receipt_event_mismatch"),
        (
            ("resolver label", Box::new(|r| r.resolver.label = "forged-resolver".into())),
            "receipt_event_mismatch",
        ),
        (("transport", Box::new(|r| r.resolver.transport = Some("slack".into()))), "receipt_event_mismatch"),
        (
            ("expires_at", Box::new(|r| r.expires_at = Some("2030-01-01T00:00:00Z".into()))),
            "receipt_event_mismatch",
        ),
        (
            ("requester label", Box::new(|r| r.requester.label = "someone-else".into())),
            "receipt_event_mismatch",
        ),
        (("resolver_is_requester", Box::new(|r| r.resolver_is_requester = true)), "receipt_event_mismatch"),
        (
            ("decided_at after", Box::new(|r| r.decided_at = "2099-01-01T00:00:00Z".into())),
            "receipt_decided_at_out_of_range",
        ),
        (
            ("decided_at before request", Box::new(|r| r.decided_at = "2001-01-01T00:00:00Z".into())),
            "receipt_decided_at_out_of_range",
        ),
        (
            ("decided_at not RFC 3339", Box::new(|r| r.decided_at = "!".into())),
            "receipt_decided_at_out_of_range",
        ),
        (
            (
                "no policy cited",
                Box::new(|r| {
                    r.policy_revision = None;
                    r.policy_digest = None;
                }),
            ),
            "receipt_policy_mismatch",
        ),
        (("other policy cited", Box::new(|r| r.policy_revision = Some(2))), "receipt_policy_mismatch"),
    ];
    for ((name, f), reason) in cases {
        let tmp = good_copy("good_hub");
        edit_receipt(tmp.path(), 10, |r| f(r));
        remanifest_and_resign(tmp.path(), &sk, false);
        let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
        assert_eq!(v.exit_code, 1, "{name}: {v:?}");
        assert_eq!(v.reason.as_deref(), Some(reason), "{name}: {v:?}");
    }
}

/// A minimal default-organization release: task 42, deliverable 1 rev 1,
/// approval 10 (requested by `requester`, resolved by `resolver`), its
/// requested/resolved events, and a signed hub checkpoint at the head.
struct ReleaseSeed {
    policy: Option<Value>,
    config_event: bool,
    requester: &'static str,
    resolver: &'static str,
    /// A second policy revision (with its config event) created after the
    /// first and before the approval.
    second_policy: bool,
    /// `(decision, resolver)` resolutions after the request; empty means one
    /// approve by `resolver`. The release event follows the first approve.
    resolutions: &'static [(&'static str, &'static str)],
}

fn seed_release_hub(db: &Db, sk: &SigningKey, pk: &str, seed: &ReleaseSeed) -> String {
    let payload_obj = json!({ "deliverable_id": 1, "revision": 1, "destination": "release/report.md" });
    let canon = ua_core::canonical::to_string(&payload_obj);
    let digest = sha256_hex(canon.as_bytes());
    let artifact_sha = "e".repeat(64);
    db.write(|tx| {
        key_add(tx, FIXTURE_KEY_ID, pk, "2026-11-20T00:00:00Z", None)?;
        if let Some(doc) = &seed.policy {
            let doc_canon = ua_core::canonical::to_string(doc);
            let doc_sha = sha256_hex(doc_canon.as_bytes());
            tx.execute(
                "INSERT INTO config_revisions (kind, revision, action, actor, document, document_sha256, raw_sha256, created_at) \
                 VALUES ('policy', 1, 'commit', 'operator', ?1, ?2, ?2, '2026-11-20T00:01:00Z')",
                params![doc_canon, doc_sha],
            )?;
            if seed.config_event {
                ledger::append(
                    tx,
                    EventInput::new(
                        "default",
                        "agent.config.revision",
                        json!({ "schema": 1, "kind": "policy", "revision": 1, "action": "commit",
                                "actor": "operator", "document_sha256": doc_sha, "raw_sha256": doc_sha,
                                "approval_id": null, "diff": "" }),
                    )
                    .by("operator"),
                )?;
            }
        }
        if seed.second_policy {
            let doc = json!({ "version": 2, "rules": [{ "tool": "deliverable_release", "action": "require_approval" }] });
            let doc_canon = ua_core::canonical::to_string(&doc);
            let doc_sha = sha256_hex(doc_canon.as_bytes());
            tx.execute(
                "INSERT INTO config_revisions (kind, revision, action, actor, document, document_sha256, raw_sha256, created_at) \
                 VALUES ('policy', 2, 'commit', 'operator', ?1, ?2, ?2, '2026-11-20T00:04:30Z')",
                params![doc_canon, doc_sha],
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "default",
                    "agent.config.revision",
                    json!({ "schema": 1, "kind": "policy", "revision": 2, "action": "commit",
                            "actor": "operator", "document_sha256": doc_sha, "raw_sha256": doc_sha,
                            "approval_id": null, "diff": "" }),
                )
                .by("operator"),
            )?;
        }
        tx.execute(
            "INSERT INTO tasks (id, org_id, title, created_at) VALUES (42, 'default', 'Report', '2026-11-20T00:02:00Z')",
            [],
        )?;
        tx.execute(
            "INSERT INTO dispatch_runs (run_id, task_id, attempt, created_at) VALUES ('run-9', 42, 1, '2026-11-20T00:02:00Z')",
            [],
        )?;
        tx.execute(
            "INSERT INTO deliverables (id, org_id, task_id, kind, title, created_by, created_at) \
             VALUES (1, 'default', 42, 'file', 'Report', 'builder-1', '2026-11-20T00:03:00Z')",
            [],
        )?;
        tx.execute(
            "INSERT INTO deliverable_revisions (id, org_id, deliverable_id, rev_no, identity, producer, recorded_at) \
             VALUES (1, 'default', 1, 1, ?1, 'builder-1', '2026-11-20T00:03:00Z')",
            [&artifact_sha],
        )?;
        tx.execute(
            "INSERT INTO approvals (id, org_id, tool, payload, requested_by, status, resolved_by, resolved_transport, created_at, updated_at, resolved_at, run_id) \
             VALUES (10, 'default', 'deliverable_release', ?1, ?2, 'approved', ?3, 'ui', '2026-11-20T00:04:00Z', '2026-11-20T00:05:00Z', '2026-11-20T00:05:00Z', 'run-9')",
            params![canon, seed.requester, seed.resolver],
        )?;
        tx.execute(
            "INSERT INTO deliverable_releases (approval_id, revision_id, org_id, requester, approver, destination, root_identity, staging_id, workflow_revision, ownership_generation) \
             VALUES (10, 1, 'default', ?1, ?2, 'release/report.md', 'root', 'stage', 1, 1)",
            params![seed.requester, seed.resolver],
        )?;
        ledger::append(
            tx,
            EventInput::new(
                "default",
                "agent.approval.requested",
                json!({ "approval_id": 10, "tool": "deliverable_release", "requested_by": seed.requester,
                        "payload_sha256": digest }),
            )
            .by(seed.requester),
        )?;
        let default_res = [("approve", seed.resolver)];
        let resolutions: &[(&str, &str)] = if seed.resolutions.is_empty() { &default_res } else { seed.resolutions };
        let mut released = false;
        for (decision, by) in resolutions {
            let mut ev = json!({ "approval_id": 10, "tool": "deliverable_release", "decision": decision,
                                 "resolved_by": by, "transport": "ui", "payload_sha256": digest });
            if *decision == "approve" {
                ev["expires_at"] = json!("2026-11-21T00:05:00Z");
            }
            ledger::append(tx, EventInput::new("default", "agent.approval.resolved", ev).by(*by))?;
            if *decision == "approve" && !released {
                released = true;
                ledger::append(
                    tx,
                    EventInput::new(
                        "default",
                        "agent.deliverable.released",
                        json!({ "task_id": 42, "deliverable_id": 1, "revision_id": 1, "sha256": artifact_sha,
                                "approval_id": 10, "approver": by, "destination": "release/report.md",
                                "root_identity": "root" }),
                    )
                    .by(seed.requester),
                )?;
            }
        }
        write_hub_cp_at_head(tx, "cp-release", sk, FIXTURE_KEY_ID)
    })
    .unwrap()
}

/// S-NEW-1 and B-S8: self-approval is refused whatever the policy says (a
/// real-format policy has no SoD key); SoD is hub-asserted when the policy is
/// not bound to its ledger event; a hub with no policy revision exports and
/// verifies with the link reported as absent; N16 is pinned.
#[test]
fn self_approval_is_refused_whatever_the_policy_says() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });
    let real_policy =
        json!({ "version": 1, "rules": [{ "tool": "deliverable_release", "action": "require_approval" }] });

    // Self-approval under the hub's own policy format -> refused.
    let (_d, db) = open_test_db();
    let cp = seed_release_hub(
        &db,
        &sk,
        &pk,
        &ReleaseSeed {
            policy: Some(real_policy.clone()),
            config_event: true,
            requester: "operator",
            resolver: "operator",
            second_policy: false,
            resolutions: &[],
        },
    );
    let out = tempdir().unwrap();
    export_signed(&db, &cp, &out.path().join("b"), &sk);
    let v = verify_bundle_dir(&out.path().join("b"), &trust).unwrap();
    assert_refused(&v, "receipt_sod_violation");
    assert_eq!(v.separation_of_duties.status, ClaimStatus::Refused);

    // Honest approval, policy bound -> SoD verified; artifact bound -> verified.
    let (_d, db) = open_test_db();
    let cp = seed_release_hub(
        &db,
        &sk,
        &pk,
        &ReleaseSeed {
            policy: Some(real_policy.clone()),
            config_event: true,
            requester: "builder-1",
            resolver: "operator",
            second_policy: false,
            resolutions: &[],
        },
    );
    export_signed(&db, &cp, &out.path().join("c"), &sk);
    let v = verify_bundle_dir(&out.path().join("c"), &trust).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.separation_of_duties.status, ClaimStatus::Verified, "{v:?}");

    // Honest approval, policy not bound to an agent.config.revision event ->
    // SoD hub-asserted, never verified.
    let (_d, db) = open_test_db();
    let cp = seed_release_hub(
        &db,
        &sk,
        &pk,
        &ReleaseSeed {
            policy: Some(real_policy),
            config_event: false,
            requester: "builder-1",
            resolver: "operator",
            second_policy: false,
            resolutions: &[],
        },
    );
    export_signed(&db, &cp, &out.path().join("d"), &sk);
    let v = verify_bundle_dir(&out.path().join("d"), &trust).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.separation_of_duties.status, ClaimStatus::HubAsserted, "{v:?}");
    assert!(v.separation_of_duties.basis.contains("agent.config.revision"));

    // B-S8: no policy revision at all -> exports and verifies; the receipt and
    // artifact carry no policy link, which the verifier accepts because none
    // was in force.
    let (_d, db) = open_test_db();
    let cp = seed_release_hub(
        &db,
        &sk,
        &pk,
        &ReleaseSeed {
            policy: None,
            config_event: false,
            requester: "builder-1",
            resolver: "operator",
            second_policy: false,
            resolutions: &[],
        },
    );
    let dir = out.path().join("e");
    export_signed(&db, &cp, &dir, &sk);
    let v = verify_bundle_dir(&dir, &trust).unwrap();
    assert!(v.ok, "{v:?}");
    let arts: Vec<ArtifactIndexEntry> = read_json(&dir.join("artifacts/index.json"));
    assert_eq!(arts[0].release_status, "released");
    assert_eq!(arts[0].policy_revision, None);
    let rec: ApprovalReceipt = read_json(&dir.join("approvals/10.json"));
    assert_eq!(rec.policy_revision, None);

    // N16: sod_tools claimed without its document refuses.
    let tmp = good_copy("good_hub");
    let pp = tmp.path().join("policy/revisions.json");
    let mut revs: Vec<PolicyRevisionRecord> = read_json(&pp);
    let pol = revs.iter_mut().find(|r| r.kind == "policy").unwrap();
    assert!(!pol.sod_tools.is_empty());
    pol.document = None;
    write_json(&pp, &revs);
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &fixture_trust()).unwrap(), "policy_sod_unverifiable");
}

/// Insert a raw `event_log` row (hash_v 2) chained to the current head.
fn insert_raw_event(tx: &mut ua_store::WriteTx<'_>, ulid: &str, channel: &str, payload: &str) {
    let prev: String =
        tx.query_row("SELECT entry_hash FROM event_log ORDER BY seq DESC LIMIT 1", [], |r| r.get(0)).unwrap();
    let ts = "2026-11-21T00:00:00Z";
    let eh = compute_entry_hash_v2(
        Some(&prev),
        ulid,
        channel,
        payload,
        Some("sys"),
        None,
        None,
        ts,
        None,
        "default",
    );
    tx.execute(
        "INSERT INTO event_log (ulid, channel, payload, originator, created_at, prev_hash, entry_hash, org_id, hash_v) \
         VALUES (?1, ?2, ?3, 'sys', ?4, ?5, ?6, 'default', 2)",
        params![ulid, channel, payload, ts, prev, eh],
    )
    .unwrap();
}

/// Blocker 4 (B-B2): payloads that are not strict JSON are exported only as
/// `unparseable_payload` stubs, and the verifier refuses one in clear.
#[test]
fn non_strict_json_payloads_are_stubbed_at_export_and_refused_at_verify() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });
    let mut deep = json!({ "password": "PLANT14-deep" });
    for _ in 0..130 {
        deep = json!([deep]);
    }
    let (_d, db) = open_test_db();
    let cp = db
        .write(|tx| {
            key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
            insert_raw_event(
                tx,
                "01NAN0000000000000000000001",
                "agent.log",
                r#"{"password":"PLANT24-nan","score":NaN}"#,
            );
            insert_raw_event(
                tx,
                "01TRL0000000000000000000002",
                "agent.log",
                r#"{"password":"PLANT25-trail"} trailing"#,
            );
            insert_raw_event(
                tx,
                "01DUP0000000000000000000003",
                "agent.log",
                r#"{"password":"PLANT26-dup","password":null}"#,
            );
            ledger::append(tx, EventInput::new("default", "agent.log", json!({ "d": deep })))?;
            ledger::append(tx, EventInput::new("default", "agent.task.created", json!({ "task_id": 1 })))?;
            write_hub_cp_at_head(tx, "cp-nonstrict", &sk, FIXTURE_KEY_ID)
        })
        .unwrap();
    let out = tempdir().unwrap();
    let dir = out.path().join("b");
    export_signed(&db, &cp, &dir, &sk);
    let text = std::fs::read_to_string(dir.join("ledger/events.jsonl")).unwrap();
    for plant in ["PLANT24", "PLANT25", "PLANT26", "PLANT14"] {
        assert!(!text.contains(plant), "{plant} leaked into the bundle");
    }
    let withheld: WithheldReport = read_json(&dir.join("withheld.json"));
    assert_eq!(withheld.classes.get(CLASS_UNPARSEABLE_PAYLOAD), Some(&4));
    let v = verify_bundle_dir(&dir, &trust).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.redacted_events.count, 4);

    // Put one payload back in clear (its row hash still verifies): refused.
    let raw: (String, String, Option<String>) = db
        .read(|c| {
            Ok(c.query_row(
                "SELECT channel, payload, originator FROM event_log WHERE ulid = '01DUP0000000000000000000003'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?)
        })
        .unwrap();
    let mut evs = read_events(&dir);
    let ev = evs.iter_mut().find(|e| e.ulid == "01DUP0000000000000000000003").unwrap();
    ev.channel = raw.0;
    ev.payload = raw.1;
    ev.originator = raw.2;
    ev.redacted = false;
    ev.redacted_class = None;
    write_events(&dir, &evs);
    remanifest_and_resign(&dir, &sk, false);
    let v = verify_bundle_dir(&dir, &trust).unwrap();
    assert_refused(&v, "forbidden_private_content");
    assert_eq!(v.offending.as_ref().unwrap()["class"], CLASS_UNPARSEABLE_PAYLOAD);
}

/// Blocker 5 (B-B3): manifest.files holds exactly the required files plus
/// `approvals/<id>.json` with a canonical decimal id, and every file parses
/// strictly to its schema.
#[test]
fn manifest_lists_exactly_the_bundle_files() {
    let trust = fixture_trust();
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);

    for extra in [
        "notes/ops.txt",
        "notes/deep.json",
        "approvals/010.json",
        "approvals/+10.json",
        "Approvals/10.json",
        "approvals/0.json",
    ] {
        let tmp = good_copy("good_hub");
        let target = tmp.path().join(extra);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(tmp.path().join("approvals/10.json"), &target).unwrap();
        let sha = sha256_hex(&std::fs::read(&target).unwrap());
        edit_manifest(tmp.path(), &sk, |m| {
            m.files.insert(extra.to_string(), sha);
        });
        assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "unexpected_bundle_file");
    }

    // A listed file with a duplicate key refuses (strict parse).
    let tmp = good_copy("good_hub");
    std::fs::write(tmp.path().join("withheld.json"), br#"{"classes":{},"total":0,"total":5}"#).unwrap();
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "invalid_withheld");
}

/// Blocker 6 (B-B4): a non-default organization's approvals sit in the
/// default ledger, so its org bundle reports the release as not provable,
/// counts the omitted approvals, and says approvals are not covered.
#[test]
fn org_bundle_reports_releases_and_approvals_as_not_covered() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });
    let (_d, db) = open_test_db();
    let canon = ua_core::canonical::to_string(&json!({ "deliverable_id": 3 }));
    let digest = sha256_hex(canon.as_bytes());
    let (org_cp, hub_cp) = db
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, created_at) VALUES ('acme', 'acme', 'Acme', '2026-11-20T00:00:00Z')",
                [],
            )?;
            key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
            tx.execute(
                "INSERT INTO tasks (id, org_id, title, created_at) VALUES (101, 'acme', 't', '2026-11-20T00:02:00Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO dispatch_runs (run_id, task_id, attempt, created_at) VALUES ('run-a', 101, 1, '2026-11-20T00:02:00Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO deliverables (id, org_id, task_id, kind, title, created_by, created_at) \
                 VALUES (3, 'acme', 101, 'file', 'd', 'acme-bot', '2026-11-20T00:03:00Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO deliverable_revisions (id, org_id, deliverable_id, rev_no, identity, producer, recorded_at) \
                 VALUES (3, 'acme', 3, 1, ?1, 'acme-bot', '2026-11-20T00:03:00Z')",
                ["f".repeat(64)],
            )?;
            tx.execute(
                "INSERT INTO approvals (id, org_id, tool, payload, requested_by, status, resolved_by, resolved_transport, created_at, updated_at, resolved_at) \
                 VALUES (20, 'acme', 'deliverable_release', ?1, 'acme-bot', 'approved', 'acme-human', 'ui', '2026-11-20T00:04:00Z', '2026-11-20T00:05:00Z', '2026-11-20T00:05:00Z')",
                [&canon],
            )?;
            tx.execute(
                "INSERT INTO deliverable_releases (approval_id, revision_id, org_id, requester, approver, destination, root_identity, staging_id, workflow_revision, ownership_generation) \
                 VALUES (20, 3, 'acme', 'acme-bot', 'acme-human', 'out', 'root', 'stage', 1, 1)",
                [],
            )?;
            ledger::append(
                tx,
                EventInput::new("acme", "agent.task.completed", json!({ "task_id": 101 })).by("acme-bot"),
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "default",
                    "agent.approval.resolved",
                    json!({ "approval_id": 20, "tool": "deliverable_release", "decision": "approve",
                            "resolved_by": null, "transport": "ui", "payload_sha256": digest }),
                )
                .by("system"),
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "default",
                    "agent.deliverable.released",
                    json!({ "task_id": 101, "deliverable_id": 3, "revision_id": 3, "sha256": "f".repeat(64),
                            "approval_id": 20, "approver": null, "destination": "out", "root_identity": "root" }),
                )
                .by("system"),
            )?;
            let sum = compute_org_window_checkpoint(tx, "acme", "2026-11-01T00:00:00Z", "2099-12-31T23:59:59Z", None)?;
            let cp = Checkpoint {
                checkpoint_id: "cp-acme".into(),
                class: CheckpointClass::Org,
                org_id: Some("acme".into()),
                seq: None,
                hash: None,
                window: Some(sum.window),
                global_from_hash: Some(sum.global_from_hash),
                global_head_hash: Some(sum.global_head_hash),
                org_row_count: Some(sum.org_row_count),
                org_chain_hash: Some(sum.org_chain_hash),
                key_id: FIXTURE_KEY_ID.into(),
                signed_at: "2026-11-25T12:00:00Z".into(),
            };
            let d = checkpoint_write(tx, &cp, "2026-11-25T12:00:00Z")?;
            checkpoint_attach(tx, &cp.checkpoint_id, &sign_hex_digest(&sk, &d))?;
            let hub = write_hub_cp_at_head(tx, "cp-acme-hub", &sk, FIXTURE_KEY_ID)?;
            Ok((cp.checkpoint_id, hub))
        })
        .unwrap();
    let out = tempdir().unwrap();
    let dir = out.path().join("org");
    export_signed(&db, &org_cp, &dir, &sk);
    let arts: Vec<ArtifactIndexEntry> = read_json(&dir.join("artifacts/index.json"));
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0].release_status, "not_provable_in_org_bundle");
    assert_eq!(arts[0].approval_id, None);
    let withheld: WithheldReport = read_json(&dir.join("withheld.json"));
    assert_eq!(withheld.classes.get(CLASS_APPROVALS_IN_DEFAULT_LEDGER), Some(&1));
    let v = verify_bundle_dir(&dir, &trust).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.approvals.status, ClaimStatus::Unverified);
    assert!(v.approvals.basis.contains("not covered"), "{:?}", v.approvals);

    // The claim cannot be forged as `released: false`-style "unreleased" plus
    // an approval id, nor as not_provable in a hub bundle.
    let hub_dir = out.path().join("hub");
    export_signed(&db, &hub_cp, &hub_dir, &sk);
    let arts: Vec<ArtifactIndexEntry> = read_json(&hub_dir.join("artifacts/index.json"));
    assert_eq!(arts[0].release_status, "released");
    let ap = hub_dir.join("artifacts/index.json");
    let mut forged = arts.clone();
    forged[0].release_status = "not_provable_in_org_bundle".into();
    forged[0].approval_id = None;
    write_json(&ap, &forged);
    edit_receipt(&hub_dir, 20, |r| r.covers.clear());
    remanifest_and_resign(&hub_dir, &sk, false);
    assert_refused(&verify_bundle_dir(&hub_dir, &trust).unwrap(), "broken_artifact_trace");
}

/// S-NEW-2 and N28: an org bundle carries only the policy revisions it cites,
/// with the digest and without the document.
#[test]
fn org_bundles_omit_policy_documents_and_uncited_revisions() {
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);
    let (_d, db) = open_test_db();
    let (hub_cp, org_cp) = populate_sample_db(&db, &sk, FIXTURE_KEY_ID);
    let out = tempdir().unwrap();
    db.read(|c| export_bundle(c, &out.path().join("org"), &export_opts(&org_cp))).unwrap();
    db.read(|c| export_bundle(c, &out.path().join("hub"), &export_opts(&hub_cp))).unwrap();
    let revs: Vec<PolicyRevisionRecord> = read_json(&out.path().join("org/policy/revisions.json"));
    assert!(!revs.is_empty());
    for r in &revs {
        assert_eq!(r.kind, "policy", "org bundle carries an uncited {:?} revision", r.kind);
        assert!(r.document.is_none(), "org bundle carries a policy document");
        assert!(r.sod_tools.is_empty());
        assert!(r.id.is_none());
    }
    let org_text = std::fs::read_to_string(out.path().join("org/policy/revisions.json")).unwrap();
    assert!(!org_text.contains("separation_of_duties"));
    let hub: Vec<PolicyRevisionRecord> = read_json(&out.path().join("hub/policy/revisions.json"));
    assert!(hub.iter().any(|r| r.kind == "profile"), "hub bundle keeps the window's revisions");
    assert!(hub.iter().all(|r| r.document.is_some()));
}

/// S-NEW-3: org evidence rows map task ids through the same dense ordinals as
/// the artifacts, never a constant.
#[test]
fn org_evidence_rows_use_task_ordinals() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });
    let (_d, db) = open_test_db();
    let cp = db
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, created_at) VALUES ('acme', 'acme', 'Acme', '2026-11-20T00:00:00Z')",
                [],
            )?;
            key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
            for (id, org) in [(5, "acme"), (6, "default"), (7, "default"), (8, "default"), (9, "acme")] {
                tx.execute(
                    "INSERT INTO tasks (id, org_id, title, created_at) VALUES (?1, ?2, 't', '2026-11-20T00:02:00Z')",
                    params![id, org],
                )?;
            }
            tx.execute(
                "INSERT INTO deliverables (id, org_id, task_id, kind, title, created_by, created_at) \
                 VALUES (4, 'acme', 9, 'file', 'd', 'acme-bot', '2026-11-20T00:03:00Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO deliverable_revisions (id, org_id, deliverable_id, rev_no, identity, producer, recorded_at) \
                 VALUES (4, 'acme', 4, 1, ?1, 'acme-bot', '2026-11-20T00:03:00Z')",
                ["a".repeat(64)],
            )?;
            for tid in [5, 9] {
                ledger::append(
                    tx,
                    EventInput::new(
                        "acme",
                        "agent.deliverable.created",
                        json!({ "org_id": "acme", "deliverable_id": 4, "task_id": tid, "kind": "file" }),
                    )
                    .by("acme-bot"),
                )?;
            }
            let sum = compute_org_window_checkpoint(tx, "acme", "2026-11-01T00:00:00Z", "2099-12-31T23:59:59Z", None)?;
            let cp = Checkpoint {
                checkpoint_id: "cp-acme-ord".into(),
                class: CheckpointClass::Org,
                org_id: Some("acme".into()),
                seq: None,
                hash: None,
                window: Some(sum.window),
                global_from_hash: Some(sum.global_from_hash),
                global_head_hash: Some(sum.global_head_hash),
                org_row_count: Some(sum.org_row_count),
                org_chain_hash: Some(sum.org_chain_hash),
                key_id: FIXTURE_KEY_ID.into(),
                signed_at: "2026-11-25T12:00:00Z".into(),
            };
            let d = checkpoint_write(tx, &cp, "2026-11-25T12:00:00Z")?;
            checkpoint_attach(tx, &cp.checkpoint_id, &sign_hex_digest(&sk, &d))?;
            Ok(cp.checkpoint_id)
        })
        .unwrap();
    let out = tempdir().unwrap();
    let dir = out.path().join("b");
    export_signed(&db, &cp, &dir, &sk);
    let rows: Vec<EvidenceRow> = std::fs::read_to_string(dir.join("evidence/rows.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.iter().map(|r| r.task_id).collect::<Vec<_>>(), vec![Some(1), Some(2)]);
    let arts: Vec<ArtifactIndexEntry> = read_json(&dir.join("artifacts/index.json"));
    assert_eq!(arts[0].task_id, 2, "the artifact for task 9 uses the same ordinal as its evidence row");
    assert_eq!(arts[0].id, "deliverable:1");
    assert!(verify_bundle_dir(&dir, &trust).unwrap().ok);
}

/// B-S3: evidence rows are rebuilt from the ledger, the manifest window is
/// checked, and artifacts not bound to agent.deliverable.* events are
/// reported as hub-asserted.
#[test]
fn evidence_rows_window_and_artifact_bindings_are_checked() {
    let trust = fixture_trust();
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);
    let base = verify_bundle_dir(&fixtures_root().join("good_hub"), &trust).unwrap();
    assert_eq!(base.artifacts.status, ClaimStatus::Verified, "{:?}", base.artifacts);

    // A fabricated evidence row refuses.
    let tmp = good_copy("good_hub");
    let rows_path = tmp.path().join("evidence/rows.jsonl");
    let mut text = std::fs::read_to_string(&rows_path).unwrap();
    let mut fake: EvidenceRow = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    fake.id = "01FAKE00000000000000000000".into();
    fake.kind = "evidence.attestation".into();
    fake.labels = vec!["tests_passed".into()];
    text.push_str(&String::from_utf8(to_canonical_bytes(&fake).unwrap()).unwrap());
    text.push('\n');
    std::fs::write(&rows_path, text).unwrap();
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "evidence_row_mismatch");

    // An altered row (labels) refuses.
    let tmp = good_copy("good_hub");
    rewrite_jsonl::<EvidenceRow>(&tmp.path().join("evidence/rows.jsonl"), |r| {
        r.labels.push("tests_passed".into())
    });
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "evidence_row_mismatch");

    // A widened manifest window refuses, for both classes.
    for fixture in ["good_hub", "good_org"] {
        let tmp = good_copy(fixture);
        edit_manifest(tmp.path(), &sk, |m| {
            m.window = Window { start: "2001-01-01T00:00:00Z".into(), end: "2099-01-01T00:00:00Z".into() };
        });
        assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "manifest_window_mismatch");
    }

    // A fabricated unreleased artifact is not bound to a deliverable event:
    // the index is reported hub-asserted.
    let tmp = good_copy("good_hub");
    let ap = tmp.path().join("artifacts/index.json");
    let mut arts: Vec<ArtifactIndexEntry> = read_json(&ap);
    let mut fake = arts[0].clone();
    fake.id = "deliverable:999".into();
    fake.release_status = "unreleased".into();
    fake.approval_id = None;
    arts.push(fake);
    write_json(&ap, &arts);
    remanifest_and_resign(tmp.path(), &sk, false);
    let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.artifacts.status, ClaimStatus::HubAsserted);
}

/// B-S6: withheld counts and org ordinals come from the checkpoint's frozen
/// snapshot, so a re-export after deletes is byte-identical.
#[test]
fn reexport_is_byte_identical_after_deletes() {
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);
    let (_d, db) = open_test_db();
    // An earlier acme task (100) makes task 101's ordinal 2.
    db.write(|tx| {
        tx.execute(
            "INSERT INTO orgs (id, slug, display_name, created_at) VALUES ('acme', 'acme', 'Acme Org', '2026-11-20T00:00:00Z')",
            [],
        )?;
        tx.execute(
            "INSERT INTO tasks (id, org_id, title, created_at) VALUES (100, 'acme', 'earlier', '2026-11-19T00:00:00Z')",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    let (hub_cp, org_cp) = populate_sample_db(&db, &sk, FIXTURE_KEY_ID);
    for cp in [&hub_cp, &org_cp] {
        let wrote = db.write(|tx| snapshot_checkpoint(tx, cp, "2026-11-25T12:06:00Z")).unwrap();
        assert!(wrote);
        let again = db.write(|tx| snapshot_checkpoint(tx, cp, "2026-11-25T12:07:00Z")).unwrap();
        assert!(!again, "a snapshot is written once");
    }
    let out = tempdir().unwrap();
    let r1h = db.read(|c| export_bundle(c, &out.path().join("h1"), &export_opts(&hub_cp))).unwrap();
    let r1o = db.read(|c| export_bundle(c, &out.path().join("o1"), &export_opts(&org_cp))).unwrap();
    assert!(r1h.withheld.classes.contains_key("session_credentials"));
    let rows: Vec<EvidenceRow> = std::fs::read_to_string(out.path().join("o1/evidence/rows.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(rows.iter().any(|r| r.task_id == Some(2)), "task 101 is acme's second task: {rows:?}");

    db.write(|tx| {
        tx.execute("DELETE FROM session_credentials", [])?;
        tx.execute("DELETE FROM tasks WHERE id = 100", [])?;
        tx.execute("DELETE FROM agent_tokens", [])?;
        Ok(())
    })
    .unwrap();
    let r2h = db.read(|c| export_bundle(c, &out.path().join("h2"), &export_opts(&hub_cp))).unwrap();
    let r2o = db.read(|c| export_bundle(c, &out.path().join("o2"), &export_opts(&org_cp))).unwrap();
    assert_eq!(r1h.manifest, r2h.manifest, "hub bundle drifted after deletes");
    assert_eq!(r1o.manifest, r2o.manifest, "org bundle drifted after deletes");
    // The snapshot cannot be rewritten or removed.
    assert!(db.write(|tx| Ok(tx.execute("DELETE FROM evidence_export_snapshot", [])?)).is_err());
    assert!(
        db.write(|tx| Ok(tx.execute("UPDATE evidence_export_snapshot SET snapshot = '{}'", [])?)).is_err()
    );
}

// ---------------------------------------------------------------------------
// Fix round 3 (#2716 S3b+S3c, reviews at d2d6763b): allow-list egress
// ---------------------------------------------------------------------------

/// Literals that look like channels but are not ledger channels (schema part
/// names, hostnames, test placeholders).
const NOT_CHANNELS: &[&str] = &["hub.db", "hub.db.away", "hub.example.com", "agent.x", "agent.y"];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Every hub channel literal in the workspace's sources is classified for
/// egress on purpose: an exact export rule, a stub family, or a restricted
/// channel. A new channel that matches nothing fails here (it would be
/// stubbed as `unlisted_payload` at export, which is safe, but the table
/// must say so).
#[test]
fn every_hub_channel_is_classified_for_egress() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for c in std::fs::read_dir(crates).unwrap().flatten() {
        let src = c.path().join("src");
        if src.is_dir() {
            rust_sources(&src, &mut files);
        }
    }
    let mut unclassified = std::collections::BTreeSet::new();
    let mut seen = 0usize;
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        for (i, _) in text.match_indices('"') {
            let rest = &text[i + 1..];
            let Some(end) = rest.find('"') else { continue };
            let lit = &rest[..end];
            let is_channel_shape =
                ["agent.", "hub.", "evidence.", "github.credential."].iter().any(|p| lit.starts_with(p))
                    && lit.len() < 80
                    && lit
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_'))
                    && !lit.ends_with('.');
            if !is_channel_shape || NOT_CHANNELS.contains(&lit) {
                continue;
            }
            // Schema part names (`github.v1`, `evidence_key_store.v1`) are not channels.
            if lit.split('.').any(|seg| {
                seg.len() > 1 && seg.starts_with('v') && seg[1..].bytes().all(|b| b.is_ascii_digit())
            }) {
                continue;
            }
            seen += 1;
            if ua_store::evidence_bundle::rule_for(lit).is_none()
                && !ua_store::evidence_bundle::is_restricted_channel(lit)
            {
                unclassified.insert(format!("{lit} ({})", f.display()));
            }
        }
    }
    assert!(seen > 100, "the scan found only {seen} channel literals");
    assert!(
        unclassified.is_empty(),
        "classify these channels in export_schema::CHANNEL_RULES: {unclassified:#?}"
    );
}

fn seed_hub_rows(rows: &[(&str, Value)]) -> (tempfile::TempDir, Db, String) {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let (dir, db) = open_test_db();
    let cp = db
        .write(|tx| {
            key_add(tx, FIXTURE_KEY_ID, &pk, "2026-11-20T00:00:00Z", None)?;
            for (ch, payload) in rows {
                ledger::append(tx, EventInput::new("default", *ch, payload.clone()).by("builder-1"))?;
            }
            write_hub_cp_at_head(tx, "cp-rows", &sk, FIXTURE_KEY_ID)
        })
        .unwrap();
    (dir, db, cp)
}

/// Owner decision (allow-list): client `sdk.*` payloads never leave in clear,
/// whatever their keys (review B-B1 matrix); hub rows with free text or a
/// scanner hit are stubbed and never block the export (A-NB1, B-S3); the
/// hub's own typed rows export in clear (session credentials, MCP revokes).
#[test]
fn egress_is_an_allow_list_and_row_contents_never_block_export() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust = BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk });
    let plants = [
        json!({ "signing_key": "FAKE-PLANTED-SIGNING-0001" }),
        json!({ "access_key": "FAKE-PLANTED-ACCESS-0002" }),
        json!({ "passcode": "FAKE-PLANTED-PASSCODE-0003" }),
        json!({ "secrets": [70, 65, 75, 69, 45, 80, 76, 65, 78, 84] }),
        json!({ "cmd": "psql 'password=FAKE-PLANTED-DSN-0005'" }),
        json!({ "note": "{'password': 'FAKE-PLANTED-REPR-0006'}" }),
        json!({ "passw\u{0585}rd": "FAKE-PLANTED-ARMENIAN-0007" }),
        json!({ "headers": "Cookie: session=FAKE-PLANTED-COOKIE-0008" }),
        json!({ "note": "see ghp_0123456789abcdefFAKEFAKEFAKEFAKE0123" }),
        json!({ "token_count": "12" }),
    ];
    let mut rows: Vec<(&str, Value)> = plants.iter().map(|p| ("sdk.note", p.clone())).collect();
    rows.push((
        "agent.task.created",
        json!({ "task_id": 1, "title": "Rotate Bearer tokens on the gateway" }),
    ));
    rows.push(("agent.token.issued", json!({ "agent": "ghp_0123456789abcdefFAKEFAKEFAKE", "token_id": 9 })));
    rows.push((
        "hub.session_credential.minted",
        json!({ "credential_id": "a1b2c3d4e5f60718", "item_id": 1, "attempt": 1, "task_id": 42,
                "run_id": "run-001", "tools": ["fs_read"], "superseded": [] }),
    ));
    rows.push((
        "agent.mcp_server",
        json!({ "op": "revoked", "name": "srv", "spec_sha256": "abc", "approval_id": 3,
                "orphaned_secrets": ["GITHUB_DEPLOY_NAME"] }),
    ));
    let (_d, db, cp) = seed_hub_rows(&rows);
    let out = tempdir().unwrap();
    let dir = out.path().join("b");
    export_signed(&db, &cp, &dir, &sk);
    let text = std::fs::read_to_string(dir.join("ledger/events.jsonl")).unwrap();
    for needle in ["FAKE-PLANTED", "70,65,75,69", "Rotate Bearer", "ghp_0123", "\"12\""] {
        assert!(!text.contains(needle), "{needle} left the hub in clear");
    }
    let evs = read_events(&dir);
    let class_of = |ch: &str| -> Vec<Option<String>> {
        evs.iter()
            .filter(|e| e.channel == ch || (e.redacted && ch.is_empty()))
            .map(|e| e.redacted_class.clone())
            .collect()
    };
    let stubs: Vec<String> = evs.iter().filter_map(|e| e.redacted_class.clone()).collect();
    assert_eq!(stubs.iter().filter(|c| *c == CLASS_UNLISTED_PAYLOAD).count(), plants.len());
    assert!(stubs.iter().any(|c| c == CLASS_FREE_TEXT_PAYLOAD), "{stubs:?}");
    assert!(stubs.iter().any(|c| c == CLASS_SCANNER_WITHHELD), "{stubs:?}");
    assert_eq!(class_of("hub.session_credential.minted"), vec![None], "typed hub row exports in clear");
    assert_eq!(class_of("agent.mcp_server"), vec![None]);
    let withheld: WithheldReport = read_json(&dir.join("withheld.json"));
    assert_eq!(withheld.classes.get(CLASS_UNLISTED_PAYLOAD), Some(&(plants.len() as u64)));
    let v = verify_bundle_dir(&dir, &trust).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.completeness.status, ClaimStatus::Partial, "stubs drop completeness to partial");

    // A client row put back in clear (hash still valid) is refused.
    let raw: (String, String) = db
        .read(|c| {
            Ok(c.query_row(
                "SELECT channel, payload FROM event_log WHERE channel = 'sdk.note' LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    let mut evs = read_events(&dir);
    let ev = evs
        .iter_mut()
        .find(|e| e.redacted && e.redacted_class.as_deref() == Some(CLASS_UNLISTED_PAYLOAD))
        .unwrap();
    ev.channel = raw.0;
    ev.payload = raw.1;
    ev.originator = Some("builder-1".into());
    ev.redacted = false;
    ev.redacted_class = None;
    write_events(&dir, &evs);
    bump_withheld(&dir, CLASS_UNLISTED_PAYLOAD, 0);
    remanifest_and_resign(&dir, &sk, false);
    let v = verify_bundle_dir(&dir, &trust).unwrap();
    assert_eq!(v.exit_code, 1, "{v:?}");
    assert!(
        matches!(v.reason.as_deref(), Some("unlisted_payload_in_clear" | "withheld_count_mismatch")),
        "{v:?}"
    );
}

fn release_seed(resolutions: &'static [(&'static str, &'static str)], second_policy: bool) -> ReleaseSeed {
    ReleaseSeed {
        policy: Some(
            json!({ "version": 1, "rules": [{ "tool": "deliverable_release", "action": "require_approval" }] }),
        ),
        config_event: true,
        requester: "builder-1",
        resolver: "operator",
        second_policy,
        resolutions,
    }
}

/// NB2: the snapshot table refuses `INSERT OR REPLACE`, `REPLACE` and rows
/// for a checkpoint that does not exist; a snapshot bound to another
/// checkpoint is refused at export. `evidence_checkpoint` and `evidence_key`
/// refuse REPLACE too (`evidence_key_store.v3.no_replace`).
#[test]
fn snapshot_and_checkpoint_rows_cannot_be_replaced_or_planted() {
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);
    let (_d, db) = open_test_db();
    let (hub_cp, org_cp) = populate_sample_db(&db, &sk, FIXTURE_KEY_ID);
    db.write(|tx| snapshot_checkpoint(tx, &hub_cp, "2026-11-25T12:06:00Z")).unwrap();
    for sql in [
        "INSERT OR REPLACE INTO evidence_export_snapshot (checkpoint_id, snapshot, created_at) VALUES ('cp-hub-1', '{}', 'x')",
        "REPLACE INTO evidence_export_snapshot (checkpoint_id, snapshot, created_at) VALUES ('cp-hub-1', '{}', 'x')",
        "INSERT INTO evidence_export_snapshot (checkpoint_id, snapshot, created_at) VALUES ('cp-future', '{}', 'x')",
        "INSERT OR REPLACE INTO evidence_checkpoint SELECT checkpoint_id, class, org_id, seq, hash, window_start, \
         window_end, global_from_hash, global_head_hash, org_row_count, org_chain_hash, key_id, signed_at, digest, \
         NULL, created_at FROM evidence_checkpoint WHERE checkpoint_id = 'cp-hub-1'",
        "INSERT OR REPLACE INTO evidence_key SELECT key_id, algorithm, '00', created_at, retired_at, revoked_at, note \
         FROM evidence_key",
    ] {
        let r = db.write(|tx| Ok(tx.execute(sql, [])?));
        assert!(r.is_err(), "{sql} must be refused");
    }
    // A snapshot captured for one checkpoint and stored under another's id
    // is refused at export.
    let foreign = db
        .read(|c| {
            let cp = ua_store::evidence::checkpoint_get(c, &hub_cp)?.unwrap();
            ua_store::evidence_bundle::snapshot::snapshot_capture(c, &cp)
        })
        .unwrap();
    db.write(|tx| {
        tx.execute(
            "INSERT INTO evidence_export_snapshot (checkpoint_id, snapshot, created_at) VALUES (?1, ?2, 'x')",
            params![org_cp, String::from_utf8(to_canonical_bytes(&foreign).unwrap()).unwrap()],
        )?;
        Ok(())
    })
    .unwrap();
    let out = tempdir().unwrap();
    let err = db.read(|c| export_bundle(c, &out.path().join("o"), &export_opts(&org_cp))).unwrap_err();
    assert!(err.to_string().contains("different checkpoint"), "{err}");
}

/// B2/NS1/NS2: the policy in force is the verifier's choice from the
/// hash-verified `agent.config.revision` events and the resolved event's
/// time; neither a backdated `decided_at` nor an edited or shortened
/// `policy/revisions.json` moves it.
#[test]
fn policy_in_force_comes_from_config_events_not_receipt_inputs() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });
    let (_d, db) = open_test_db();
    let cp = seed_release_hub(&db, &sk, &pk, &release_seed(&[], true));
    let out = tempdir().unwrap();
    let base = out.path().join("base");
    export_signed(&db, &cp, &base, &sk);
    let v = verify_bundle_dir(&base, &trust).unwrap();
    assert!(v.ok, "{v:?}");
    let rec: ApprovalReceipt = read_json(&base.join("approvals/10.json"));
    assert_eq!(rec.policy_revision, Some(2), "the honest receipt cites the revision in force");

    // A: decided_at moved before the request, citing rev 1.
    let t = tempdir().unwrap();
    copy_dir_recursive(&base, t.path());
    edit_receipt(t.path(), 10, |r| {
        r.decided_at = "2026-11-20T00:02:00Z".into();
        r.policy_revision = Some(1);
    });
    remanifest_and_resign(t.path(), &sk, false);
    assert_refused(&verify_bundle_dir(t.path(), &trust).unwrap(), "receipt_decided_at_out_of_range");
    // B: a decided_at that is not RFC 3339.
    let t = tempdir().unwrap();
    copy_dir_recursive(&base, t.path());
    edit_receipt(t.path(), 10, |r| {
        r.decided_at = "!".into();
        r.policy_revision = None;
        r.policy_digest = None;
    });
    remanifest_and_resign(t.path(), &sk, false);
    assert_refused(&verify_bundle_dir(t.path(), &trust).unwrap(), "receipt_decided_at_out_of_range");
    // B2: with the request event stubbed (no lower bound), a decided_at that
    // is not RFC 3339 is still refused, not compared lexically.
    let t = tempdir().unwrap();
    copy_dir_recursive(&base, t.path());
    let mut evs = read_events(t.path());
    let i = evs.iter().position(|e| e.channel == "agent.approval.requested").unwrap();
    let ulid = evs[i].ulid.clone();
    make_stub(&mut evs[i], CLASS_FREE_TEXT_PAYLOAD);
    write_events(t.path(), &evs);
    let rows_path = t.path().join("evidence/rows.jsonl");
    let kept: String = std::fs::read_to_string(&rows_path)
        .unwrap()
        .lines()
        .filter(|l| !l.contains(ulid.as_str()))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&rows_path, kept).unwrap();
    bump_withheld(t.path(), CLASS_FREE_TEXT_PAYLOAD, 1);
    remanifest_and_resign(t.path(), &sk, false);
    assert!(verify_bundle_dir(t.path(), &trust).unwrap().ok, "control without the request event verifies");
    edit_receipt(t.path(), 10, |r| r.decided_at = "!".into());
    remanifest_and_resign(t.path(), &sk, false);
    assert_refused(&verify_bundle_dir(t.path(), &trust).unwrap(), "receipt_decided_at_out_of_range");
    // C: rev 2 deleted from the list while its config event stays.
    let t = tempdir().unwrap();
    copy_dir_recursive(&base, t.path());
    let pp = t.path().join("policy/revisions.json");
    let mut revs: Vec<PolicyRevisionRecord> = read_json(&pp);
    revs.retain(|r| r.revision != 2);
    write_json(&pp, &revs);
    remanifest_and_resign(t.path(), &sk, false);
    assert_refused(&verify_bundle_dir(t.path(), &trust).unwrap(), "policy_revision_missing");
    // D: rev 2's listed created_at pushed into the future does not move the
    // revision in force (the config event's time governs): the receipt
    // citing rev 2 still verifies, and one citing rev 1 is refused.
    let t = tempdir().unwrap();
    copy_dir_recursive(&base, t.path());
    let pp = t.path().join("policy/revisions.json");
    let mut revs: Vec<PolicyRevisionRecord> = read_json(&pp);
    revs.iter_mut().find(|r| r.revision == 2).unwrap().created_at = "2099-01-01T00:00:00Z".into();
    write_json(&pp, &revs);
    remanifest_and_resign(t.path(), &sk, false);
    assert!(verify_bundle_dir(t.path(), &trust).unwrap().ok);
    let p1 = revs.iter().find(|r| r.revision == 1).unwrap().document_sha256.clone();
    edit_receipt(t.path(), 10, |r| {
        r.policy_revision = Some(1);
        r.policy_digest = Some(p1);
    });
    remanifest_and_resign(t.path(), &sk, false);
    assert_refused(&verify_bundle_dir(t.path(), &trust).unwrap(), "receipt_policy_mismatch");
}

/// B3: release state comes from the full approval history. Approve then
/// revoke is `release_revoked`, a forged `released` is refused, and SoD runs
/// on every approve, not only the latest resolution.
#[test]
fn releases_follow_the_full_approval_history() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });
    let out = tempdir().unwrap();

    // Approve, release, then revoke.
    let (_d, db) = open_test_db();
    let cp = seed_release_hub(
        &db,
        &sk,
        &pk,
        &release_seed(&[("approve", "operator"), ("revoke", "operator")], false),
    );
    let dir = out.path().join("revoked");
    export_signed(&db, &cp, &dir, &sk);
    let arts: Vec<ArtifactIndexEntry> = read_json(&dir.join("artifacts/index.json"));
    assert_eq!(arts[0].release_status, "release_revoked");
    let v = verify_bundle_dir(&dir, &trust).unwrap();
    assert!(v.ok, "{v:?}");
    // Forging it back to released (with a receipt that covers it) is refused.
    let ap = dir.join("artifacts/index.json");
    let mut forged = arts.clone();
    forged[0].release_status = "released".into();
    forged[0].approval_id = Some(10);
    write_json(&ap, &forged);
    let cov = ua_store::evidence_bundle::CoveredArtifact {
        id: forged[0].id.clone(),
        revision: forged[0].revision,
        sha256: forged[0].sha256.clone(),
    };
    edit_receipt(&dir, 10, |r| r.covers = vec![cov]);
    remanifest_and_resign(&dir, &sk, false);
    assert_refused(&verify_bundle_dir(&dir, &trust).unwrap(), "release_not_bound");

    // A self-approval later revoked by someone else is still a violation.
    let (_d, db) = open_test_db();
    let cp = seed_release_hub(
        &db,
        &sk,
        &pk,
        &release_seed(&[("approve", "builder-1"), ("revoke", "operator")], false),
    );
    let dir = out.path().join("selfapprove");
    export_signed(&db, &cp, &dir, &sk);
    assert_refused(&verify_bundle_dir(&dir, &trust).unwrap(), "receipt_sod_violation");

    // Deny only: never released.
    let (_d, db) = open_test_db();
    let cp = seed_release_hub(&db, &sk, &pk, &release_seed(&[("deny", "operator")], false));
    let dir = out.path().join("denied");
    export_signed(&db, &cp, &dir, &sk);
    let arts: Vec<ArtifactIndexEntry> = read_json(&dir.join("artifacts/index.json"));
    assert_ne!(arts[0].release_status, "released");
    assert!(verify_bundle_dir(&dir, &trust).unwrap().ok);
}

/// B4: receipts and release state come from immutable ledger rows and the
/// snapshot, so a revoke, cancel or label change after the checkpoint
/// leaves the re-export byte-identical and verifiable.
#[test]
fn reexport_is_byte_identical_after_later_revoke_and_cancel() {
    let (sk, pk) = signing_key(FIXTURE_KEY_SEED);
    let trust =
        BundleVerifyTrust::from_anchor(TrustAnchor { key_id: FIXTURE_KEY_ID.into(), public_key: pk.clone() });
    let (_d, db) = open_test_db();
    let cp = seed_release_hub(&db, &sk, &pk, &release_seed(&[], false));
    db.write(|tx| snapshot_checkpoint(tx, &cp, "2026-11-25T12:06:00Z")).unwrap();
    let out = tempdir().unwrap();
    let r1 = db.read(|c| export_bundle(c, &out.path().join("a"), &export_opts(&cp))).unwrap();
    db.write(|tx| {
        tx.execute(
            "UPDATE approvals SET status = 'revoked', reason = 'later', resolved_by = 'someone', \
             resolved_transport = 'slack', resolved_at = '2030-01-01T00:00:00Z' WHERE id = 10",
            [],
        )?;
        tx.execute("UPDATE deliverable_releases SET cancelled_at = '2030-01-01T00:00:00Z'", [])?;
        ledger::append(
            tx,
            EventInput::new(
                "default",
                "agent.approval.resolved",
                json!({ "approval_id": 10, "decision": "revoke" }),
            ),
        )?;
        Ok(())
    })
    .unwrap();
    let r2 = db.read(|c| export_bundle(c, &out.path().join("b"), &export_opts(&cp))).unwrap();
    assert_eq!(r1.manifest, r2.manifest, "re-export drifted after a later revoke and cancel");
    for f in ["approvals/10.json", "artifacts/index.json"] {
        assert_eq!(
            std::fs::read(out.path().join("a").join(f)).unwrap(),
            std::fs::read(out.path().join("b").join(f)).unwrap(),
            "{f}"
        );
    }
    sign_bundle_offline(&out.path().join("b"), &sk);
    assert!(verify_bundle_dir(&out.path().join("b"), &trust).unwrap().ok);
}

/// NB3: exit-0 verdicts may not state something false. Stubs drop the
/// statuses to `partial`; a default-org bundle cannot hide its own approval as
/// `cross_org_events` under `--hub-bundle`; a hidden release is refused; and
/// forged artifact task/size fields are hub-asserted.
#[test]
fn exit_zero_statuses_never_overstate_what_is_bound() {
    let trust = fixture_trust();
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);
    let base = verify_bundle_dir(&fixtures_root().join("good_hub"), &trust).unwrap();
    assert_eq!(base.approvals.status, ClaimStatus::Verified);
    assert_eq!(base.artifacts.status, ClaimStatus::Verified);

    // Stubbed approval with its receipt dropped: statuses are partial.
    let tmp = good_copy("good_hub");
    let mut evs = read_events(tmp.path());
    let i = evs.iter().position(|e| e.channel == "agent.approval.resolved").unwrap();
    let j = evs.iter().position(|e| e.channel == "agent.deliverable.released").unwrap();
    let ulids = [evs[i].ulid.clone(), evs[j].ulid.clone()];
    make_stub(&mut evs[i], CLASS_UNPARSEABLE_PAYLOAD);
    make_stub(&mut evs[j], CLASS_UNPARSEABLE_PAYLOAD);
    write_events(tmp.path(), &evs);
    std::fs::remove_file(tmp.path().join("approvals/10.json")).unwrap();
    let ap = tmp.path().join("artifacts/index.json");
    let mut arts: Vec<ArtifactIndexEntry> = read_json(&ap);
    arts[0].release_status = "unreleased".into();
    arts[0].approval_id = None;
    write_json(&ap, &arts);
    let rows_path = tmp.path().join("evidence/rows.jsonl");
    let kept: String = std::fs::read_to_string(&rows_path)
        .unwrap()
        .lines()
        .filter(|l| !ulids.iter().any(|u| l.contains(u.as_str())))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&rows_path, kept).unwrap();
    edit_manifest(tmp.path(), &sk, |m| {
        m.files.remove("approvals/10.json");
    });
    bump_withheld(tmp.path(), CLASS_UNPARSEABLE_PAYLOAD, 2);
    remanifest_and_resign(tmp.path(), &sk, false);
    let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
    assert!(v.ok, "{v:?}");
    for c in [&v.completeness, &v.approvals, &v.separation_of_duties, &v.artifacts] {
        assert_eq!(c.status, ClaimStatus::Partial, "{c:?}");
        assert!(!c.basis.starts_with("no approval resolved in this bundle's window"), "{c:?}");
    }

    // A hidden release (released event in clear, artifact says unreleased).
    let tmp = good_copy("good_hub");
    let ap = tmp.path().join("artifacts/index.json");
    let mut arts: Vec<ArtifactIndexEntry> = read_json(&ap);
    arts[0].release_status = "unreleased".into();
    arts[0].approval_id = None;
    write_json(&ap, &arts);
    edit_receipt(tmp.path(), 10, |r| r.covers.clear());
    remanifest_and_resign(tmp.path(), &sk, false);
    assert_refused(&verify_bundle_dir(tmp.path(), &trust).unwrap(), "release_hidden");

    // Forged task_id and size: the artifact is no longer bound.
    let tmp = good_copy("good_hub");
    let ap = tmp.path().join("artifacts/index.json");
    let mut arts: Vec<ArtifactIndexEntry> = read_json(&ap);
    arts[0].size = 1;
    write_json(&ap, &arts);
    remanifest_and_resign(tmp.path(), &sk, false);
    let v = verify_bundle_dir(tmp.path(), &trust).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.artifacts.status, ClaimStatus::HubAsserted);

    // A default-org org bundle stubs its own approval as cross_org_events:
    // refused under --hub-bundle.
    let (_d, db) = open_test_db();
    populate_sample_db(&db, &sk, FIXTURE_KEY_ID);
    let (def_cp, hub_cp) = db
        .write(|tx| {
            let sum = compute_org_window_checkpoint(
                tx,
                "default",
                "2026-11-01T00:00:00Z",
                "2099-12-31T23:59:59Z",
                None,
            )?;
            let cp = Checkpoint {
                checkpoint_id: "cp-def".into(),
                class: CheckpointClass::Org,
                org_id: Some("default".into()),
                seq: None,
                hash: None,
                window: Some(sum.window),
                global_from_hash: Some(sum.global_from_hash),
                global_head_hash: Some(sum.global_head_hash),
                org_row_count: Some(sum.org_row_count),
                org_chain_hash: Some(sum.org_chain_hash),
                key_id: FIXTURE_KEY_ID.into(),
                signed_at: "2026-11-25T12:00:00Z".into(),
            };
            let d = checkpoint_write(tx, &cp, "2026-11-25T12:00:00Z")?;
            checkpoint_attach(tx, &cp.checkpoint_id, &sign_hex_digest(&sk, &d))?;
            let hub = write_hub_cp_at_head(tx, "cp-hub-late", &sk, FIXTURE_KEY_ID)?;
            Ok((cp.checkpoint_id, hub))
        })
        .unwrap();
    let out = tempdir().unwrap();
    let def_dir = out.path().join("def");
    let hub_dir = out.path().join("hub");
    export_signed(&db, &def_cp, &def_dir, &sk);
    export_signed(&db, &hub_cp, &hub_dir, &sk);
    let mut evs = read_events(&def_dir);
    let i = evs.iter().position(|e| e.channel == "agent.approval.resolved").unwrap();
    let ulid = evs[i].ulid.clone();
    make_stub(&mut evs[i], CLASS_CROSS_ORG_EVENTS);
    write_events(&def_dir, &evs);
    std::fs::remove_file(def_dir.join("approvals/1.json")).unwrap();
    let ap = def_dir.join("artifacts/index.json");
    let mut arts: Vec<ArtifactIndexEntry> = read_json(&ap);
    for a in &mut arts {
        a.release_status = "release_not_in_bundle".into();
        a.approval_id = None;
    }
    write_json(&ap, &arts);
    let rows_path = def_dir.join("evidence/rows.jsonl");
    let kept: String = std::fs::read_to_string(&rows_path)
        .unwrap()
        .lines()
        .filter(|l| !l.contains(ulid.as_str()))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&rows_path, kept).unwrap();
    edit_manifest(&def_dir, &sk, |m| {
        m.files.remove("approvals/1.json");
    });
    bump_withheld(&def_dir, CLASS_CROSS_ORG_EVENTS, 1);
    remanifest_and_resign(&def_dir, &sk, false);
    let hub_cc = load_verified_hub_cross_check(&hub_dir, &trust).unwrap().unwrap();
    let mut cc = trust.clone();
    cc.hub_cross_check = Some(hub_cc);
    assert_refused(&verify_bundle_dir(&def_dir, &cc).unwrap(), "unjustified_redaction");
}

/// Pins V11 (org approval event without a receipt), V12 (artifact-side
/// covers), M17 (placeholder labels outside a hub bundle's non-default
/// receipts), N25 (withheld counts follow the bundle window) and the
/// duplicate-receipt nit.
#[test]
fn pins_for_surviving_round_three_mutations() {
    let trust = fixture_trust();
    let (sk, _) = signing_key(FIXTURE_KEY_SEED);

    // V11: a default-org org bundle that drops a receipt.
    let (_d, db) = open_test_db();
    let (hub_cp, _) = populate_sample_db(&db, &sk, FIXTURE_KEY_ID);
    let def_cp = db
        .write(|tx| {
            let sum = compute_org_window_checkpoint(
                tx,
                "default",
                "2026-11-01T00:00:00Z",
                "2099-12-31T23:59:59Z",
                None,
            )?;
            let cp = Checkpoint {
                checkpoint_id: "cp-def-v11".into(),
                class: CheckpointClass::Org,
                org_id: Some("default".into()),
                seq: None,
                hash: None,
                window: Some(sum.window),
                global_from_hash: Some(sum.global_from_hash),
                global_head_hash: Some(sum.global_head_hash),
                org_row_count: Some(sum.org_row_count),
                org_chain_hash: Some(sum.org_chain_hash),
                key_id: FIXTURE_KEY_ID.into(),
                signed_at: "2026-11-25T12:00:00Z".into(),
            };
            let d = checkpoint_write(tx, &cp, "2026-11-25T12:00:00Z")?;
            checkpoint_attach(tx, &cp.checkpoint_id, &sign_hex_digest(&sk, &d))?;
            Ok(cp.checkpoint_id)
        })
        .unwrap();
    let out = tempdir().unwrap();
    let def_dir = out.path().join("def");
    export_signed(&db, &def_cp, &def_dir, &sk);
    assert!(verify_bundle_dir(&def_dir, &trust).unwrap().ok);
    let t = tempdir().unwrap();
    copy_dir_recursive(&def_dir, t.path());
    std::fs::remove_file(t.path().join("approvals/1.json")).unwrap();
    edit_manifest(t.path(), &sk, |m| {
        m.files.remove("approvals/1.json");
    });
    remanifest_and_resign(t.path(), &sk, false);
    let v = verify_bundle_dir(t.path(), &trust).unwrap();
    assert_eq!(v.exit_code, 1, "{v:?}");

    // Nit: a second org receipt bound to the same event.
    let t = tempdir().unwrap();
    copy_dir_recursive(&def_dir, t.path());
    let mut r: ApprovalReceipt = read_json(&t.path().join("approvals/1.json"));
    r.approval_id = 2;
    r.covers.clear();
    r.receipt_id = r.compute_receipt_id().unwrap();
    write_json(&t.path().join("approvals/2.json"), &r);
    remanifest_and_resign(t.path(), &sk, false);
    assert_refused(&verify_bundle_dir(t.path(), &trust).unwrap(), "cross_link_duplicate_receipt");

    // M17: a placeholder label in a default-organization receipt.
    let t = good_copy("good_hub");
    edit_receipt(t.path(), 10, |r| r.requester.label = LABEL_PLACEHOLDER.into());
    remanifest_and_resign(t.path(), &sk, false);
    assert_refused(&verify_bundle_dir(t.path(), &trust).unwrap(), "receipt_label_placeholder");

    // V12: a released artifact whose receipt covers nothing.
    let t = good_copy("good_hub");
    edit_receipt(t.path(), 10, |r| r.covers.clear());
    remanifest_and_resign(t.path(), &sk, false);
    assert_refused(&verify_bundle_dir(t.path(), &trust).unwrap(), "broken_artifact_trace");

    // N25: an incremental hub bundle counts only its own window's withheld rows.
    let full = db.read(|c| export_bundle(c, &out.path().join("full"), &export_opts(&hub_cp))).unwrap();
    let cp_seq: i64 = db
        .read(|c| {
            Ok(c.query_row("SELECT seq FROM evidence_checkpoint WHERE checkpoint_id = ?1", [&hub_cp], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    let mut inc = export_opts(&hub_cp);
    inc.from_seq = Some(cp_seq - 1);
    let part = db.read(|c| export_bundle(c, &out.path().join("inc"), &inc)).unwrap();
    assert!(full.withheld.classes.contains_key("session_credentials"), "{:?}", full.withheld);
    assert!(!part.withheld.classes.contains_key("session_credentials"), "{:?}", part.withheld);
    assert!(
        full.withheld.total > part.withheld.total,
        "full {:?} vs incremental {:?}",
        full.withheld,
        part.withheld
    );
}

/// M24/S2: verification is linear. The scanner and the artifact/release
/// bindings finish well inside a deadline on inputs that took minutes when
/// quadratic; the deadline fails the test instead of hanging it.
#[test]
fn verification_is_linear_on_large_unsigned_bundles() {
    let n = 6000usize;
    let mut events = Vec::new();
    let mut prev = GENESIS_HASH.to_string();
    let mut artifacts = Vec::new();
    for i in 0..n {
        let identity = format!("{:064x}", i + 1);
        let payload = json!({ "org_id": "default", "deliverable_id": i as i64 + 1, "task_id": 1,
                              "revision_id": i as i64 + 1, "rev_no": 1, "kind": "file", "identity": identity });
        let payload = ua_core::canonical::to_string(&payload);
        let ulid = format!("01SYN{i:021}");
        let ts = "2026-11-20T00:00:00Z";
        let eh = compute_entry_hash_v2(
            Some(&prev),
            &ulid,
            "agent.deliverable.revised",
            &payload,
            None,
            None,
            None,
            ts,
            None,
            "default",
        );
        events.push(BundleLedgerEvent {
            seq: Some(i as i64 + 1),
            org_seq: None,
            ulid,
            channel: "agent.deliverable.revised".into(),
            payload,
            originator: None,
            episode_id: None,
            causal_parent_id: None,
            created_at: ts.into(),
            dedupe_key: None,
            prev_hash: Some(prev.clone()),
            entry_hash: Some(eh.clone()),
            org_id: "default".into(),
            hash_v: HASH_V2,
            redacted: false,
            redacted_class: None,
        });
        prev = eh;
        artifacts.push(ArtifactIndexEntry {
            id: format!("deliverable:{}", i + 1),
            revision: 1,
            sha256: format!("{:064x}", n * 2 + i),
            size: 0,
            media_type: "application/octet-stream".into(),
            task_id: 1,
            run_id: None,
            attempt: None,
            policy_revision: None,
            approval_id: None,
            release_status: "unreleased".into(),
            recorded_at: "2026-11-20T00:00:00Z".into(),
        });
    }
    let dir = tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("ledger")).unwrap();
    std::fs::create_dir_all(dir.path().join("evidence")).unwrap();
    std::fs::create_dir_all(dir.path().join("policy")).unwrap();
    std::fs::create_dir_all(dir.path().join("artifacts")).unwrap();
    write_events(dir.path(), &events);
    let timeline = ua_store::evidence_bundle::PolicyTimeline::default();
    let mut rows = String::new();
    for ev in &events {
        let p: Value = serde_json::from_str(&ev.payload).unwrap();
        let row = ua_store::evidence_bundle::derive_evidence_row(ev, &p, &timeline);
        rows.push_str(&String::from_utf8(to_canonical_bytes(&row).unwrap()).unwrap());
        rows.push('\n');
    }
    std::fs::write(dir.path().join("evidence/rows.jsonl"), rows).unwrap();
    write_json(&dir.path().join("artifacts/index.json"), &artifacts);
    write_json(&dir.path().join("policy/revisions.json"), &Vec::<PolicyRevisionRecord>::new());
    write_json(&dir.path().join("withheld.json"), &WithheldReport::default());
    let cp = Checkpoint {
        checkpoint_id: "cp-syn".into(),
        class: CheckpointClass::Hub,
        org_id: None,
        seq: Some(n as i64),
        hash: Some(prev),
        window: None,
        global_from_hash: None,
        global_head_hash: None,
        org_row_count: None,
        org_chain_hash: None,
        key_id: "k-syn".into(),
        signed_at: "2026-11-25T12:00:00Z".into(),
    };
    let cpf = BundleCheckpointFile {
        format: ua_store::evidence::CHECKPOINT_FORMAT.into(),
        digest: cp.digest(),
        checkpoint: cp,
        signature: None,
    };
    write_json(&dir.path().join("ledger/checkpoint.json"), &cpf);
    let mut files = BTreeMap::new();
    for rel in [
        "artifacts/index.json",
        "evidence/rows.jsonl",
        "ledger/checkpoint.json",
        "ledger/events.jsonl",
        "policy/revisions.json",
        "withheld.json",
    ] {
        files.insert(rel.to_string(), sha256_hex(&std::fs::read(dir.path().join(rel)).unwrap()));
    }
    let mut m = BundleManifest {
        format: "ua.evidence.bundle.v1".into(),
        class: CheckpointClass::Hub,
        org_id: None,
        artifact_content: "hash_only".into(),
        window: Window { start: "2026-11-20T00:00:00Z".into(), end: "2026-11-20T00:00:00Z".into() },
        counts: ua_store::evidence_bundle::ManifestCounts {
            events: n as u64,
            redacted_events: 0,
            unhashed_legacy_prefix: 0,
            approvals: 0,
            evidence_rows: n as u64,
            policy_revisions: 0,
            artifacts: n as u64,
            withheld_total: 0,
        },
        files,
        digest: String::new(),
    };
    m.digest = m.recompute_digest().unwrap();
    write_json(&dir.path().join("manifest.json"), &m);

    let path = dir.path().to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let v = verify_bundle_dir(&path, &BundleVerifyTrust::default()).unwrap();
        let _ = tx.send(v);
    });
    let v =
        rx.recv_timeout(std::time::Duration::from_secs(60)).expect("verification did not finish within 60 s");
    assert_eq!(v.reason.as_deref(), Some("unsigned_checkpoint"), "{v:?}");
    assert_eq!(v.artifacts.status, ClaimStatus::HubAsserted);
}
