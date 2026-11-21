//! Immutable revisions of authority config: `config_revision_manage`.
//!
//! Three kinds share the policy file (`policy_file`):
//!
//! | Kind | Live document |
//! |---|---|
//! | `policy` | the whole policy mapping (and its file text) |
//! | `profile` | `{code_defaults, overlay}`: the `[profiles]` config map plus the file's `profile_defaults` overlay |
//! | `approval_rule` | the file's `require_approval` rules, plus `approval_tools` (observed, never written) |
//!
//! Revisions live in `config_revisions` (append-only: triggers refuse UPDATE
//! and DELETE) with a SHA-256 of the canonical JSON document and of the file
//! text, and each one appends an `agent.config.revision` ledger event in the
//! same transaction. An edit made directly to the file is not a revision;
//! `list` reports it as drift until `capture` records it.
//!
//! Every `commit` that changes the file and every `rollback` needs a one-time
//! human approval, requested as `config_revision_commit` /
//! `config_revision_rollback`. The approver must be a human other than the
//! requester (the approval queue's separation of duties). The pass is bound to
//! the hash of the live file it was reviewed against, so an edit that lands
//! first makes the retry a new request. The file is written atomically
//! (temporary sibling + rename) inside the database write transaction; if
//! recording fails, the previous bytes are put back.

use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::params;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::{Config, Profile, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use crate::approvals::{self, GateOutcome};
use crate::policy;
use crate::registry::{Registry, ToolCtx, blocking, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "config_revisions.v1",
    sql: "
CREATE TABLE IF NOT EXISTS config_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('policy','profile','approval_rule')),
    revision INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('capture','commit','rollback')),
    actor TEXT NOT NULL,
    document TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    raw TEXT NOT NULL DEFAULT '',
    raw_sha256 TEXT NOT NULL,
    diff TEXT NOT NULL DEFAULT '',
    parent_revision INTEGER,
    restores_revision INTEGER,
    approval_id INTEGER,
    event_ulid TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (kind, revision)
);
CREATE TRIGGER IF NOT EXISTS config_revisions_no_update BEFORE UPDATE ON config_revisions
BEGIN SELECT RAISE(ABORT, 'config revisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS config_revisions_no_delete BEFORE DELETE ON config_revisions
BEGIN SELECT RAISE(ABORT, 'config revisions are append-only'); END;
",
};

pub const CHANNEL: &str = "agent.config.revision";
/// Approval gate name for a commit that changes the live file.
pub const COMMIT_GATE: &str = "config_revision_commit";
/// Approval gate name for a rollback.
pub const ROLLBACK_GATE: &str = "config_revision_rollback";
pub const KINDS: [&str; 3] = ["policy", "profile", "approval_rule"];
pub const MAX_RAW_BYTES: usize = 256_000;
pub const MAX_DIFF_CHARS: usize = 80_000;

const SECRET_KEYS: [&str; 9] = [
    "token",
    "password",
    "secret",
    "authorization",
    "api_key",
    "apikey",
    "bearer",
    "private_key",
    "client_secret",
];
const PROSE_VALUES: [&str; 10] =
    ["allow", "deny", "false", "missing", "none", "null", "operator", "optional", "required", "true"];

fn bad(msg: impl Into<String>) -> UaError {
    UaError::invalid(msg)
}

// ---------------------------------------------------------------------------
// Hashing, diffs, secrets.

/// SHA-256 of the canonical JSON form (sorted keys, no whitespace).
pub fn doc_sha(doc: &Value) -> String {
    hex::encode(Sha256::digest(ua_core::canonical::to_string(doc).as_bytes()))
}

fn raw_sha(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn truncate_diff(mut text: String) -> String {
    if text.len() > MAX_DIFF_CHARS {
        let mut cut = MAX_DIFF_CHARS;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str("\n... diff truncated\n");
    }
    text
}

fn text_diff(before: &str, after: &str, to: &str) -> String {
    let diff = similar::TextDiff::from_lines(before, after);
    truncate_diff(diff.unified_diff().context_radius(3).header("previous", to).to_string())
}

fn pretty(doc: &Value) -> String {
    let mut s = serde_json::to_string_pretty(doc).unwrap_or_default();
    s.push('\n');
    s
}

fn doc_diff(before: Option<&Value>, after: &Value) -> String {
    let prior = before.map(pretty).unwrap_or_default();
    text_diff(&prior, &pretty(after), "next")
}

fn refuse_secrets(v: &Value) -> UaResult<()> {
    match v {
        Value::Object(o) => {
            for (k, item) in o {
                let key = k.replace('-', "_").to_lowercase();
                if SECRET_KEYS.contains(&key.as_str()) {
                    return Err(bad(format!("config documents cannot carry secret values; remove {k:?}")));
                }
                refuse_secrets(item)?;
            }
        }
        Value::Array(a) => a.iter().try_for_each(refuse_secrets)?,
        Value::String(s) if s.contains("BEGIN PRIVATE KEY") => {
            return Err(bad("config documents cannot carry private keys"));
        }
        _ => {}
    }
    Ok(())
}

/// Reject private keys and credential assignments in file text. A prose value
/// such as `password: required` is not a credential.
fn refuse_secret_text(raw: &str) -> UaResult<()> {
    if raw.contains("BEGIN PRIVATE KEY") || raw.contains("BEGIN OPENSSH PRIVATE KEY") {
        return Err(bad("config documents cannot carry private keys"));
    }
    static RX: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        let keys = {
            let mut k = SECRET_KEYS.to_vec();
            k.sort();
            k.join("|")
        };
        regex::Regex::new(&format!(r#"(?im)(?:^|[\s#"'])({keys})\s*[:=]\s*\S+"#)).expect("static pattern")
    });
    for m in RX.find_iter(raw) {
        let text = m.as_str();
        let after = text.split_once(':').map(|x| x.1).unwrap_or(text);
        let after = after.split_once('=').map(|x| x.1).unwrap_or(after);
        let token =
            after.trim().trim_matches(['"', '\'', '`']).trim_end_matches(['.', ',', ';']).to_lowercase();
        if !PROSE_VALUES.contains(&token.as_str()) {
            return Err(bad("config documents cannot carry secret values"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Live state.

fn policy_path(cfg: &Config) -> UaResult<PathBuf> {
    cfg.policy_file
        .clone()
        .ok_or_else(|| bad("policy_file is not configured; config revisions need a policy file path"))
}

fn read_raw(path: &Path) -> UaResult<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.len() > MAX_RAW_BYTES {
                return Err(bad("the policy file exceeds the revision size limit"));
            }
            String::from_utf8(bytes).map(Some).map_err(|_| bad("the policy file is not UTF-8"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(UaError::internal(format!("cannot read the policy file: {e}"))),
    }
}

/// The parsed mapping and the file text ("" when the file is missing).
fn read_policy(path: &Path) -> UaResult<(Map<String, Value>, String)> {
    let Some(raw) = read_raw(path)? else { return Ok((Map::new(), String::new())) };
    if raw.trim().is_empty() {
        return Err(bad("the policy file is empty; delete it to use the empty default policy"));
    }
    let data = policy::yaml_to_value(&raw).map_err(bad)?;
    let map = match data {
        Value::Null => Map::new(),
        Value::Object(o) => o,
        _ => return Err(bad("the policy file must be a YAML mapping")),
    };
    refuse_secrets(&Value::Object(map.clone()))?;
    Ok((map, raw))
}

fn default_policy_document() -> Map<String, Value> {
    let v = json!({ "version": 1, "enabled": true, "default_action": "allow", "rules": [] });
    v.as_object().cloned().unwrap_or_default()
}

/// The mapping a patch starts from: the file, or the default document.
fn base_mapping(path: &Path) -> UaResult<Map<String, Value>> {
    let (map, raw) = read_policy(path)?;
    Ok(if raw.is_empty() { default_policy_document() } else { map })
}

fn approval_rules_of(map: &Map<String, Value>) -> Vec<Value> {
    map.get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter(|r| r.get("action").and_then(Value::as_str) == Some("require_approval"))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn overlay_of(map: &Map<String, Value>) -> Map<String, Value> {
    map.get("profile_defaults")
        .and_then(Value::as_object)
        .map(|o| o.iter().filter(|(_, v)| v.is_string()).map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

fn env_gated(cfg: &Config) -> Vec<String> {
    let mut v = cfg.approval_tools.clone();
    v.sort();
    v.dedup();
    v
}

struct Live {
    document: Value,
    raw: String,
}

fn live(cfg: &Config, kind: &str) -> UaResult<Live> {
    let path = policy_path(cfg)?;
    let (map, raw) = read_policy(&path)?;
    let document = match kind {
        "policy" => Value::Object(if raw.is_empty() { default_policy_document() } else { map }),
        "profile" => json!({ "code_defaults": cfg.profiles, "overlay": overlay_of(&map) }),
        _ => json!({ "rules": approval_rules_of(&map), "env_gated_tools": env_gated(cfg) }),
    };
    // Profile and approval revisions restore a slice; their raw is the slice.
    let raw = if kind == "policy" { raw } else { pretty(&document) };
    Ok(Live { document, raw })
}

fn empty_sibling(cfg: &Config, kind: &str) -> Value {
    match kind {
        "profile" => json!({ "code_defaults": cfg.profiles, "overlay": {} }),
        _ => json!({ "rules": [], "env_gated_tools": env_gated(cfg) }),
    }
}

fn label_ok(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn tool_names() -> Vec<&'static str> {
    crate::builtin_registry_shared().all().map(|t| t.name).collect()
}

/// Validate a profile overlay: known labels and profiles, each entry repeats
/// or lowers the identity's configured default without granting a tool that
/// default refuses, and at least one identity holding config authority (the
/// coordinator profile) remains.
fn validate_overlay(cfg: &Config, overlay: &Value) -> UaResult<Map<String, Value>> {
    let Some(obj) = overlay.as_object() else { return Err(bad("profile overlay must be an object")) };
    let tools = tool_names();
    let mut clean = Map::new();
    for (key, value) in obj {
        if !label_ok(key) {
            return Err(bad(format!("invalid profile identity {key:?}")));
        }
        let chosen: Profile = value
            .as_str()
            .ok_or_else(|| bad(format!("unknown profile {value} for {key}")))
            .and_then(|name| Profile::parse_assignable(name).map_err(|e| bad(format!("{e} for {key}"))))?;
        let code_default: Profile =
            cfg.profiles.get(key).and_then(|p| p.parse().ok()).unwrap_or(Profile::Developer);
        if !policy::overlay_allowed(chosen, code_default, tools.iter().copied()) {
            return Err(UaError::denied(
                "overlay_escalation",
                format!(
                    "profile overlay cannot change {key} from {code_default} to {chosen}: an overlay may only repeat \
                     the configured default or reduce its privilege"
                ),
            ));
        }
        clean.insert(key.clone(), json!(chosen.as_str()));
    }
    // The coordinator profile holds config authority: it is the recovery
    // path for config revisions, so an overlay may not demote every identity
    // configured with it. Legacy profile names count as the profile they name.
    let authority = Profile::Coordinator;
    let holders: Vec<&String> = cfg
        .profiles
        .iter()
        .filter(|(_, p)| p.parse::<Profile>().ok() == Some(authority))
        .map(|(k, _)| k)
        .collect();
    let remaining = holders
        .iter()
        .filter(|k| {
            clean
                .get(k.as_str())
                .and_then(Value::as_str)
                .is_none_or(|p| p.parse::<Profile>().ok() == Some(authority))
        })
        .count();
    if !holders.is_empty() && remaining == 0 {
        return Err(bad(format!(
            "profile overlay must leave at least one identity holding config authority (the {authority} profile); \
             it is the recovery path for config revisions"
        )));
    }
    Ok(clean)
}

fn dump(map: &Map<String, Value>) -> UaResult<String> {
    let v = Value::Object(map.clone());
    refuse_secrets(&v)?;
    let text =
        serde_saphyr::to_string(&v).map_err(|e| UaError::internal(format!("cannot write YAML: {e}")))?;
    if text.len() > MAX_RAW_BYTES {
        return Err(bad("the config document exceeds the revision size limit"));
    }
    Ok(text)
}

/// The text must load as a policy (same parser the gate uses).
fn validate_text(text: &str) -> UaResult<()> {
    refuse_secret_text(text)?;
    policy::parse_policy(text).map(|_| ()).map_err(|e| bad(format!("the resulting policy is invalid: {e}")))
}

// ---------------------------------------------------------------------------
// Rows.

#[derive(Debug, Clone)]
struct Row {
    revision: i64,
    action: String,
    actor: String,
    document: Value,
    document_sha256: String,
    raw: String,
    raw_sha256: String,
    diff: String,
    parent_revision: Option<i64>,
    restores_revision: Option<i64>,
    approval_id: Option<i64>,
    event_ulid: Option<String>,
    created_at: String,
}

impl Row {
    fn public(&self) -> Value {
        json!({
            "revision": self.revision,
            "action": self.action,
            "actor": self.actor,
            "ts": self.created_at,
            "ulid": self.event_ulid,
            "document_sha256": self.document_sha256,
            "raw_sha256": self.raw_sha256,
            "parent_revision": self.parent_revision,
            "restores_revision": self.restores_revision,
            "approval_id": self.approval_id,
        })
    }

    fn same_snapshot(&self, kind: &str, live: &Live) -> bool {
        self.document_sha256 == doc_sha(&live.document)
            && (kind != "policy" || self.raw_sha256 == raw_sha(&live.raw))
    }

    fn verified(&self, kind: &str) -> UaResult<()> {
        if doc_sha(&self.document) != self.document_sha256 || raw_sha(&self.raw) != self.raw_sha256 {
            return Err(UaError::conflict(format!(
                "{kind} revision {} does not match its stored hash",
                self.revision
            )));
        }
        Ok(())
    }
}

fn load_rows(conn: &rusqlite::Connection, kind: &str) -> UaResult<Vec<Row>> {
    let mut stmt = conn.prepare(
        "SELECT revision, action, actor, document, document_sha256, raw, raw_sha256, diff, parent_revision, \
         restores_revision, approval_id, event_ulid, created_at FROM config_revisions WHERE kind = ?1 \
         ORDER BY revision ASC",
    )?;
    let rows = stmt.query_map([kind], |r| {
        let doc: String = r.get(3)?;
        Ok(Row {
            revision: r.get(0)?,
            action: r.get(1)?,
            actor: r.get(2)?,
            document: serde_json::from_str(&doc).unwrap_or(Value::String(doc)),
            document_sha256: r.get(4)?,
            raw: r.get(5)?,
            raw_sha256: r.get(6)?,
            diff: r.get(7)?,
            parent_revision: r.get(8)?,
            restores_revision: r.get(9)?,
            approval_id: r.get(10)?,
            event_ulid: r.get(11)?,
            created_at: r.get(12)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn find(rows: &[Row], kind: &str, revision: i64) -> UaResult<Row> {
    rows.iter()
        .find(|r| r.revision == revision)
        .cloned()
        .ok_or_else(|| UaError::not_found(format!("no {kind} revision {revision}")))
}

struct NewRevision<'a> {
    kind: &'a str,
    action: &'a str,
    actor: &'a str,
    live: &'a Live,
    restores: Option<i64>,
    approval_id: Option<i64>,
}

/// Append one revision row plus its ledger event.
fn record(tx: &mut WriteTx<'_>, n: NewRevision<'_>) -> UaResult<Value> {
    let prior = load_rows(tx, n.kind)?.pop();
    let revision = prior.as_ref().map(|p| p.revision + 1).unwrap_or(1);
    let diff = if n.kind == "policy" {
        text_diff(prior.as_ref().map(|p| p.raw.as_str()).unwrap_or(""), &n.live.raw, "next")
    } else {
        doc_diff(prior.as_ref().map(|p| &p.document), &n.live.document)
    };
    let document_sha256 = doc_sha(&n.live.document);
    let raw_sha256 = raw_sha(&n.live.raw);
    let now = ua_core::time::now();
    let parent = prior.as_ref().map(|p| p.revision);
    let event = ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            CHANNEL,
            json!({
                "schema": 1,
                "kind": n.kind,
                "revision": revision,
                "action": n.action,
                "actor": n.actor,
                "parent_revision": parent,
                "restores_revision": n.restores,
                "document_sha256": document_sha256,
                "raw_sha256": raw_sha256,
                "approval_id": n.approval_id,
                "diff": diff,
            }),
        )
        .by(n.actor.to_string()),
    )?;
    let ulid = event.as_ref().map(|e| e.ulid.clone());
    tx.execute(
        "INSERT INTO config_revisions (kind, revision, action, actor, document, document_sha256, raw, raw_sha256, \
         diff, parent_revision, restores_revision, approval_id, event_ulid, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            n.kind,
            revision,
            n.action,
            n.actor,
            serde_json::to_string(&n.live.document)?,
            document_sha256,
            n.live.raw,
            raw_sha256,
            diff,
            parent,
            n.restores,
            n.approval_id,
            ulid,
            now
        ],
    )?;
    Ok(json!({
        "kind": n.kind,
        "action": n.action,
        "revision": revision,
        "actor": n.actor,
        "ts": now,
        "ulid": ulid,
        "entry_hash": event.as_ref().and_then(|e| e.entry_hash.clone()),
        "document_sha256": document_sha256,
        "parent_revision": parent,
        "restores_revision": n.restores,
        "approval_id": n.approval_id,
        "unchanged": false,
        "diff": diff,
    }))
}

fn unchanged(kind: &str, row: &Row, note: Option<&str>) -> Value {
    let mut v = json!({
        "kind": kind,
        "unchanged": true,
        "revision": row.revision,
        "ulid": row.event_ulid,
        "document_sha256": row.document_sha256,
        "action": row.action,
    });
    if let Some(n) = note {
        v["note"] = json!(n);
    }
    v
}

/// Record the live document unless the latest revision already holds it.
fn append_live(tx: &mut WriteTx<'_>, cfg: &Config, kind: &str, action: &str, actor: &str) -> UaResult<Value> {
    let l = live(cfg, kind)?;
    refuse_secret_text(&l.raw)?;
    let rows = load_rows(tx, kind)?;
    if let Some(latest) = rows.last()
        && latest.same_snapshot(kind, &l)
    {
        return Ok(unchanged(kind, latest, None));
    }
    record(tx, NewRevision { kind, action, actor, live: &l, restores: None, approval_id: None })
}

/// After a write, capture the other kinds the write moved.
fn capture_siblings(tx: &mut WriteTx<'_>, cfg: &Config, primary: &str, actor: &str) -> UaResult<()> {
    for kind in KINDS {
        if kind == primary {
            continue;
        }
        let l = live(cfg, kind)?;
        let rows = load_rows(tx, kind)?;
        if let Some(latest) = rows.last()
            && latest.same_snapshot(kind, &l)
        {
            continue;
        }
        if rows.is_empty() && kind != "policy" && doc_sha(&l.document) == doc_sha(&empty_sibling(cfg, kind)) {
            continue;
        }
        record(
            tx,
            NewRevision { kind, action: "capture", actor, live: &l, restores: None, approval_id: None },
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// File writes.

fn guard_path(path: &Path) -> UaResult<()> {
    if path.symlink_metadata().is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(UaError::denied("config_path", "refusing to write config through a symlink"));
    }
    Ok(())
}

/// Write `text` to a fresh sibling and rename it over `path`.
fn replace_file(path: &Path, text: &str) -> UaResult<()> {
    guard_path(path)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|e| UaError::internal(format!("cannot create the config directory: {e}")))?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "policy".into());
    let tmp = parent.join(format!(".{name}.tmp.{}.{}", std::process::id(), ulid::Ulid::generate()));
    let write = || -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        UaError::internal(format!("cannot write the config file: {e}"))
    })
}

fn apply_text(path: &Path, text: Option<&str>) -> UaResult<()> {
    let res = match text {
        Some(t) => replace_file(path, t),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(UaError::internal(format!("cannot remove the config file: {e}"))),
        },
    };
    policy::invalidate(path);
    res
}

/// A planned write: new file text, or `None` to delete the file.
struct Plan {
    text: Option<String>,
    note: Option<String>,
}

enum Gated {
    Done(Value),
    Pending(i64),
    Denied(i64, Option<String>),
}

/// Park, refuse or apply a write under its approval gate, in one transaction.
async fn gated_write(
    ctx: &ToolCtx,
    gate: &'static str,
    payload: Value,
    kind: &'static str,
    action: &'static str,
    plan: Plan,
    restores: Option<i64>,
) -> UaResult<Value> {
    let hub = ctx.hub.clone();
    let caller = ctx.caller.clone();
    let outcome = blocking(move || {
        let cfg = hub.cfg().clone();
        let path = policy_path(&cfg)?;
        hub.db().write(|tx| {
            let approval_id = match approvals::gate(tx, &cfg, &caller, gate, &payload)? {
                GateOutcome::Pending { approval_id } => return Ok(Gated::Pending(approval_id)),
                GateOutcome::Denied { approval_id, reason } => return Ok(Gated::Denied(approval_id, reason)),
                GateOutcome::Pass { approval_id } => approval_id,
            };
            // The pass names the file it was reviewed against. Returning an
            // error rolls the transaction back, which keeps the pass unspent.
            let base_now = raw_sha(&read_raw(&path)?.unwrap_or_default());
            if payload.get("base_sha256").and_then(Value::as_str) != Some(base_now.as_str()) {
                return Err(UaError::conflict("live config changed after approval was requested; request it again"));
            }
            let previous = std::fs::read(&path).ok();
            apply_text(&path, plan.text.as_deref())?;
            let recorded = (|| {
                let l = live(&cfg, kind)?;
                let mut out = record(
                    tx,
                    NewRevision {
                        kind,
                        action,
                        actor: &caller.label,
                        live: &l,
                        restores,
                        approval_id: Some(approval_id),
                    },
                )?;
                capture_siblings(tx, &cfg, kind, &caller.label)?;
                if let Some(n) = &plan.note {
                    out["note"] = json!(n);
                }
                Ok::<_, UaError>(out)
            })();
            match recorded {
                Ok(v) => Ok(Gated::Done(v)),
                Err(e) => {
                    let restore = match &previous {
                        Some(bytes) => replace_file(&path, &String::from_utf8_lossy(bytes)),
                        None => apply_text(&path, None),
                    };
                    policy::invalidate(&path);
                    if let Err(re) = restore {
                        tracing::error!(error = %re, "could not restore the config file after a failed revision");
                    }
                    Err(e)
                }
            }
        })
    })
    .await?;
    match outcome {
        Gated::Done(v) => Ok(v),
        Gated::Pending(approval_id) => Err(UaError::ApprovalRequired { tool: gate.to_string(), approval_id }),
        Gated::Denied(approval_id, reason) => Err(UaError::denied(
            "approval_denied",
            format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
        )),
    }
}

// ---------------------------------------------------------------------------
// Actions.

fn kind_of(kind: Option<&str>) -> UaResult<&'static str> {
    let k = kind.unwrap_or("policy");
    KINDS
        .into_iter()
        .find(|x| *x == k)
        .ok_or_else(|| bad(format!("unknown config kind {k:?}; choose from {}", KINDS.join(", "))))
}

fn list(ctx: &ToolCtx, kind: &str, limit: i64, from: Option<i64>, to: Option<i64>) -> UaResult<Value> {
    let cfg = ctx.hub.cfg();
    let l = live(cfg, kind)?;
    let rows = ctx.hub.db().read(|c| load_rows(c, kind))?;
    let latest = rows.last();
    let drift = latest.is_none_or(|r| !r.same_snapshot(kind, &l));
    let latest_diff = match latest {
        _ if !drift => String::new(),
        Some(r) if kind == "policy" && r.document_sha256 == doc_sha(&l.document) => {
            text_diff(&r.raw, &l.raw, "live")
        }
        Some(r) => doc_diff(Some(&r.document), &l.document),
        None => doc_diff(None, &l.document),
    };
    let limit = limit.clamp(1, 100) as usize;
    let revisions: Vec<Value> = rows.iter().rev().take(limit).map(Row::public).collect();
    let mut out = json!({
        "kind": kind,
        "live_sha256": doc_sha(&l.document),
        "drift": drift,
        "latest_diff": latest_diff,
        "revisions": revisions,
        "count": rows.len(),
    });
    if let Some(from) = from {
        out["diff"] = diff(ctx, kind, from, to)?;
    }
    Ok(out)
}

fn diff(ctx: &ToolCtx, kind: &str, from: i64, to: Option<i64>) -> UaResult<Value> {
    let rows = ctx.hub.db().read(|c| load_rows(c, kind))?;
    let source = find(&rows, kind, from)?;
    let (label, sha, doc, raw) = match to {
        None => {
            let l = live(ctx.hub.cfg(), kind)?;
            ("live".to_string(), doc_sha(&l.document), l.document, l.raw)
        }
        Some(n) => {
            let t = find(&rows, kind, n)?;
            (t.revision.to_string(), t.document_sha256.clone(), t.document, t.raw)
        }
    };
    let shown = if kind == "policy" {
        text_diff(&source.raw, &raw, &label)
    } else {
        doc_diff(Some(&source.document), &doc)
    };
    Ok(json!({
        "kind": kind,
        "from_revision": source.revision,
        "to_revision": label,
        "from_sha256": source.document_sha256,
        "to_sha256": sha,
        "diff": shown,
    }))
}

fn show(ctx: &ToolCtx, kind: &str, revision: i64) -> UaResult<Value> {
    let rows = ctx.hub.db().read(|c| load_rows(c, kind))?;
    let row = find(&rows, kind, revision)?;
    row.verified(kind)?;
    let mut out = row.public();
    out["kind"] = json!(kind);
    out["document"] = row.document.clone();
    out["diff"] = json!(row.diff);
    if kind == "policy" {
        out["raw"] = json!(row.raw);
    }
    Ok(out)
}

fn capture(ctx: &ToolCtx, kind: &'static str) -> UaResult<Value> {
    let cfg = ctx.hub.cfg().clone();
    let actor = ctx.caller.label.clone();
    ctx.hub.db().write(|tx| append_live(tx, &cfg, kind, "capture", &actor))
}

/// The file text a commit of `document` produces, or `None` when the commit
/// matches the live document (recorded without a write).
fn commit_plan(cfg: &Config, kind: &str, document: &Value) -> UaResult<Option<String>> {
    let path = policy_path(cfg)?;
    let Some(obj) = document.as_object() else { return Err(bad("document must be an object")) };
    refuse_secrets(document)?;
    match kind {
        "policy" => {
            if let Some(overlay) = obj.get("profile_defaults").filter(|v| !v.is_null()) {
                validate_overlay(cfg, overlay)?;
            }
            if doc_sha(document) == doc_sha(&live(cfg, "policy")?.document) {
                return Ok(None);
            }
            Ok(Some(dump(obj)?))
        }
        "profile" => {
            let overlay = validate_overlay(cfg, obj.get("overlay").unwrap_or(&Value::Object(Map::new())))?;
            let mut map = base_mapping(&path)?;
            if overlay == overlay_of(&map) {
                return Ok(None);
            }
            if overlay.is_empty() {
                map.remove("profile_defaults");
            } else {
                map.insert("profile_defaults".into(), Value::Object(overlay));
            }
            Ok(Some(dump(&map)?))
        }
        _ => {
            let Some(rules) = obj.get("rules").and_then(Value::as_array) else {
                return Err(bad("approval rules must be a list"));
            };
            if rules.iter().any(|r| r.get("action").and_then(Value::as_str) != Some("require_approval")) {
                return Err(bad("every approval rule must be an object with action require_approval"));
            }
            if let Some(env) = obj.get("env_gated_tools").filter(|v| !v.is_null()) {
                let mut submitted: Vec<String> = serde_json::from_value(env.clone())
                    .map_err(|_| bad("env_gated_tools must be a list of tool names"))?;
                submitted.sort();
                submitted.dedup();
                if submitted != env_gated(cfg) {
                    return Err(bad(
                        "approval_tools is observed, not written; omit env_gated_tools or pass the current set",
                    ));
                }
            }
            let mut map = base_mapping(&path)?;
            if *rules == approval_rules_of(&map) {
                return Ok(None);
            }
            let mut kept: Vec<Value> = map
                .get("rules")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter(|r| r.get("action").and_then(Value::as_str) != Some("require_approval"))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            kept.extend(rules.iter().cloned());
            map.insert("rules".into(), Value::Array(kept));
            Ok(Some(dump(&map)?))
        }
    }
}

async fn commit(ctx: &ToolCtx, kind: &'static str, document: Value) -> UaResult<Value> {
    let cfg = ctx.hub.cfg().clone();
    let (cfg2, doc2) = (cfg.clone(), document.clone());
    let plan = blocking(move || commit_plan(&cfg2, kind, &doc2)).await?;
    let Some(text) = plan else {
        let c = ctx.clone();
        return blocking(move || {
            let cfg = c.hub.cfg().clone();
            c.hub.db().write(|tx| append_live(tx, &cfg, kind, "commit", &c.caller.label))
        })
        .await;
    };
    validate_text(&text)?;
    let path = policy_path(&cfg)?;
    let base = raw_sha(&read_raw(&path)?.unwrap_or_default());
    let payload = json!({
        "kind": kind,
        "document_sha256": doc_sha(&document),
        "text_sha256": raw_sha(&text),
        "base_sha256": base,
    });
    gated_write(ctx, COMMIT_GATE, payload, kind, "commit", Plan { text: Some(text), note: None }, None).await
}

fn restore_plan(cfg: &Config, kind: &str, target: &Row) -> UaResult<Option<Plan>> {
    let path = policy_path(cfg)?;
    match kind {
        "policy" => {
            let current = read_raw(&path)?.unwrap_or_default();
            if current == target.raw {
                return Ok(None);
            }
            let text = (!target.raw.is_empty()).then(|| target.raw.clone());
            Ok(Some(Plan { text, note: None }))
        }
        "profile" => {
            let overlay =
                validate_overlay(cfg, target.document.get("overlay").unwrap_or(&Value::Object(Map::new())))?;
            let mut map = base_mapping(&path)?;
            if overlay == overlay_of(&map) {
                return Ok(None);
            }
            if overlay.is_empty() {
                map.remove("profile_defaults");
            } else {
                map.insert("profile_defaults".into(), Value::Object(overlay));
            }
            Ok(Some(Plan { text: Some(dump(&map)?), note: None }))
        }
        _ => {
            let rules = target.document.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
            let target_env: Vec<String> =
                serde_json::from_value(target.document.get("env_gated_tools").cloned().unwrap_or(json!([])))
                    .unwrap_or_default();
            let note = (target_env != env_gated(cfg)).then(|| {
                "approval_tools was not restored; it stays at the current configuration value".to_string()
            });
            let mut map = base_mapping(&path)?;
            if rules == approval_rules_of(&map) {
                return Ok(None);
            }
            let mut kept: Vec<Value> = map
                .get("rules")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter(|r| r.get("action").and_then(Value::as_str) != Some("require_approval"))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            kept.extend(rules);
            map.insert("rules".into(), Value::Array(kept));
            Ok(Some(Plan { text: Some(dump(&map)?), note }))
        }
    }
}

async fn rollback(ctx: &ToolCtx, kind: &'static str, revision: i64) -> UaResult<Value> {
    let c = ctx.clone();
    let prepared = blocking(move || {
        let cfg = c.hub.cfg().clone();
        let rows = c.hub.db().read(|conn| load_rows(conn, kind))?;
        let target = find(&rows, kind, revision)?;
        target.verified(kind)?;
        let plan = restore_plan(&cfg, kind, &target)?;
        let base = raw_sha(&read_raw(&policy_path(&cfg)?)?.unwrap_or_default());
        Ok((target, plan, base))
    })
    .await?;
    let (target, plan, base) = prepared;
    let Some(plan) = plan else {
        // Already live: nothing to approve, no pass spent.
        return Ok(unchanged(kind, &target, None));
    };
    if let Some(text) = &plan.text {
        validate_text(text)?;
    }
    let payload = json!({
        "kind": kind,
        "revision": revision,
        "document_sha256": target.document_sha256,
        "base_sha256": base,
    });
    let mut out = gated_write(ctx, ROLLBACK_GATE, payload, kind, "rollback", plan, Some(revision)).await?;
    out["restores_revision"] = json!(revision);
    Ok(out)
}

// ---------------------------------------------------------------------------
// The tool.

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManageParams {
    /// `policy` (default), `profile` or `approval_rule`.
    pub kind: Option<String>,
    /// Revision number (show, rollback).
    pub revision: Option<i64>,
    /// Diff source revision (diff; optional on list).
    pub from_revision: Option<i64>,
    /// Diff target revision; omitted means the live document.
    pub to_revision: Option<i64>,
    /// The new document (commit). Policy: the whole mapping. Profile:
    /// `{overlay: {identity: profile}}`. Approval rules: `{rules: [...]}`.
    pub document: Option<Value>,
    /// Maximum revisions listed, 1-100 (default 50).
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManageArgs {
    /// One of list (default), diff, show, capture, commit, rollback.
    #[serde(default = "default_action")]
    pub action: String,
    /// `policy` (default), `profile` or `approval_rule`.
    pub kind: Option<String>,
    /// Revision number (show, rollback).
    pub revision: Option<i64>,
    /// Diff source revision (diff; optional on list).
    pub from_revision: Option<i64>,
    /// Diff target revision; omitted means the live document.
    pub to_revision: Option<i64>,
    /// The new document (commit).
    pub document: Option<Value>,
    /// Maximum revisions listed, 1-100 (default 50).
    pub limit: Option<i64>,
    /// The same arguments as one object (the consolidated `*_manage` form);
    /// a field given here wins over the top-level one.
    pub params: Option<ManageParams>,
}

fn default_action() -> String {
    "list".into()
}

async fn manage(ctx: ToolCtx, a: ManageArgs) -> UaResult<Value> {
    let p = a.params.unwrap_or_default();
    let kind = kind_of(p.kind.as_deref().or(a.kind.as_deref()))?;
    let revision = p.revision.or(a.revision);
    let from = p.from_revision.or(a.from_revision);
    let to = p.to_revision.or(a.to_revision);
    let document = p.document.or(a.document);
    let limit = p.limit.or(a.limit).unwrap_or(50);
    match crate::routes::action_of("config_revision_manage", Some(&a.action))? {
        "list" => blocking(move || list(&ctx, kind, limit, from, to)).await,
        "diff" => {
            let from = from.ok_or_else(|| bad("diff requires from_revision"))?;
            blocking(move || diff(&ctx, kind, from, to)).await
        }
        "show" => {
            let revision = revision.ok_or_else(|| bad("show requires revision"))?;
            blocking(move || show(&ctx, kind, revision)).await
        }
        "capture" => blocking(move || capture(&ctx, kind)).await,
        "commit" => {
            let document = document.ok_or_else(|| bad("commit requires document"))?;
            commit(&ctx, kind, document).await
        }
        "rollback" => {
            let revision = revision.ok_or_else(|| bad("rollback requires revision"))?;
            rollback(&ctx, kind, revision).await
        }
        other => Err(crate::routes::unhandled("config_revision_manage", other)),
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "config_revision_manage",
            "List, diff, show, capture, commit or roll back authority config (kind policy, profile or approval_rule). \
             Revisions are append-only with content hashes. A commit that changes the policy file and every \
             rollback need a one-time approval from a human other than the requester (gates \
             config_revision_commit / config_revision_rollback); the pass is bound to the live file. A profile \
             overlay may only repeat or lower an identity's configured default. approval_tools is observed, never \
             written.",
            manage,
        )
        .handler_may_gate(crate::HandlerGate::Actions(&["commit", "rollback"]))
        .family("config"),
    );
}
