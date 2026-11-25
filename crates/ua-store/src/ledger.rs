//! The append-only event ledger.
//!
//! Every row carries `prev_hash` and `entry_hash`. `entry_hash` is the SHA-256
//! of a canonical JSON object of the row's fields plus `prev_hash`, so editing
//! or deleting any row breaks every hash after it. The canonical encoding is
//! byte-compatible with the original Python hub (sorted keys, `,`/`:`
//! separators, non-ASCII escaped as `\uXXXX`), so imported chains verify.
//!
//! Event ids are ULIDs minted inside the write transaction against the log's
//! current maximum, so id order equals commit order.
//!
//! Once `organization.v1.store` has applied, every row also carries `org_id`
//! and `hash_v`. This build writes and verifies only `hash_v = 1`, the
//! nine-field form above, which does **not** cover `org_id`: a row's
//! `org_id` is recorded but not tamper-evident until rows are written with
//! `hash_v = 2` (see `docs/organization.md`, The ledger). [`verify`] refuses
//! any other `hash_v`.

use std::fmt::Write as _;

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};

use crate::db::WriteTx;
use crate::schema::SchemaPart;

pub const GENESIS_HASH: &str = "GENESIS";

/// The only hash form this build writes and verifies.
pub const HASH_V: i64 = 1;

/// Refuse a ledger whose newest row uses a hash form newer than [`HASH_V`].
///
/// This is the rollback fence: a hub rolled back from a build that writes
/// `hash_v = 2` must not append `hash_v = 1` rows after those, which no
/// later `verify` accepts. [`crate::Db`] runs it at open and [`append`] before
/// every write.
///
/// It reads only the newest row (by `seq`, the primary key, so a single
/// index lookup however long the ledger is), not `MAX(hash_v)` (a full scan,
/// as `hash_v` has no index). That is sufficient because a valid chain never
/// decreases its `hash_v` (`docs/organization.md`, The ledger: a `hash_v = 1`
/// row after the first `hash_v = 2` row fails verification), so the newest
/// row carries the highest form. A ledger whose newest row has a lower form
/// than an earlier one already fails [`verify`]. Ledgers without the column
/// (`organization.v1.store` not applied) pass.
pub fn check_hash_form(conn: &Connection) -> UaResult<()> {
    if has_org_columns(conn)? { refuse_newer_hash_form(conn) } else { Ok(()) }
}

/// Whether `event_log` has the `org_id` and `hash_v` columns
/// (`organization.v1.store` applied). A ledger without them is one from
/// before organizations, such as an older backup just restored; the part
/// adds them on the next open.
fn has_org_columns(conn: &Connection) -> UaResult<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM pragma_table_info('event_log') WHERE name = 'hash_v'", [], |_| Ok(true))
        .optional()?
        .unwrap_or(false))
}

fn refuse_newer_hash_form(conn: &Connection) -> UaResult<()> {
    let newest: Option<rusqlite::types::Value> = conn
        .query_row("SELECT hash_v FROM event_log ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
        .optional()?;
    match newest {
        None | Some(rusqlite::types::Value::Integer(HASH_V)) => Ok(()),
        Some(rusqlite::types::Value::Integer(v)) if v > HASH_V => Err(UaError::conflict(format!(
            "event_log holds rows with hash_v {v}, written by a newer build; this build writes and verifies \
             only hash_v {HASH_V}, so it refuses to append to this ledger. Run a build that supports hash_v {v}"
        ))),
        // Anything else is not a form any build writes; `verify` reports it.
        Some(_) => Ok(()),
    }
}

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "ledger.v1",
    sql: "
CREATE TABLE IF NOT EXISTS event_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ulid TEXT NOT NULL UNIQUE,
    channel TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    originator TEXT,
    episode_id TEXT,
    causal_parent_id TEXT,
    created_at TEXT NOT NULL,
    dedupe_key TEXT UNIQUE,
    prev_hash TEXT,
    entry_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_log_channel ON event_log(channel, seq);
CREATE INDEX IF NOT EXISTS idx_event_log_created ON event_log(created_at);
CREATE INDEX IF NOT EXISTS idx_event_log_episode ON event_log(episode_id);
-- The ledger is append-only: refuse edits and deletes at the database level.
CREATE TRIGGER IF NOT EXISTS event_log_no_update BEFORE UPDATE ON event_log
BEGIN SELECT RAISE(ABORT, 'event_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS event_log_no_delete BEFORE DELETE ON event_log
BEGIN SELECT RAISE(ABORT, 'event_log is append-only'); END;
",
};

/// Facts about the ledger itself. `unhashed_legacy_prefix` is the number of
/// unhashed rows an import copied ahead of the hash chain; [`verify`]
/// requires the ledger's unhashed prefix to be exactly that long (0 when
/// nothing was imported).
pub const META_SCHEMA: SchemaPart = SchemaPart {
    name: "ledger_meta.v1",
    sql: "
CREATE TABLE IF NOT EXISTS ledger_meta (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
",
};

/// The `ledger_meta` key recording the imported unhashed prefix.
pub const LEGACY_PREFIX_KEY: &str = "unhashed_legacy_prefix";

/// Add `n` unhashed rows to the recorded legacy prefix, inside the write
/// transaction that copies them.
pub fn record_legacy_prefix(tx: &mut WriteTx<'_>, n: u64) -> UaResult<()> {
    if n == 0 {
        return Ok(());
    }
    tx.execute(
        "INSERT INTO ledger_meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = value + excluded.value",
        params![LEGACY_PREFIX_KEY, i64::try_from(n).unwrap_or(i64::MAX)],
    )?;
    Ok(())
}

/// The recorded legacy prefix; 0 when nothing was imported (or the table
/// does not exist, as in a store opened without [`META_SCHEMA`]).
fn recorded_legacy_prefix(conn: &Connection) -> UaResult<u64> {
    let has_table: bool = conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ledger_meta'", [], |_| {
            Ok(true)
        })
        .optional()?
        .unwrap_or(false);
    if !has_table {
        return Ok(0);
    }
    let v: Option<i64> = conn
        .query_row("SELECT value FROM ledger_meta WHERE key = ?1", [LEGACY_PREFIX_KEY], |r| r.get(0))
        .optional()?;
    Ok(v.and_then(|v| u64::try_from(v).ok()).unwrap_or(0))
}

/// A new event.
///
/// There is no `Default`: every event names its organization, the
/// organization of the row it is about (not the caller's;
/// `docs/organization.md`, The ledger). Today that is always
/// [`ua_core::DEFAULT_ORG`].
#[derive(Debug, Clone)]
pub struct EventInput {
    /// The organization of the affected row. Recorded in `event_log.org_id`,
    /// which `hash_v = 1` does not cover.
    pub org_id: String,
    pub channel: String,
    pub payload: Value,
    pub originator: Option<String>,
    pub episode_id: Option<String>,
    pub causal_parent_id: Option<String>,
    /// When set, a second append with the same key is a no-op.
    pub dedupe_key: Option<String>,
}

impl EventInput {
    pub fn new(org_id: impl Into<String>, channel: impl Into<String>, payload: Value) -> Self {
        Self {
            org_id: org_id.into(),
            channel: channel.into(),
            payload,
            originator: None,
            episode_id: None,
            causal_parent_id: None,
            dedupe_key: None,
        }
    }

    pub fn by(mut self, originator: impl Into<String>) -> Self {
        self.originator = Some(originator.into());
        self
    }

    pub fn dedupe(mut self, key: impl Into<String>) -> Self {
        self.dedupe_key = Some(key.into());
        self
    }
}

/// A stored event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub seq: i64,
    pub ulid: String,
    pub channel: String,
    pub payload: Value,
    pub originator: Option<String>,
    pub episode_id: Option<String>,
    pub causal_parent_id: Option<String>,
    pub created_at: String,
    pub dedupe_key: Option<String>,
    pub prev_hash: Option<String>,
    pub entry_hash: Option<String>,
}

const COLUMNS: &str = "seq, ulid, channel, payload, originator, episode_id, causal_parent_id, created_at, \
                       dedupe_key, prev_hash, entry_hash";

fn from_row(r: &Row<'_>) -> rusqlite::Result<Event> {
    let payload: String = r.get(3)?;
    Ok(Event {
        seq: r.get(0)?,
        ulid: r.get(1)?,
        channel: r.get(2)?,
        payload: serde_json::from_str(&payload).unwrap_or(Value::String(payload)),
        originator: r.get(4)?,
        episode_id: r.get(5)?,
        causal_parent_id: r.get(6)?,
        created_at: r.get(7)?,
        dedupe_key: r.get(8)?,
        prev_hash: r.get(9)?,
        entry_hash: r.get(10)?,
    })
}

/// Encode a string the way Python's `json.dumps` does with `ensure_ascii=True`.
pub(crate) fn py_json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The canonical hash of one entry.
#[allow(clippy::too_many_arguments)]
pub fn compute_entry_hash(
    prev_hash: Option<&str>,
    ulid: &str,
    channel: &str,
    payload_str: &str,
    originator: Option<&str>,
    episode_id: Option<&str>,
    causal_parent_id: Option<&str>,
    created_at: &str,
    dedupe_key: Option<&str>,
) -> String {
    // Keys in sorted order, exactly as `json.dumps(sort_keys=True)` emits them.
    let fields: [(&str, Option<&str>); 9] = [
        ("causal_parent_id", causal_parent_id),
        ("channel", Some(channel)),
        ("created_at", Some(created_at)),
        ("dedupe_key", dedupe_key),
        ("episode_id", episode_id),
        ("originator", originator),
        ("payload", Some(payload_str)),
        ("prev_hash", Some(prev_hash.unwrap_or(GENESIS_HASH))),
        ("ulid", Some(ulid)),
    ];
    let mut out = String::with_capacity(256 + payload_str.len());
    out.push('{');
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        py_json_str(&mut out, k);
        out.push(':');
        match v {
            Some(v) => py_json_str(&mut out, v),
            None => out.push_str("null"),
        }
    }
    out.push('}');
    hex::encode(Sha256::digest(out.as_bytes()))
}

fn mint_ulid(conn: &Connection) -> UaResult<String> {
    let last: Option<String> = conn
        .query_row("SELECT ulid FROM event_log ORDER BY ulid DESC LIMIT 1", [], |r| r.get(0))
        .optional()?;
    let fresh = ulid::Ulid::generate();
    let id = match last.and_then(|s| ulid::Ulid::from_string(&s).ok()) {
        Some(prev) if fresh <= prev => {
            prev.increment().map_err(|_| UaError::internal("ULID space exhausted for this millisecond"))?
        }
        _ => fresh,
    };
    Ok(id.to_string())
}

/// Append an event inside the caller's transaction. Returns `None` when the
/// dedupe key was already used.
pub fn append(tx: &mut WriteTx<'_>, input: EventInput) -> UaResult<Option<Event>> {
    if input.channel.trim().is_empty() {
        return Err(UaError::invalid("event channel must not be empty"));
    }
    if input.org_id.trim().is_empty() {
        return Err(UaError::invalid("event org_id must not be empty"));
    }
    let org_columns = has_org_columns(tx)?;
    if org_columns {
        refuse_newer_hash_form(tx)?;
        // The organization must exist: one primary-key lookup in `orgs` (a
        // handful of rows), in the same write transaction as the insert.
        // `event_log` has no existence trigger, so this is the check.
        let known: bool = tx
            .query_row("SELECT 1 FROM orgs WHERE id = ?1", [&input.org_id], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        if !known {
            return Err(UaError::invalid(format!(
                "unknown organization {:?}; the event was not recorded",
                input.org_id
            )));
        }
    } else if input.org_id != ua_core::DEFAULT_ORG {
        // Nowhere to record another organization: refuse rather than drop it.
        return Err(UaError::conflict(format!(
            "event_log has no org_id column (organization.v1.store not applied), so an event for \
             organization {:?} cannot be recorded",
            input.org_id
        )));
    }
    if let Some(k) = &input.dedupe_key {
        let seen: Option<i64> =
            tx.query_row("SELECT seq FROM event_log WHERE dedupe_key = ?1", [k], |r| r.get(0)).optional()?;
        if seen.is_some() {
            return Ok(None);
        }
    }
    let payload_str = serde_json::to_string(&input.payload)?;
    let created_at = ua_core::time::now();
    let ulid = mint_ulid(tx)?;
    let prev: Option<String> = tx
        .query_row(
            "SELECT entry_hash FROM event_log WHERE entry_hash IS NOT NULL ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let prev_hash = prev.unwrap_or_else(|| GENESIS_HASH.to_string());
    let entry_hash = compute_entry_hash(
        Some(&prev_hash),
        &ulid,
        &input.channel,
        &payload_str,
        input.originator.as_deref(),
        input.episode_id.as_deref(),
        input.causal_parent_id.as_deref(),
        &created_at,
        input.dedupe_key.as_deref(),
    );
    if org_columns {
        tx.execute(
            "INSERT INTO event_log (ulid, channel, payload, originator, episode_id, causal_parent_id, created_at, \
             dedupe_key, prev_hash, entry_hash, org_id, hash_v) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                ulid,
                input.channel,
                payload_str,
                input.originator,
                input.episode_id,
                input.causal_parent_id,
                created_at,
                input.dedupe_key,
                prev_hash,
                entry_hash,
                input.org_id,
                HASH_V
            ],
        )?;
    } else {
        tx.execute(
            "INSERT INTO event_log (ulid, channel, payload, originator, episode_id, causal_parent_id, created_at, \
             dedupe_key, prev_hash, entry_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                ulid,
                input.channel,
                payload_str,
                input.originator,
                input.episode_id,
                input.causal_parent_id,
                created_at,
                input.dedupe_key,
                prev_hash,
                entry_hash
            ],
        )?;
    }
    let event = Event {
        seq: tx.last_insert_rowid(),
        ulid,
        channel: input.channel,
        payload: input.payload,
        originator: input.originator,
        episode_id: input.episode_id,
        causal_parent_id: input.causal_parent_id,
        created_at,
        dedupe_key: input.dedupe_key,
        prev_hash: Some(prev_hash),
        entry_hash: Some(entry_hash),
    };
    tx.pending.push(event.clone());
    Ok(Some(event))
}

/// [`append`] an event that must outlive the transaction it is appended in:
/// a refusal recorded by the call it refuses, which then fails and rolls
/// back. When the transaction commits, the event is committed with it, once.
/// When it rolls back, [`crate::Db::write`] appends the event again in a
/// separate transaction before returning the call's error. Use it only for
/// events that state a fact independent of the rest of the transaction.
pub fn append_surviving(tx: &mut WriteTx<'_>, input: EventInput) -> UaResult<Option<Event>> {
    let copy = input.clone();
    let out = append(tx, input)?;
    if out.is_some() {
        tx.surviving.push(copy);
    }
    Ok(out)
}

/// Filters for [`query`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventQuery {
    pub channels: Option<Vec<String>>,
    pub channel_prefix: Option<String>,
    pub since: Option<String>,
    pub after_seq: Option<i64>,
    pub originator: Option<String>,
    pub limit: Option<usize>,
}

/// Read events in commit order.
pub fn query(conn: &Connection, q: &EventQuery) -> UaResult<Vec<Event>> {
    query_filtered(conn, q, "1=1", &[])
}

/// Read events with an additional SQL predicate applied before pagination.
/// The predicate is a code-defined expression over the event log. Bind its
/// values with anonymous placeholders in the order given by the slice.
pub fn query_filtered(
    conn: &Connection,
    q: &EventQuery,
    predicate: &'static str,
    values: &[&dyn rusqlite::ToSql],
) -> UaResult<Vec<Event>> {
    let mut sql = format!("SELECT {COLUMNS} FROM event_log WHERE 1=1");
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(chs) = q.channels.as_ref().filter(|c| !c.is_empty()) {
        let marks = vec!["?"; chs.len()].join(",");
        sql.push_str(&format!(" AND channel IN ({marks})"));
        for c in chs {
            args.push(Box::new(c.clone()));
        }
    }
    if let Some(p) = &q.channel_prefix {
        sql.push_str(" AND substr(channel, 1, length(?)) = ?");
        args.push(Box::new(p.clone()));
        args.push(Box::new(p.clone()));
    }
    if let Some(s) = &q.since {
        sql.push_str(" AND created_at >= ?");
        args.push(Box::new(s.clone()));
    }
    if let Some(a) = q.after_seq {
        sql.push_str(" AND seq > ?");
        args.push(Box::new(a));
    }
    if let Some(o) = &q.originator {
        sql.push_str(" AND originator = ?");
        args.push(Box::new(o.clone()));
    }
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    sql.push_str(" AND (");
    sql.push_str(predicate);
    sql.push(')');
    // With a cursor, page forward: the oldest `limit` rows after it, so a
    // poller never skips rows. Without one, the newest `limit` rows. Both are
    // returned oldest first.
    let sql = if q.after_seq.is_some() {
        format!("{sql} ORDER BY seq ASC LIMIT {limit}")
    } else {
        format!("SELECT * FROM ({sql} ORDER BY seq DESC LIMIT {limit}) ORDER BY seq ASC")
    };
    let mut stmt = conn.prepare(&sql)?;
    let bindings = args.iter().map(|b| b.as_ref()).chain(values.iter().copied());
    let rows = stmt.query_map(rusqlite::params_from_iter(bindings), from_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Outcome of [`verify`].
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct VerifyReport {
    pub ok: bool,
    /// Hashed rows recomputed and linked.
    pub checked: u64,
    /// Unhashed rows before the first hashed row: a legacy prefix carried
    /// over from an import, never verified.
    pub unhashed_legacy_prefix: u64,
    pub first_bad_seq: Option<i64>,
    pub reason: Option<String>,
}

/// Recompute the whole chain.
///
/// Rows without an `entry_hash` are accepted only as a contiguous prefix
/// before the first hashed row (an imported legacy ledger, which the import
/// verifies the same way) and are counted in `unhashed_legacy_prefix`. That
/// prefix must be exactly as long as the import recorded in `ledger_meta`
/// (0 when nothing was imported), so an unhashed row slipped in ahead of the
/// chain (a low or negative `seq`) fails too. An unhashed row after the
/// chain has started fails verification: nothing the hub appends lacks a
/// hash, so such a row was written around the ledger.
///
/// Every row's `hash_v` (when the column exists, after
/// `organization.v1.store`) must be [`HASH_V`]; any other value fails, so a
/// row cannot claim a hash form this build does not check.
pub fn verify(conn: &Connection) -> UaResult<VerifyReport> {
    let expected_prefix = recorded_legacy_prefix(conn)?;
    let has_hash_v: bool = conn
        .query_row("SELECT 1 FROM pragma_table_info('event_log') WHERE name = 'hash_v'", [], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    let hash_v = if has_hash_v { "hash_v" } else { "1" };
    let mut stmt = conn.prepare(&format!(
        "SELECT seq, ulid, channel, payload, originator, episode_id, causal_parent_id, created_at, dedupe_key, \
         prev_hash, entry_hash, {hash_v} FROM event_log ORDER BY seq ASC"
    ))?;
    let mut rows = stmt.query([])?;
    let mut expected_prev = GENESIS_HASH.to_string();
    let mut report =
        VerifyReport { ok: true, checked: 0, unhashed_legacy_prefix: 0, first_bad_seq: None, reason: None };
    let mut first_unhashed: Option<i64> = None;
    while let Some(r) = rows.next()? {
        let seq: i64 = r.get(0)?;
        let fail = |reason: &str| VerifyReport {
            ok: false,
            checked: report.checked,
            unhashed_legacy_prefix: report.unhashed_legacy_prefix,
            first_bad_seq: Some(seq),
            reason: Some(reason.to_string()),
        };
        // Read untyped, so a tampered non-integer value is reported, not an error.
        let form: rusqlite::types::Value = r.get(11)?;
        if form != rusqlite::types::Value::Integer(HASH_V) {
            let shown = match form {
                rusqlite::types::Value::Null => "NULL".to_string(),
                rusqlite::types::Value::Integer(v) => v.to_string(),
                rusqlite::types::Value::Real(v) => v.to_string(),
                rusqlite::types::Value::Text(v) => format!("{v:?}"),
                rusqlite::types::Value::Blob(_) => "a blob".to_string(),
            };
            return Ok(fail(&format!("unknown hash_v {shown}; this build verifies only hash_v = {HASH_V}")));
        }
        let entry: Option<String> = r.get(10)?;
        let Some(entry) = entry else {
            if report.checked > 0 {
                return Ok(fail("unhashed row after the hash chain started"));
            }
            report.unhashed_legacy_prefix += 1;
            first_unhashed.get_or_insert(seq);
            continue;
        };
        let prev: Option<String> = r.get(9)?;
        if prev.as_deref() != Some(expected_prev.as_str()) {
            return Ok(fail("prev_hash does not link to the previous entry"));
        }
        let get = |i: usize| -> rusqlite::Result<Option<String>> { r.get(i) };
        let recomputed = compute_entry_hash(
            prev.as_deref(),
            &r.get::<_, String>(1)?,
            &r.get::<_, String>(2)?,
            &r.get::<_, String>(3)?,
            get(4)?.as_deref(),
            get(5)?.as_deref(),
            get(6)?.as_deref(),
            &r.get::<_, String>(7)?,
            get(8)?.as_deref(),
        );
        if recomputed != entry {
            return Ok(fail("entry_hash does not match the row contents"));
        }
        report.checked += 1;
        expected_prev = entry;
    }
    if report.unhashed_legacy_prefix != expected_prefix {
        report.ok = false;
        report.first_bad_seq = first_unhashed;
        report.reason = Some(format!(
            "{} unhashed row(s) precede the hash chain, but the import recorded a legacy prefix of {expected_prefix}",
            report.unhashed_legacy_prefix
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;
    use serde_json::json;

    #[test]
    fn python_compatible_hash() {
        // Reference value computed with the original implementation:
        // compute_entry_hash(None, "01J0000000000000000000000", "agent.task.updated",
        //   '{"id": 1, "t": "café"}', "builder-1", None, None, "2026-01-01T00:00:00+00:00")
        let h = compute_entry_hash(
            None,
            "01J0000000000000000000000",
            "agent.task.updated",
            "{\"id\": 1, \"t\": \"café\"}",
            Some("builder-1"),
            None,
            None,
            "2026-01-01T00:00:00+00:00",
            None,
        );
        assert_eq!(h, include_str!("../tests/fixtures/py_hash.txt").trim());
    }

    fn channels(db: &Db) -> Vec<String> {
        db.read(|c| query(c, &EventQuery::default())).unwrap().into_iter().map(|e| e.channel).collect()
    }

    #[test]
    fn a_surviving_event_outlives_the_rolled_back_write() {
        let db = Db::open_in_memory(&[SCHEMA]).unwrap();
        let mut rx = db.subscribe();
        let err = db
            .write(|tx| -> UaResult<()> {
                append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.effect", json!({})))?;
                append_surviving(
                    tx,
                    EventInput::new(ua_core::DEFAULT_ORG, "test.refused", json!({ "n": 1 })),
                )?;
                Err(UaError::denied("refused", "the call is refused"))
            })
            .unwrap_err();
        assert_eq!(err.reason_code(), Some("refused"), "the caller sees the original error: {err:?}");
        // The rest of the transaction rolled back; the refusal did not.
        assert_eq!(channels(&db), ["test.refused"]);
        assert_eq!(rx.try_recv().unwrap().channel, "test.refused", "the replayed event is broadcast");
        assert!(rx.try_recv().is_err(), "nothing rolled back is broadcast");
        // The chain still verifies with the replayed event in it.
        let report = db.read(verify).unwrap();
        assert!(report.ok, "{report:?}");
    }

    #[test]
    fn a_surviving_event_in_a_committed_write_is_recorded_once() {
        let db = Db::open_in_memory(&[SCHEMA]).unwrap();
        db.write(|tx| {
            append_surviving(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.refused", json!({})))?;
            append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.effect", json!({})))
        })
        .unwrap();
        assert_eq!(channels(&db), ["test.refused", "test.effect"]);
        // A deduplicated surviving event is not replayed either.
        let key = "refusal:1";
        db.write(|tx| {
            append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.refused", json!({})).dedupe(key))
        })
        .unwrap();
        let _ = db.write(|tx| -> UaResult<()> {
            append_surviving(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG, "test.refused", json!({})).dedupe(key),
            )?;
            Err(UaError::denied("refused", "again"))
        });
        assert_eq!(channels(&db).len(), 3);
    }

    #[test]
    fn a_cursor_pages_forward_without_skipping() {
        let db = Db::open_in_memory(&[SCHEMA]).unwrap();
        for i in 0..10 {
            db.write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({ "i": i }))))
                .unwrap();
        }
        let page = |after: i64| {
            db.read(|c| {
                query(c, &EventQuery { after_seq: Some(after), limit: Some(3), ..Default::default() })
            })
            .unwrap()
        };
        let first = page(0);
        assert_eq!(first.iter().map(|e| e.payload["i"].as_i64().unwrap()).collect::<Vec<_>>(), [0, 1, 2]);
        let next = page(first.last().unwrap().seq);
        assert_eq!(next.iter().map(|e| e.payload["i"].as_i64().unwrap()).collect::<Vec<_>>(), [3, 4, 5]);
        // Without a cursor: the newest rows, oldest first.
        let newest = db.read(|c| query(c, &EventQuery { limit: Some(2), ..Default::default() })).unwrap();
        assert_eq!(newest.iter().map(|e| e.payload["i"].as_i64().unwrap()).collect::<Vec<_>>(), [8, 9]);
    }

    #[test]
    fn append_chain_verify_and_tamper() {
        let db = Db::open_in_memory(&[SCHEMA]).unwrap();
        let mut rx = db.subscribe();
        for i in 0..5 {
            db.write(|tx| {
                append(
                    tx,
                    EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({ "i": i })).by("tester"),
                )
            })
            .unwrap();
        }
        assert_eq!(rx.try_recv().unwrap().payload, json!({ "i": 0 }));
        let deduped = db
            .write(|tx| {
                append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.once", json!({})).dedupe("k1"))?;
                append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.once", json!({})).dedupe("k1"))
            })
            .unwrap();
        assert!(deduped.is_none());

        let report = db.read(verify).unwrap();
        assert!(report.ok, "{report:?}");
        assert_eq!(report.checked, 6);

        let evs = db
            .read(|c| query(c, &EventQuery { channel_prefix: Some("test.ev".into()), ..Default::default() }))
            .unwrap();
        assert_eq!(evs.len(), 5);
        assert!(evs.windows(2).all(|w| w[0].ulid < w[1].ulid));

        // Updates are refused by the trigger; tamper by dropping it first.
        assert!(
            db.write(|tx| Ok(tx.execute("UPDATE event_log SET payload = '{}' WHERE seq = 2", [])?)).is_err()
        );
        db.write(|tx| {
            tx.execute_batch("DROP TRIGGER event_log_no_update")?;
            tx.execute("UPDATE event_log SET payload = '{\"i\":99}' WHERE seq = 2", [])?;
            Ok(())
        })
        .unwrap();
        let report = db.read(verify).unwrap();
        assert!(!report.ok);
        assert_eq!(report.first_bad_seq, Some(2));
    }

    #[test]
    fn verify_refuses_a_hash_form_it_does_not_check() {
        let db = Db::open_in_memory(&[
            crate::Part::from(SCHEMA),
            crate::Part::from(META_SCHEMA),
            crate::Part::from(crate::org::STORE_PART),
        ])
        .unwrap();
        for i in 0..3 {
            db.write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({ "i": i }))))
                .unwrap();
        }
        assert!(db.read(verify).unwrap().ok);
        db.write(|tx| Ok(tx.execute_batch("DROP TRIGGER event_log_no_update;")?)).unwrap();
        // A text value keeps TEXT storage in an INTEGER column only when it does
        // not look like a number.
        for (value, shown) in [("2", "2"), ("'v1'", "\"v1\"")] {
            db.write(|tx| {
                Ok(tx.execute(&format!("UPDATE event_log SET hash_v = {value} WHERE seq = 2"), [])?)
            })
            .unwrap();
            let report = db.read(verify).unwrap();
            assert!(!report.ok, "{value}: {report:?}");
            assert_eq!(report.first_bad_seq, Some(2), "{value}");
            assert_eq!(
                report.reason.as_deref(),
                Some(format!("unknown hash_v {shown}; this build verifies only hash_v = 1").as_str()),
                "{value}"
            );
        }
    }

    /// The rollback fence: a ledger whose newest row has a newer hash form
    /// (as a later build will write) refuses both `append` and `Db::open`,
    /// naming both forms, so a rolled-back build never writes `hash_v = 1`
    /// rows after `hash_v = 2` ones.
    #[test]
    fn a_ledger_with_a_newer_hash_form_refuses_append_and_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        let parts = [
            crate::Part::from(SCHEMA),
            crate::Part::from(META_SCHEMA),
            crate::Part::from(crate::org::STORE_PART),
        ];
        let db = Db::open(&path, &parts).unwrap();
        for i in 0..2 {
            db.write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({ "i": i }))))
                .unwrap();
        }
        // Stand in for a newer build's row: the newest row claims hash_v 2.
        db.write(|tx| {
            tx.execute_batch("DROP TRIGGER event_log_no_update;")?;
            tx.execute("UPDATE event_log SET hash_v = 2 WHERE seq = (SELECT MAX(seq) FROM event_log)", [])?;
            Ok(())
        })
        .unwrap();
        let before: i64 =
            db.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM event_log", [], |r| r.get(0))?)).unwrap();
        let err = db
            .write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({}))))
            .unwrap_err()
            .to_string();
        assert!(err.contains("hash_v 2") && err.contains("only hash_v 1"), "{err}");
        let after: i64 =
            db.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM event_log", [], |r| r.get(0))?)).unwrap();
        assert_eq!(before, after, "nothing was appended");
        drop(db);

        let err = Db::open(&path, &parts).err().expect("open must refuse").to_string();
        assert!(err.contains("hash_v 2") && err.contains("only hash_v 1"), "{err}");

        // A ledger whose rows are all hash_v 1 opens and appends as before.
        let fresh = dir.path().join("fresh.db");
        let db = Db::open(&fresh, &parts).unwrap();
        db.write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({})))).unwrap();
        drop(db);
        assert!(Db::open(&fresh, &parts).is_ok());
    }

    /// `append` writes the event's organization and hash form explicitly
    /// when the ledger has the columns, and on a ledger from before them
    /// refuses an organization it cannot record instead of dropping it.
    #[test]
    fn append_records_the_organization_or_refuses_what_it_cannot_record() {
        let parts = [
            crate::Part::from(SCHEMA),
            crate::Part::from(META_SCHEMA),
            crate::Part::from(crate::org::STORE_PART),
        ];
        let db = Db::open_in_memory(&parts).unwrap();
        db.write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({})))).unwrap();
        let row: (String, i64) = db
            .read(|c| {
                Ok(c.query_row("SELECT org_id, hash_v FROM event_log", [], |r| Ok((r.get(0)?, r.get(1)?)))?)
            })
            .unwrap();
        assert_eq!(row, (ua_core::DEFAULT_ORG.to_string(), HASH_V));
        let err = db
            .write(|tx| {
                append(
                    tx,
                    EventInput {
                        org_id: " ".into(),
                        ..EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({}))
                    },
                )
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("org_id must not be empty"), "{err}");
        // An organization `orgs` does not hold is refused, and nothing is written.
        let err = db
            .write(|tx| {
                append(
                    tx,
                    EventInput {
                        org_id: "nope".into(),
                        ..EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({}))
                    },
                )
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown organization \"nope\""), "{err}");
        let n: i64 =
            db.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM event_log", [], |r| r.get(0))?)).unwrap();
        assert_eq!(n, 1);

        let legacy = Db::open_in_memory(&[SCHEMA]).unwrap();
        legacy
            .write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({}))))
            .unwrap();
        let err = legacy
            .write(|tx| {
                append(
                    tx,
                    EventInput {
                        org_id: "org-b".into(),
                        ..EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({}))
                    },
                )
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("no org_id column") && err.contains("org-b"), "{err}");
        assert!(legacy.read(verify).unwrap().ok);
    }

    /// Insert a row with no hashes, as a legacy import or a direct write would.
    fn insert_unhashed(db: &Db, ulid: &str) {
        db.write(|tx| {
            tx.execute(
                "INSERT INTO event_log (ulid, channel, payload, created_at) \
                 VALUES (?1, 'legacy.event', '{}', '2026-01-01T00:00:00+00:00')",
                [ulid],
            )?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn an_unhashed_row_after_the_chain_started_fails_verification() {
        let db = Db::open_in_memory(&[SCHEMA]).unwrap();
        for i in 0..2 {
            db.write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({ "i": i }))))
                .unwrap();
        }
        insert_unhashed(&db, "01J0000000000000000000ZZZZ");
        db.write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({ "i": 2 }))))
            .unwrap();
        let report = db.read(verify).unwrap();
        assert!(!report.ok, "{report:?}");
        assert_eq!(report.first_bad_seq, Some(3));
        assert_eq!(report.reason.as_deref(), Some("unhashed row after the hash chain started"));
    }

    #[test]
    fn a_contiguous_legacy_prefix_verifies_and_is_reported() {
        let db = Db::open_in_memory(&[SCHEMA, META_SCHEMA]).unwrap();
        insert_unhashed(&db, "01J0000000000000000000000A");
        insert_unhashed(&db, "01J0000000000000000000000B");
        // Without the import's record, the prefix is unexplained.
        let report = db.read(verify).unwrap();
        assert!(!report.ok && report.first_bad_seq == Some(1), "{report:?}");
        db.write(|tx| record_legacy_prefix(tx, 2)).unwrap();
        for i in 0..3 {
            db.write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({ "i": i }))))
                .unwrap();
        }
        let report = db.read(verify).unwrap();
        assert!(report.ok, "{report:?}");
        assert_eq!(report.checked, 3);
        assert_eq!(report.unhashed_legacy_prefix, 2);

        // Only unhashed rows: nothing is verified, and the prefix is named.
        let legacy = Db::open_in_memory(&[SCHEMA, META_SCHEMA]).unwrap();
        insert_unhashed(&legacy, "01J0000000000000000000000A");
        legacy.write(|tx| record_legacy_prefix(tx, 1)).unwrap();
        let report = legacy.read(verify).unwrap();
        assert!(report.ok && report.checked == 0 && report.unhashed_legacy_prefix == 1, "{report:?}");
    }

    #[test]
    fn an_unhashed_row_slipped_ahead_of_the_chain_fails_verification() {
        let db = Db::open_in_memory(&[SCHEMA, META_SCHEMA]).unwrap();
        for i in 0..3 {
            db.write(|tx| append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({ "i": i }))))
                .unwrap();
        }
        assert!(db.read(verify).unwrap().ok);
        for seq in [0i64, -5] {
            db.write(|tx| {
                tx.execute(
                    "INSERT INTO event_log (seq, ulid, channel, payload, created_at) \
                     VALUES (?1, ?2, 'forged.event', '{}', '2026-01-01T00:00:00+00:00')",
                    params![seq, format!("01J00000000000000000000F{}", seq.abs())],
                )?;
                Ok(())
            })
            .unwrap();
        }
        let report = db.read(verify).unwrap();
        assert!(!report.ok, "{report:?}");
        assert_eq!(report.unhashed_legacy_prefix, 2);
        assert_eq!(report.first_bad_seq, Some(-5));
        assert!(report.reason.unwrap().contains("recorded a legacy prefix of 0"));
    }
}
