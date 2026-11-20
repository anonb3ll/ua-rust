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

use std::fmt::Write as _;

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};

use crate::db::WriteTx;
use crate::schema::SchemaPart;

pub const GENESIS_HASH: &str = "GENESIS";

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

/// A new event.
#[derive(Debug, Clone, Default)]
pub struct EventInput {
    pub channel: String,
    pub payload: Value,
    pub originator: Option<String>,
    pub episode_id: Option<String>,
    pub causal_parent_id: Option<String>,
    /// When set, a second append with the same key is a no-op.
    pub dedupe_key: Option<String>,
}

impl EventInput {
    pub fn new(channel: impl Into<String>, payload: Value) -> Self {
        Self { channel: channel.into(), payload, ..Self::default() }
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
fn py_json_str(out: &mut String, s: &str) {
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
    // With a cursor, page forward: the oldest `limit` rows after it, so a
    // poller never skips rows. Without one, the newest `limit` rows. Both are
    // returned oldest first.
    let sql = if q.after_seq.is_some() {
        format!("{sql} ORDER BY seq ASC LIMIT {limit}")
    } else {
        format!("SELECT * FROM ({sql} ORDER BY seq DESC LIMIT {limit}) ORDER BY seq ASC")
    };
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter().map(|b| b.as_ref())), from_row)?;
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
/// verifies the same way) and are counted in `unhashed_legacy_prefix`. An
/// unhashed row after the chain has started fails verification: nothing the
/// hub appends lacks a hash, so such a row was written around the ledger.
pub fn verify(conn: &Connection) -> UaResult<VerifyReport> {
    let mut stmt = conn.prepare(
        "SELECT seq, ulid, channel, payload, originator, episode_id, causal_parent_id, created_at, dedupe_key, \
         prev_hash, entry_hash FROM event_log ORDER BY seq ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut expected_prev = GENESIS_HASH.to_string();
    let mut report =
        VerifyReport { ok: true, checked: 0, unhashed_legacy_prefix: 0, first_bad_seq: None, reason: None };
    while let Some(r) = rows.next()? {
        let seq: i64 = r.get(0)?;
        let fail = |reason: &str| VerifyReport {
            ok: false,
            checked: report.checked,
            unhashed_legacy_prefix: report.unhashed_legacy_prefix,
            first_bad_seq: Some(seq),
            reason: Some(reason.to_string()),
        };
        let entry: Option<String> = r.get(10)?;
        let Some(entry) = entry else {
            if report.checked > 0 {
                return Ok(fail("unhashed row after the hash chain started"));
            }
            report.unhashed_legacy_prefix += 1;
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

    #[test]
    fn a_cursor_pages_forward_without_skipping() {
        let db = Db::open_in_memory(&[SCHEMA]).unwrap();
        for i in 0..10 {
            db.write(|tx| append(tx, EventInput::new("test.event", json!({ "i": i })))).unwrap();
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
            db.write(|tx| append(tx, EventInput::new("test.event", json!({ "i": i })).by("tester"))).unwrap();
        }
        assert_eq!(rx.try_recv().unwrap().payload, json!({ "i": 0 }));
        let deduped = db
            .write(|tx| {
                append(tx, EventInput::new("test.once", json!({})).dedupe("k1"))?;
                append(tx, EventInput::new("test.once", json!({})).dedupe("k1"))
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
            db.write(|tx| append(tx, EventInput::new("test.event", json!({ "i": i })))).unwrap();
        }
        insert_unhashed(&db, "01J0000000000000000000ZZZZ");
        db.write(|tx| append(tx, EventInput::new("test.event", json!({ "i": 2 })))).unwrap();
        let report = db.read(verify).unwrap();
        assert!(!report.ok, "{report:?}");
        assert_eq!(report.first_bad_seq, Some(3));
        assert_eq!(report.reason.as_deref(), Some("unhashed row after the hash chain started"));
    }

    #[test]
    fn a_contiguous_legacy_prefix_verifies_and_is_reported() {
        let db = Db::open_in_memory(&[SCHEMA]).unwrap();
        insert_unhashed(&db, "01J0000000000000000000000A");
        insert_unhashed(&db, "01J0000000000000000000000B");
        for i in 0..3 {
            db.write(|tx| append(tx, EventInput::new("test.event", json!({ "i": i })))).unwrap();
        }
        let report = db.read(verify).unwrap();
        assert!(report.ok, "{report:?}");
        assert_eq!(report.checked, 3);
        assert_eq!(report.unhashed_legacy_prefix, 2);

        // Only unhashed rows: nothing is verified, and the prefix is named.
        let legacy = Db::open_in_memory(&[SCHEMA]).unwrap();
        insert_unhashed(&legacy, "01J0000000000000000000000A");
        let report = legacy.read(verify).unwrap();
        assert!(report.ok && report.checked == 0 && report.unhashed_legacy_prefix == 1, "{report:?}");
    }
}
