//! Idle-session wakes: the hub half of waking an agent session that sits at
//! its prompt while trigger mail waits for it.
//!
//! Three locks, all required, as in the original hub:
//!
//! 1. **The request.** The session's own agent opts in
//!    (`coordination_manage` `session_wake_opt_in`). A request never enables
//!    a wake by itself; withdrawing it clears outstanding offers.
//! 2. **The grant.** Only a verified human sets it (`session_wake_grant`).
//!    A grant is bound to one hub session id; a new session needs a new one.
//! 3. **No decline.** Any verified human, a lifecycle operator or the
//!    session's own agent may decline (`session_wake_decline`); a decline
//!    only restricts. It revokes any grant and is kept until a later grant:
//!    asking again does not clear it.
//!
//! Delivery uses the node's own outbound channel. A session wakes only
//! through its *wake node* ([`wake_node`]): a node its own agent owns. The
//! session may name that node when it asks (`node`); then only that node is
//! used. Otherwise it is the agent's one live node whose name matches the
//! session's `host` by short lowercase name, or, when several do, the one
//! whose full name is the host; still ambiguous, the session is not woken.
//! Another agent's node never sees the session, and two machines that share
//! a short name never receive each other's wakes. The wake node long-polls
//! `node_wake` (`POST /api/node/wake`, `offer_version` 3; at most
//! [`MAX_POLLS_PER_NODE`] polls open per node).
//! The hub applies every gate centrally and answers ids and counts only:
//! `{session_id, external_session_id, unread, newest_seq, expires_at,
//! offer_id}`. The node types the fixed [`WAKE_TEXT`] line itself, reserves
//! the attempt first with `node_wake_check` (`/api/node/wake/check`), and
//! reports `delivered`, `failed` or `skipped` with `node_wake_receipt`
//! (`/api/node/wake/receipt`). A receipt is idempotent: a resend, or one for
//! an offer that lapsed, answers `duplicate: true`. A check or receipt from
//! any node but the session's wake node is refused (`not_found`).
//!
//! Gates, in order: an offer still outstanding (120 s); the retry hold after
//! a failed or skipped offer (30 s); the breaker ([`BREAKER_AFTER`] wakes or
//! attempts with no inbox read in between pause the session until it reads
//! mail); the floor between wakes (600 s); the hourly caps (6 wakes, 6
//! attempts); trigger mail (unread `request`, `query` or `handoff`, or
//! `expects_reply`, newer than the last woken set); and the debounce (20 s
//! quiet, at most 60 s held). Skips in [`FINAL_SKIPS`] and the 20th retry
//! give the mail set up to the session's own hooks.
//!
//! This module reads mailbox metadata only (`message_index`,
//! `message_reads`), never message bodies, so no message text reaches a wake.
//! Every change is ledgered on `agent.wake*` in the same transaction.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, Row, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{Caller, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use super::agents::verified;
use super::{governance, node_queue, nodes};
use crate::registry::{Registry, ToolCtx, tool};
use ua_org::authz::{Authority, Authz};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "wake.v1",
    sql: "
CREATE TABLE IF NOT EXISTS session_wake (
    session_id TEXT PRIMARY KEY,
    opted_in INTEGER NOT NULL DEFAULT 0,
    requested_at TEXT,
    granted_at TEXT,
    granted_by TEXT,
    declined_at TEXT,
    declined_by TEXT,
    decline_reason TEXT,
    offered_at REAL,
    offered_seq INTEGER,
    offered_id TEXT,
    retry_at REAL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_wake_at REAL,
    last_wake_seq INTEGER NOT NULL DEFAULT 0,
    hour_started_at REAL,
    wakes_last_hour INTEGER NOT NULL DEFAULT 0,
    unacked_wakes INTEGER NOT NULL DEFAULT 0,
    last_attempt_at REAL,
    attempt_hour_started_at REAL,
    attempts_last_hour INTEGER NOT NULL DEFAULT 0,
    unacked_attempts INTEGER NOT NULL DEFAULT 0,
    paused_reason TEXT,
    last_outcome TEXT,
    last_reason TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_wake_armed ON session_wake(opted_in)
    WHERE granted_at IS NOT NULL AND declined_at IS NULL;

-- One row per offered generation. The random offer id makes a delayed old
-- offer for the same mail set invalid once it is re-offered.
CREATE TABLE IF NOT EXISTS session_wake_offers (
    offer_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    node TEXT NOT NULL,
    offered_seq INTEGER NOT NULL,
    offered_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    attempted_at REAL,
    invalidated_at REAL,
    recorded_at REAL,
    outcome TEXT,
    delivered_at REAL,
    reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_session_wake_offers_session ON session_wake_offers(session_id, offered_at);
",
};

/// The node a session named when it asked for wakes: once set, the only node
/// its wakes go through.
pub const SCHEMA_V2: SchemaPart = SchemaPart {
    name: "wake.v2",
    sql: "
ALTER TABLE session_wake ADD COLUMN node TEXT;
",
};

/// Acts that ring the doorbell. `inform` and `done` wait for the session's
/// hooks, unless the sender set `expects_reply`.
pub const WAKE_ACTS: [&str; 3] = ["handoff", "query", "request"];
/// The only text a node ever types: one constant and one integer.
pub const WAKE_TEXT: &str = "You have {n} new hub messages; run message_inbox";

pub const DEBOUNCE_QUIET_S: f64 = 20.0;
pub const DEBOUNCE_MAX_HOLD_S: f64 = 60.0;
pub const FLOOR_S: f64 = 600.0;
pub const HOURLY_CAP: i64 = 6;
pub const BREAKER_AFTER: i64 = 3;
/// An offer with no receipt blocks a re-offer this long, then lapses.
pub const OFFER_LEASE_S: f64 = 120.0;
/// Slack between the node's `delivered_at` clock and the hub's.
pub const RECEIPT_CLOCK_SKEW_S: f64 = 5.0;
/// After a failed or skipped offer, offer again this much later.
pub const RETRY_S: f64 = 30.0;
/// Retries per mail set before it is left to the session's hooks.
pub const MAX_ATTEMPTS: i64 = 20;
/// Skips that give the mail set up without repeating an absent or
/// uncertain prompt.
pub const FINAL_SKIPS: [&str; 5] =
    ["no_match", "herdr_missing", "input_state_unavailable", "already_delivered", "delivery_uncertain"];
pub const OUTCOMES: [&str; 3] = ["delivered", "failed", "skipped"];

pub const CHANNEL_WAKE: &str = "agent.wake";
pub const CHANNEL_GRANT: &str = "agent.wake.grant";
pub const CHANNEL_REQUEST: &str = "agent.wake.request";
pub const CHANNEL_ATTEMPT: &str = "agent.wake.attempt";
pub const CHANNEL_REVIVED: &str = "agent.wake.session_revived";

/// Hub features advertised at node registration.
pub const FEATURE: &str = "node_wake_v3";
pub const LIVE_SESSIONS_FEATURE: &str = "node_wake_live_sessions";

const PAUSED_NO_READ: &str = "no_inbox_read";
/// Panes one node may report on a wake poll, and the length of one id.
pub const MAX_LIVE_SESSIONS: usize = 64;
pub const MAX_EXTERNAL_ID_CHARS: usize = 512;
/// The only way a pane report reopens a session: the reaper closed it.
const REAPED_EXIT: &str = "no_heartbeat";
const OPEN: &str = "'starting','running','waiting'";
const MAX_DECLINE_REASON: usize = 500;
/// How long a node may hold a wake poll open, and how often it is re-checked.
pub const WAKE_MAX_WAIT_S: f64 = 30.0;
const WAKE_POLL: Duration = Duration::from_secs(1);
/// Offers handed out by one poll.
const MAX_OFFERS: usize = 50;
/// Wake long-polls one node may hold open at once.
pub const MAX_POLLS_PER_NODE: usize = 2;
/// Upper bound of a unix timestamp the hub accepts (year 9999).
const MAX_UNIX: f64 = 253_402_300_800.0;

/// The wake line for `n` unread messages.
pub fn wake_text(n: i64) -> String {
    WAKE_TEXT.replace("{n}", &n.to_string())
}

/// Hosts compare by short lowercase name: `Box.local` and `box` are one host.
pub fn host_key(host: &str) -> String {
    host.trim().to_ascii_lowercase().split('.').next().unwrap_or("").to_string()
}

fn now_f() -> f64 {
    ua_core::time::now_ms() as f64 / 1000.0
}

fn iso(t: f64) -> String {
    let ts = Timestamp::from_millisecond((t * 1000.0) as i64).unwrap_or_else(|_| Timestamp::now());
    ua_core::time::format_ts(ts)
}

fn ts_f(s: Option<&str>) -> Option<f64> {
    s.and_then(ua_core::time::parse_ts).map(|t| t.as_millisecond() as f64 / 1000.0)
}

fn record(tx: &mut WriteTx<'_>, channel: &str, kind: &str, mut payload: Value, by: &str) -> UaResult<()> {
    payload["kind"] = json!(kind);
    ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, channel, payload).by(by.to_string()))?;
    Ok(())
}

// --- rows -----------------------------------------------------------------------

/// A `session_wake` row joined with its session.
#[derive(Debug, Clone)]
struct WakeRow {
    session_id: String,
    agent: String,
    external_session_id: Option<String>,
    host: Option<String>,
    status: String,
    opted_in: bool,
    granted: bool,
    declined: bool,
    offered_at: Option<f64>,
    offered_seq: Option<i64>,
    offered_id: Option<String>,
    retry_at: Option<f64>,
    attempts: i64,
    last_wake_at: Option<f64>,
    last_wake_seq: i64,
    hour_started_at: Option<f64>,
    wakes_last_hour: i64,
    unacked_wakes: i64,
    last_attempt_at: Option<f64>,
    attempt_hour_started_at: Option<f64>,
    attempts_last_hour: i64,
    unacked_attempts: i64,
    paused_reason: Option<String>,
    /// The node the session named when it asked, if any.
    node: Option<String>,
}

const ROW_COLS: &str = "w.session_id, s.agent, s.external_session_id, s.host, s.status, w.opted_in, \
    w.granted_at IS NOT NULL, w.declined_at IS NOT NULL, w.offered_at, w.offered_seq, w.offered_id, w.retry_at, \
    w.attempts, w.last_wake_at, w.last_wake_seq, w.hour_started_at, w.wakes_last_hour, w.unacked_wakes, \
    w.last_attempt_at, w.attempt_hour_started_at, w.attempts_last_hour, w.unacked_attempts, w.paused_reason, w.node";

fn wake_row(r: &Row<'_>) -> rusqlite::Result<WakeRow> {
    Ok(WakeRow {
        session_id: r.get(0)?,
        agent: r.get(1)?,
        external_session_id: r.get(2)?,
        host: r.get(3)?,
        status: r.get(4)?,
        opted_in: r.get::<_, i64>(5)? != 0,
        granted: r.get::<_, bool>(6)?,
        declined: r.get::<_, bool>(7)?,
        offered_at: r.get(8)?,
        offered_seq: r.get(9)?,
        offered_id: r.get(10)?,
        retry_at: r.get(11)?,
        attempts: r.get(12)?,
        last_wake_at: r.get(13)?,
        last_wake_seq: r.get(14)?,
        hour_started_at: r.get(15)?,
        wakes_last_hour: r.get(16)?,
        unacked_wakes: r.get(17)?,
        last_attempt_at: r.get(18)?,
        attempt_hour_started_at: r.get(19)?,
        attempts_last_hour: r.get(20)?,
        unacked_attempts: r.get(21)?,
        paused_reason: r.get(22)?,
        node: r.get(23)?,
    })
}

fn load_row(c: &Connection, session_id: &str) -> UaResult<Option<WakeRow>> {
    Ok(c.query_row(
        &format!(
            "SELECT {ROW_COLS} FROM session_wake w JOIN agent_sessions s ON s.id = w.session_id \
             WHERE w.session_id = ?1"
        ),
        [session_id],
        wake_row,
    )
    .optional()?)
}

impl WakeRow {
    fn open(&self) -> bool {
        matches!(self.status.as_str(), "starting" | "running" | "waiting")
    }
}

/// The one node a session's wakes go through, or `None`. Only a live node
/// the session's own agent owns qualifies: the node the session named when it
/// asked, else the agent's one node whose short name is the session host's,
/// else, among several such, the one whose full name is the host
/// (case-insensitively). Anything still ambiguous wakes nothing, so two
/// machines sharing a short name never receive each other's wakes.
fn wake_node(c: &Connection, row: &WakeRow) -> UaResult<Option<String>> {
    if let Some(named) = &row.node {
        let owned = c
            .query_row(
                "SELECT 1 FROM nodes WHERE node = ?1 AND agent = ?2 AND retired_at IS NULL",
                params![named, row.agent],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        return Ok(owned.then(|| named.clone()));
    }
    let Some(host) = row.host.as_deref().map(str::trim).filter(|h| !h.is_empty()) else { return Ok(None) };
    let key = host_key(host);
    if key.is_empty() {
        return Ok(None);
    }
    let mut stmt =
        c.prepare("SELECT node FROM nodes WHERE agent = ?1 AND retired_at IS NULL ORDER BY node")?;
    let same_short: Vec<String> = stmt
        .query_map([&row.agent], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|n| host_key(n) == key)
        .collect();
    if same_short.len() <= 1 {
        return Ok(same_short.into_iter().next());
    }
    let mut exact = same_short.into_iter().filter(|n| n.eq_ignore_ascii_case(host));
    match (exact.next(), exact.next()) {
        (Some(n), None) => Ok(Some(n)),
        _ => Ok(None),
    }
}

/// Whether `node` is `row`'s wake node.
fn wakes_through(c: &Connection, row: &WakeRow, node: &str) -> UaResult<bool> {
    Ok(wake_node(c, row)?.as_deref() == Some(node))
}

/// The session's agent, or not found.
fn session_agent(c: &Connection, session_id: &str) -> UaResult<(String, String)> {
    c.query_row("SELECT agent, status FROM agent_sessions WHERE id = ?1", [session_id], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })
    .optional()?
    .ok_or_else(|| UaError::not_found(format!("session {session_id:?} does not exist")))
}

fn check_session_id(raw: &str) -> UaResult<String> {
    let id = raw.trim();
    if id.is_empty() || id.len() > 200 {
        return Err(UaError::invalid("session_id must be 1-200 characters"));
    }
    Ok(id.to_string())
}

/// Clear any outstanding offer of `session_id` (consent changed).
fn invalidate_offers(tx: &WriteTx<'_>, session_id: &str, now: f64) -> UaResult<()> {
    tx.execute(
        "UPDATE session_wake_offers SET invalidated_at = ?2 WHERE session_id = ?1 \
         AND recorded_at IS NULL AND invalidated_at IS NULL",
        params![session_id, now],
    )?;
    Ok(())
}

// --- mailbox reads ----------------------------------------------------------------
//
// A wake is for an agent session, and every session is the default
// organization's until agents carry one, so these reads count only the
// default organization's mail (`i.org_id = ?`, bound to `DEFAULT_ORG`).

/// Did the session (or its label) read any of its mail after `since`?
fn read_since(c: &Connection, agent: &str, session_id: &str, since: f64) -> UaResult<bool> {
    let row: Option<i64> = c
        .query_row(
            "SELECT 1 FROM message_index i \
             LEFT JOIN message_reads r ON r.message_id = i.message_id AND r.session_id = ?1 \
             WHERE i.org_id = ?4 AND i.recipient = ?2 AND (i.target_session IS NULL OR i.target_session = ?1) \
             AND COALESCE(i.read_at, r.read_at) > ?3 LIMIT 1",
            params![session_id, agent, iso(since), ua_core::DEFAULT_ORG],
            |r| r.get(0),
        )
        .optional()?;
    Ok(row.is_some())
}

/// Unread trigger mail with `after < seq <= through`.
struct Trigger {
    n: i64,
    newest: Option<i64>,
    oldest_at: Option<f64>,
    newest_at: Option<f64>,
}

fn trigger(c: &Connection, agent: &str, session_id: &str, after: i64, through: i64) -> UaResult<Trigger> {
    let acts = WAKE_ACTS.iter().map(|a| format!("'{a}'")).collect::<Vec<_>>().join(",");
    Ok(c.query_row(
        &format!(
            "SELECT COUNT(*), MAX(i.event_seq), MIN(i.created_at), MAX(i.created_at) FROM message_index i \
             LEFT JOIN message_reads r ON r.message_id = i.message_id AND r.session_id = ?1 \
             WHERE i.org_id = ?5 AND i.recipient = ?2 AND i.read_at IS NULL AND r.read_at IS NULL \
             AND (i.target_session IS NULL OR i.target_session = ?1) \
             AND (i.act IN ({acts}) OR i.expects_reply = 1) AND i.event_seq > ?3 AND i.event_seq <= ?4"
        ),
        params![session_id, agent, after, through, ua_core::DEFAULT_ORG],
        |r| {
            Ok(Trigger {
                n: r.get(0)?,
                newest: r.get(1)?,
                oldest_at: ts_f(r.get::<_, Option<String>>(2)?.as_deref()),
                newest_at: ts_f(r.get::<_, Option<String>>(3)?.as_deref()),
            })
        },
    )?)
}

/// Every unread message of the session: label mail plus mail to it.
fn unread(c: &Connection, agent: &str, session_id: &str) -> UaResult<i64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM message_index i \
         LEFT JOIN message_reads r ON r.message_id = i.message_id AND r.session_id = ?1 \
         WHERE i.org_id = ?3 AND i.recipient = ?2 AND i.read_at IS NULL AND r.read_at IS NULL \
         AND (i.target_session IS NULL OR i.target_session = ?1)",
        params![session_id, agent, ua_core::DEFAULT_ORG],
        |r| r.get(0),
    )?)
}

// --- gates ----------------------------------------------------------------------

/// The breaker, floor and hourly caps, read-only. Known delivery and the
/// conservative one-shot attempt budget are counted separately. A read since
/// the last wake or attempt resets the breaker: the second value says that
/// reset is due (a write, applied by [`budget_hold`]).
fn budget(c: &Connection, row: &WakeRow, now: f64) -> UaResult<(Option<&'static str>, bool)> {
    let last = match (row.last_wake_at, row.last_attempt_at) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let mut unacked = row.unacked_wakes.max(row.unacked_attempts);
    let read_after = row.last_attempt_at.or(row.last_wake_at);
    let mut reset = false;
    if unacked > 0
        && let Some(since) = read_after
        && read_since(c, &row.agent, &row.session_id, since)?
    {
        unacked = 0;
        reset = true;
    }
    if unacked >= BREAKER_AFTER {
        return Ok((Some("breaker"), reset));
    }
    if last.is_some_and(|l| now - l < FLOOR_S) {
        return Ok((Some("floor"), reset));
    }
    for (start, count) in
        [(row.hour_started_at, row.wakes_last_hour), (row.attempt_hour_started_at, row.attempts_last_hour)]
    {
        if start.is_some_and(|s| now - s < 3600.0) && count >= HOURLY_CAP {
            return Ok((Some("hourly_cap"), reset));
        }
    }
    Ok((None, reset))
}

/// [`budget`], applying a due breaker reset.
fn budget_hold(tx: &WriteTx<'_>, row: &WakeRow, now: f64) -> UaResult<Option<&'static str>> {
    let (hold, reset) = budget(tx, row, now)?;
    if reset {
        reset_breaker(tx, &row.session_id)?;
    }
    Ok(hold)
}

fn reset_breaker(tx: &WriteTx<'_>, session_id: &str) -> UaResult<()> {
    tx.execute(
        "UPDATE session_wake SET unacked_wakes = 0, unacked_attempts = 0, paused_reason = NULL \
         WHERE session_id = ?1",
        [session_id],
    )?;
    Ok(())
}

enum Verdict {
    Due { unread: i64, newest_seq: i64 },
    Hold(&'static str),
}

/// Every gate, read-only. The flag says a breaker reset is due.
fn evaluate(c: &Connection, row: &WakeRow, now: f64) -> UaResult<(Verdict, bool)> {
    if row.offered_at.is_some_and(|o| now - o < OFFER_LEASE_S) {
        return Ok((Verdict::Hold("offer_outstanding"), false));
    }
    if row.retry_at.is_some_and(|r| now < r) {
        return Ok((Verdict::Hold("retry_wait"), false));
    }
    if governance::stopped(c, &row.agent)?.is_some() {
        return Ok((Verdict::Hold("agent_stopped"), false));
    }
    let (hold, reset) = budget(c, row, now)?;
    if let Some(hold) = hold {
        return Ok((Verdict::Hold(hold), reset));
    }
    let mail = trigger(c, &row.agent, &row.session_id, row.last_wake_seq, i64::MAX)?;
    let Some(newest) = mail.newest.filter(|_| mail.n > 0) else {
        return Ok((Verdict::Hold("nothing_to_wake"), reset));
    };
    let quiet = mail.newest_at.map_or(0.0, |t| now - t);
    let held = mail.oldest_at.map_or(0.0, |t| now - t);
    if quiet < DEBOUNCE_QUIET_S && held < DEBOUNCE_MAX_HOLD_S {
        return Ok((Verdict::Hold("debounce"), reset));
    }
    let unread = unread(c, &row.agent, &row.session_id)?;
    if unread <= 0 {
        return Ok((Verdict::Hold("nothing_to_wake"), reset));
    }
    Ok((Verdict::Due { unread, newest_seq: newest }, reset))
}

fn gate(tx: &mut WriteTx<'_>, row: &WakeRow, now: f64) -> UaResult<Verdict> {
    let (verdict, reset) = evaluate(tx, row, now)?;
    if reset {
        reset_breaker(tx, &row.session_id)?;
    }
    Ok(verdict)
}

/// Granted, opted-in, undeclined open sessions with a native id whose wake
/// node is `node`, which `agent` owns: only the agent's own sessions.
fn candidates(c: &Connection, node: &str, agent: &str) -> UaResult<Vec<WakeRow>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {ROW_COLS} FROM session_wake w JOIN agent_sessions s ON s.id = w.session_id \
         WHERE w.opted_in = 1 AND w.granted_at IS NOT NULL AND w.declined_at IS NULL \
         AND s.status IN ({OPEN}) AND s.external_session_id IS NOT NULL AND s.agent = ?1 \
         ORDER BY w.session_id"
    ))?;
    let rows = stmt.query_map([agent], wake_row)?.collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        if wakes_through(c, &r, node)? {
            out.push(r);
        }
    }
    Ok(out)
}

/// Whether a poll of `node` has anything to write now: an offer due, a
/// breaker reset or a pause to record. Read-only, so an idle long-poll never
/// takes the write lock.
fn poll_pending(c: &Connection, node: &str, agent: &str, now: f64) -> UaResult<bool> {
    for row in candidates(c, node, agent)? {
        let (verdict, reset) = evaluate(c, &row, now)?;
        let pause = matches!(verdict, Verdict::Hold("breaker"))
            && row.paused_reason.as_deref() != Some(PAUSED_NO_READ);
        if reset || pause || matches!(verdict, Verdict::Due { .. }) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Sessions whose wake node is `node` that are due a wake now, marked
/// offered.
fn due_wakes(tx: &mut WriteTx<'_>, node: &str, identity: &str, now: f64) -> UaResult<Vec<Value>> {
    let name = node_queue::owned_node(tx, node, identity)?.node;
    let mut out = Vec::new();
    for row in candidates(tx, &name, identity)? {
        if out.len() >= MAX_OFFERS {
            break;
        }
        match gate(tx, &row, now)? {
            Verdict::Hold(why) => {
                if why == "breaker" && row.paused_reason.as_deref() != Some(PAUSED_NO_READ) {
                    tx.execute(
                        "UPDATE session_wake SET paused_reason = ?2 WHERE session_id = ?1",
                        params![row.session_id, PAUSED_NO_READ],
                    )?;
                }
            }
            Verdict::Due { unread, newest_seq } => {
                let offer_id = uuid::Uuid::new_v4().simple().to_string();
                let expires_at = now + OFFER_LEASE_S;
                tx.execute(
                    "INSERT INTO session_wake_offers (offer_id, session_id, node, offered_seq, offered_at, expires_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![offer_id, row.session_id, name, newest_seq, now, expires_at],
                )?;
                tx.execute(
                    "UPDATE session_wake SET offered_at = ?2, offered_seq = ?3, offered_id = ?4, updated_at = ?5 \
                     WHERE session_id = ?1",
                    params![row.session_id, now, newest_seq, offer_id, ua_core::time::now()],
                )?;
                record(
                    tx,
                    CHANNEL_WAKE,
                    "offered",
                    json!({ "session_id": row.session_id, "node": name, "seq": newest_seq, "offer_id": offer_id }),
                    identity,
                )?;
                out.push(json!({
                    "session_id": row.session_id,
                    "external_session_id": row.external_session_id,
                    "unread": unread,
                    "newest_seq": newest_seq,
                    "expires_at": expires_at,
                    "offer_id": offer_id,
                }));
            }
        }
    }
    Ok(out)
}

/// Seconds left on the live offer `(seq, offer_id, expires_at)`, else 0.
fn live_offer(row: &WakeRow, seq: i64, now: f64, expires_at: f64, offer_id: &str) -> f64 {
    let Some(offered) = row.offered_at else { return 0.0 };
    if row.offered_seq != Some(seq)
        || row.offered_id.as_deref() != Some(offer_id)
        || seq <= row.last_wake_seq
        || !row.opted_in
        || !row.granted
        || row.declined
        || !row.open()
    {
        return 0.0;
    }
    let deadline = offered + OFFER_LEASE_S;
    if expires_at != deadline {
        return 0.0;
    }
    (deadline - now).max(0.0)
}

/// One server-time reservation per offered generation, before any typing.
fn reserve_attempt(
    tx: &mut WriteTx<'_>,
    row: &WakeRow,
    offer_id: &str,
    now: f64,
    identity: &str,
) -> UaResult<bool> {
    let changed = tx.execute(
        "UPDATE session_wake_offers SET attempted_at = ?2 WHERE offer_id = ?1 AND attempted_at IS NULL",
        params![offer_id, now],
    )?;
    if changed == 0 {
        return Ok(false);
    }
    let fresh_hour = row.attempt_hour_started_at.is_none_or(|h| now - h >= 3600.0);
    let unacked = row.unacked_attempts + 1;
    tx.execute(
        "UPDATE session_wake SET last_attempt_at = ?2, attempt_hour_started_at = ?3, attempts_last_hour = ?4, \
         unacked_attempts = ?5, paused_reason = ?6 WHERE session_id = ?1",
        params![
            row.session_id,
            now,
            if fresh_hour { Some(now) } else { row.attempt_hour_started_at },
            if fresh_hour { 1 } else { row.attempts_last_hour + 1 },
            unacked,
            if unacked >= BREAKER_AFTER { Some(PAUSED_NO_READ.to_string()) } else { row.paused_reason.clone() },
        ],
    )?;
    record(
        tx,
        CHANNEL_ATTEMPT,
        "reserved",
        json!({ "session_id": row.session_id, "offer_id": offer_id }),
        identity,
    )?;
    Ok(true)
}

fn check_seq(seq: i64) -> UaResult<i64> {
    if seq < 0 {
        return Err(UaError::invalid("seq must be the offer's newest_seq, a non-negative integer"));
    }
    Ok(seq)
}

fn check_stamp(v: f64, field: &str) -> UaResult<f64> {
    if !(v.is_finite() && v > 0.0 && v < MAX_UNIX) {
        return Err(UaError::invalid(format!("{field} must be a finite unix timestamp")));
    }
    Ok(v)
}

fn check_offer_id(id: &str) -> UaResult<String> {
    if id.len() != 32 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(UaError::invalid("offer_id must identify an offered generation (32 lowercase hex)"));
    }
    Ok(id.to_string())
}

/// The wake row of `session_id` when `node` (which `agent` owns) is its wake
/// node, else not found: no other node may check, report or see it.
fn node_row(c: &Connection, session_id: &str, node: &str, agent: &str) -> UaResult<WakeRow> {
    match load_row(c, session_id)? {
        Some(r) if r.agent == agent && wakes_through(c, &r, node)? => Ok(r),
        _ => {
            Err(UaError::not_found(format!("session {session_id:?} is not a wake session on node {node:?}")))
        }
    }
}

fn check_offer(tx: &mut WriteTx<'_>, node: &str, identity: &str, a: &CheckArgs, now: f64) -> UaResult<Value> {
    let name = node_queue::owned_node(tx, node, identity)?.node;
    let sid = check_session_id(&a.session_id)?;
    let seq = check_seq(a.seq)?;
    let expires_at = check_stamp(a.expires_at, "expires_at")?;
    let offer_id = check_offer_id(&a.offer_id)?;
    let row = node_row(tx, &sid, &name, identity)?;
    let mut remaining = live_offer(&row, seq, now, expires_at, &offer_id);
    if remaining > 0.0 {
        let attempted: Option<Option<f64>> = tx
            .query_row(
                "SELECT attempted_at FROM session_wake_offers WHERE offer_id = ?1 AND session_id = ?2 \
                 AND node = ?3",
                params![offer_id, sid, name],
                |r| r.get(0),
            )
            .optional()?;
        if !matches!(attempted, Some(None)) {
            remaining = 0.0;
        }
    }
    if remaining > 0.0 && trigger(tx, &row.agent, &sid, row.last_wake_seq, seq)?.n == 0 {
        remaining = 0.0;
    }
    if remaining > 0.0 && budget_hold(tx, &row, now)?.is_some() {
        remaining = 0.0;
    }
    if remaining > 0.0 {
        let fresh = node_row(tx, &sid, &name, identity)?;
        remaining = live_offer(&fresh, seq, now, expires_at, &offer_id);
        if remaining > 0.0 && !reserve_attempt(tx, &fresh, &offer_id, now, identity)? {
            remaining = 0.0;
        }
    }
    Ok(json!({ "session_id": sid, "valid": remaining > 0.0, "remaining_s": remaining }))
}

fn check_reason(reason: Option<&str>) -> UaResult<Option<String>> {
    match reason {
        None => Ok(None),
        Some(r)
            if (1..=64).contains(&r.len())
                && r.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b':' | b'.' | b'-')) =>
        {
            Ok(Some(r.to_string()))
        }
        Some(_) => Err(UaError::invalid("reason must be 1-64 chars of [a-z0-9_:.-]")),
    }
}

struct OfferRow {
    offered_seq: i64,
    expires_at: f64,
    attempted_at: Option<f64>,
    invalidated_at: Option<f64>,
    recorded_at: Option<f64>,
}

fn record_receipt(
    tx: &mut WriteTx<'_>,
    node: &str,
    identity: &str,
    a: &ReceiptArgs,
    now: f64,
) -> UaResult<Value> {
    let name = node_queue::owned_node(tx, node, identity)?.node;
    let outcome = a.outcome.trim().to_string();
    if !OUTCOMES.contains(&outcome.as_str()) {
        return Err(UaError::invalid(format!("outcome must be one of {}", OUTCOMES.join(", "))));
    }
    let reason = check_reason(a.reason.as_deref())?;
    let sid = check_session_id(&a.session_id)?;
    let seq = check_seq(a.seq)?;
    let expires_at = check_stamp(a.expires_at, "expires_at")?;
    let offer_id = check_offer_id(&a.offer_id)?;
    let delivered_at = match (outcome.as_str(), a.delivered_at) {
        ("delivered", Some(d)) => Some(check_stamp(d, "delivered_at")?),
        ("delivered", None) => {
            return Err(UaError::invalid("delivered_at must be the prompt completion timestamp"));
        }
        _ => None,
    };
    let row = node_row(tx, &sid, &name, identity)?;
    let offer: Option<OfferRow> = tx
        .query_row(
            "SELECT offered_seq, expires_at, attempted_at, invalidated_at, recorded_at FROM session_wake_offers \
             WHERE offer_id = ?1 AND session_id = ?2 AND node = ?3",
            params![offer_id, sid, name],
            |r| {
                Ok(OfferRow {
                    offered_seq: r.get(0)?,
                    expires_at: r.get(1)?,
                    attempted_at: r.get(2)?,
                    invalidated_at: r.get(3)?,
                    recorded_at: r.get(4)?,
                })
            },
        )
        .optional()?;
    let uncertain = reason.as_deref() == Some("delivery_uncertain");
    let valid = match &offer {
        Some(o) if o.recorded_at.is_none() && o.offered_seq == seq && o.expires_at == expires_at => {
            if let Some(d) = delivered_at {
                o.attempted_at.is_some_and(|t| t - RECEIPT_CLOCK_SKEW_S <= d)
                    && d < expires_at
                    && d <= now + RECEIPT_CLOCK_SKEW_S
                    && o.invalidated_at.is_none_or(|i| d < i)
            } else if uncertain {
                o.attempted_at.is_some()
            } else {
                live_offer(&row, seq, now, expires_at, &offer_id) > 0.0
            }
        }
        _ => false,
    };
    if !valid {
        return Ok(json!({ "session_id": sid, "recorded": false, "duplicate": true }));
    }
    // A delayed old result never moves the floor or the cursor backwards.
    let stamp = row.last_wake_at.map_or(now, |p| p.max(now));
    let same_generation = row.offered_id.as_deref() == Some(offer_id.as_str());
    let cursor = seq.max(row.last_wake_seq);
    let ts = ua_core::time::now();
    if outcome == "delivered" {
        let fresh_hour = row.hour_started_at.is_none_or(|h| now - h >= 3600.0);
        let unacked = row.unacked_wakes + 1;
        tx.execute(
            "UPDATE session_wake SET last_wake_at = ?2, last_wake_seq = ?3, hour_started_at = ?4, \
             wakes_last_hour = ?5, unacked_wakes = ?6, paused_reason = ?7, \
             offered_at = CASE WHEN ?8 THEN NULL ELSE offered_at END, \
             offered_seq = CASE WHEN ?8 THEN NULL ELSE offered_seq END, \
             offered_id = CASE WHEN ?8 THEN NULL ELSE offered_id END, \
             retry_at = NULL, attempts = 0, last_outcome = ?9, last_reason = ?10, updated_at = ?11 \
             WHERE session_id = ?1",
            params![
                sid,
                stamp,
                cursor,
                if fresh_hour { Some(stamp) } else { row.hour_started_at },
                if fresh_hour { 1 } else { row.wakes_last_hour + 1 },
                unacked,
                (unacked >= BREAKER_AFTER).then_some(PAUSED_NO_READ),
                same_generation,
                outcome,
                reason,
                ts,
            ],
        )?;
    } else if uncertain {
        // The check already spent the conservative attempt budget; delivery
        // counters stay truthful and a replacement offer is kept.
        tx.execute(
            "UPDATE session_wake SET last_wake_seq = ?2, \
             offered_at = CASE WHEN ?3 THEN NULL ELSE offered_at END, \
             offered_seq = CASE WHEN ?3 THEN NULL ELSE offered_seq END, \
             offered_id = CASE WHEN ?3 THEN NULL ELSE offered_id END, \
             last_outcome = ?4, last_reason = ?5, updated_at = ?6 WHERE session_id = ?1",
            params![sid, cursor, same_generation, outcome, reason, ts],
        )?;
    } else {
        let attempts = row.attempts + 1;
        let give_up = reason.as_deref().is_some_and(|r| FINAL_SKIPS.contains(&r)) || attempts >= MAX_ATTEMPTS;
        tx.execute(
            "UPDATE session_wake SET offered_at = NULL, offered_seq = NULL, offered_id = NULL, retry_at = ?2, \
             attempts = ?3, last_wake_seq = ?4, last_outcome = ?5, last_reason = ?6, updated_at = ?7 \
             WHERE session_id = ?1",
            params![
                sid,
                (!give_up).then_some(now + RETRY_S),
                if give_up { 0 } else { attempts },
                if give_up { cursor } else { row.last_wake_seq },
                outcome,
                reason,
                ts,
            ],
        )?;
    }
    tx.execute(
        "UPDATE session_wake_offers SET recorded_at = ?2, outcome = ?3, delivered_at = ?4, reason = ?5 \
         WHERE offer_id = ?1",
        params![offer_id, stamp, outcome, delivered_at, reason],
    )?;
    record(
        tx,
        CHANNEL_WAKE,
        &outcome,
        json!({ "session_id": sid, "node": name, "seq": seq, "offer_id": offer_id, "reason": reason }),
        identity,
    )?;
    Ok(json!({ "session_id": sid, "recorded": true, "duplicate": false, "outcome": outcome }))
}

/// Keep granted sessions open while the node still sees their panes: an idle
/// session at its prompt runs no hook, so nothing heartbeats it and the
/// reaper would close it. Only a session of the node's own agent that asked
/// for wakes, was granted them and wakes through this node is touched; one
/// the reaper closed comes back, one that ended any other way stays ended.
/// `(id, agent, status, exit_status, external_session_id)` of one session.
type LiveRow = (String, String, String, Option<String>, Option<String>);

fn note_live_sessions(tx: &mut WriteTx<'_>, node: &str, identity: &str, ids: &[String]) -> UaResult<Value> {
    let name = node_queue::owned_node(tx, node, identity)?.node;
    let rows: Vec<LiveRow> = {
        let mut stmt = tx.prepare(
            "SELECT s.id, s.agent, s.status, s.exit_status, s.external_session_id \
             FROM session_wake w JOIN agent_sessions s ON s.id = w.session_id \
             WHERE w.opted_in = 1 AND w.granted_at IS NOT NULL AND w.declined_at IS NULL \
             AND s.external_session_id IS NOT NULL AND s.agent = ?1",
        )?;
        stmt.query_map([identity], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<Result<_, _>>()?
    };
    let ts = ua_core::time::now();
    let (mut kept, mut revived) = (0, 0);
    for (id, agent, status, exit, ext) in rows {
        if !ext.as_ref().is_some_and(|e| ids.contains(e)) {
            continue;
        }
        let Some(row) = load_row(tx, &id)? else { continue };
        if !wakes_through(tx, &row, &name)? {
            continue;
        }
        if matches!(status.as_str(), "starting" | "running" | "waiting") {
            tx.execute("UPDATE agent_sessions SET last_heartbeat_at = ?2 WHERE id = ?1", params![id, ts])?;
            kept += 1;
        } else if status == "abandoned" && exit.as_deref() == Some(REAPED_EXIT) {
            tx.execute(
                "UPDATE agent_sessions SET last_heartbeat_at = ?2, status = 'running', ended_at = NULL, \
                 exit_status = NULL WHERE id = ?1",
                params![id, ts],
            )?;
            revived += 1;
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    CHANNEL_REVIVED,
                    json!({ "session_id": id, "agent": agent, "node": name }),
                )
                .by(identity.to_string()),
            )?;
        }
    }
    Ok(json!({ "kept_open": kept, "revived": revived }))
}

/// Open wake polls per `(hub database, node)`.
type PollKey = (usize, String);
static POLLS: LazyLock<Mutex<HashMap<PollKey, usize>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// One open wake poll of a node; dropping it frees the slot.
struct PollSlot(PollKey);

impl PollSlot {
    fn take(hub: &crate::hub::Hub, node: &str) -> UaResult<Self> {
        // The database handle lives as long as the hub, so its address tells
        // hubs in one process apart.
        let key = (std::ptr::from_ref(hub.db()) as usize, node.to_string());
        let mut polls = POLLS.lock().unwrap_or_else(|e| e.into_inner());
        let open = polls.entry(key.clone()).or_insert(0);
        if *open >= MAX_POLLS_PER_NODE {
            return Err(UaError::conflict_code(
                "wake_poll_busy",
                format!(
                    "node {node:?} already holds {MAX_POLLS_PER_NODE} wake polls open; wait for one to end"
                ),
            ));
        }
        *open += 1;
        Ok(Self(key))
    }
}

impl Drop for PollSlot {
    fn drop(&mut self) {
        let mut polls = POLLS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(open) = polls.get_mut(&self.0) {
            *open = open.saturating_sub(1);
            if *open == 0 {
                polls.remove(&self.0);
            }
        }
    }
}

// --- device-plane tools -----------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakePollArgs {
    /// Your registered node. Only your own sessions whose wake node it is
    /// are offered: the node a session named when it asked, else your one
    /// node whose name matches the session's host by short lowercase name.
    pub node: String,
    /// Seconds to wait for an offer, 0-30.
    pub wait_s: Option<f64>,
    /// Offer protocol version; must be 3.
    pub offer_version: Option<i64>,
    /// Native session ids with a pane on this host (at most 64, each at most
    /// 512 characters). Keeps idle granted sessions open on the hub.
    pub live_sessions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckArgs {
    /// Your registered node.
    pub node: String,
    /// The offer's hub session id.
    pub session_id: String,
    /// The offer's `newest_seq`.
    pub seq: i64,
    /// The offer's `expires_at`, unchanged.
    pub expires_at: f64,
    /// The offer's `offer_id`.
    pub offer_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptArgs {
    /// Your registered node.
    pub node: String,
    /// The offer's hub session id.
    pub session_id: String,
    /// The offer's `newest_seq`.
    pub seq: i64,
    /// `delivered`, `failed` or `skipped`.
    pub outcome: String,
    /// Why it was skipped or failed: 1-64 of `[a-z0-9_:.-]`, e.g. `focused`,
    /// `no_match`, `delivery_uncertain`.
    pub reason: Option<String>,
    /// The offer's `expires_at`, unchanged.
    pub expires_at: f64,
    /// The offer's `offer_id`.
    pub offer_id: String,
    /// Unix time the prompt was submitted; required for `delivered`.
    pub delivered_at: Option<f64>,
}

async fn node_wake(ctx: ToolCtx, a: WakePollArgs) -> UaResult<Value> {
    let agent = node_queue::device_agent(&ctx.caller)?;
    if a.offer_version != Some(3) {
        return Err(UaError::invalid("idle wakes require offer_version=3"));
    }
    let node = nodes::validate_node_name(&a.node)?;
    let wait = match a.wait_s {
        None => 0.0,
        Some(w) if w.is_finite() => w.clamp(0.0, WAKE_MAX_WAIT_S),
        Some(_) => return Err(UaError::invalid("wait_s must be a number")),
    };
    // Only the node's own agent holds a poll (and a slot) open.
    let (n, ag) = (node.clone(), agent.clone());
    let node = ctx.hub.db().read_async(move |c| Ok(node_queue::owned_node(c, &n, &ag)?.node)).await?;
    let _slot = PollSlot::take(&ctx.hub, &node)?;
    if let Some(live) = a.live_sessions {
        if live.len() > MAX_LIVE_SESSIONS
            || live.iter().any(|e| e.is_empty() || e.chars().count() > MAX_EXTERNAL_ID_CHARS)
        {
            return Err(UaError::invalid("live_sessions must be a short list of ids"));
        }
        let (n, ag) = (node.clone(), agent.clone());
        ctx.hub.db().write_async(move |tx| note_live_sessions(tx, &n, &ag, &live)).await?;
    }
    let deadline = Instant::now() + Duration::from_secs_f64(wait);
    loop {
        let last = Instant::now() >= deadline;
        // Read first: the write transaction runs only when something is due.
        let (n, ag) = (node.clone(), agent.clone());
        let pending = ctx.hub.db().read_async(move |c| poll_pending(c, &n, &ag, now_f())).await?;
        if pending {
            let (n, ag) = (node.clone(), agent.clone());
            let wakes = ctx.hub.db().write_async(move |tx| due_wakes(tx, &n, &ag, now_f())).await?;
            if !wakes.is_empty() {
                return Ok(json!({ "wakes": wakes }));
            }
        }
        if last {
            return Ok(json!({ "wakes": [] }));
        }
        tokio::time::sleep(WAKE_POLL.min(deadline.saturating_duration_since(Instant::now()))).await;
    }
}

async fn node_wake_check(ctx: ToolCtx, a: CheckArgs) -> UaResult<Value> {
    let agent = node_queue::device_agent(&ctx.caller)?;
    ctx.hub.db().write_async(move |tx| check_offer(tx, &a.node.clone(), &agent, &a, now_f())).await
}

async fn node_wake_receipt(ctx: ToolCtx, a: ReceiptArgs) -> UaResult<Value> {
    let agent = node_queue::device_agent(&ctx.caller)?;
    ctx.hub.db().write_async(move |tx| record_receipt(tx, &a.node.clone(), &agent, &a, now_f())).await
}

// --- consent: coordination_manage actions -----------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OptInArgs {
    /// One of your own hub sessions.
    pub session_id: String,
    /// `true` (default) asks for wakes; `false` withdraws the request and
    /// clears any outstanding offer.
    pub wake: Option<bool>,
    /// The node on this session's machine that delivers its wakes: one of
    /// your own registered nodes. Once named, only that node is offered the
    /// session's wakes, checks or reports them, or keeps the session open.
    /// Unnamed, the wake node is your one node whose name matches the
    /// session's host (short, lowercase), and none when that is ambiguous.
    pub node: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantArgs {
    /// The hub session to grant (or revoke) wakes for.
    pub session_id: String,
    /// `true` (default) grants; `false` revokes and clears outstanding offers.
    pub grant: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclineArgs {
    /// The hub session whose wake request is declined.
    pub session_id: String,
    /// Why, up to 500 characters.
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusArgs {
    /// One session's wake state. Omitted: every session with wake state you
    /// may see (an operator sees all, an agent its own) and fleet counts.
    pub session_id: Option<String>,
}

fn verified_identity(caller: &Caller, verb: &str) -> UaResult<String> {
    verified(caller).map(str::to_string).ok_or_else(|| {
        UaError::denied("identity_required", format!("{verb} requires an authenticated identity"))
    })
}

pub(crate) async fn session_wake_opt_in(ctx: ToolCtx, a: OptInArgs) -> UaResult<Value> {
    let who = verified_identity(&ctx.caller, "session_wake_opt_in")?;
    let sid = check_session_id(&a.session_id)?;
    let wake = a.wake.unwrap_or(true);
    let node = a.node.as_deref().map(nodes::validate_node_name).transpose()?;
    if node.is_some() && !wake {
        return Err(UaError::invalid("node applies only when asking for wakes"));
    }
    ctx.hub
        .db()
        .write_async(move |tx| {
            let (agent, status) = session_agent(tx, &sid)?;
            if agent != who {
                return Err(UaError::denied(
                    "not_session_owner",
                    format!("session {sid:?} is not a session of {who:?}; only its own agent asks for wakes"),
                ));
            }
            if wake && !matches!(status.as_str(), "starting" | "running" | "waiting") {
                return Err(UaError::conflict(format!("session {sid:?} has ended ({status}); it cannot ask for wakes")));
            }
            // A named wake node must be one of the session's own agent's.
            if let Some(n) = &node {
                node_queue::owned_node(tx, n, &who)?;
            }
            let before: Option<(i64, Option<String>)> = tx
                .query_row("SELECT opted_in, node FROM session_wake WHERE session_id = ?1", [&sid], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let renamed = node.is_some() && before.as_ref().and_then(|(_, n)| n.as_ref()) != node.as_ref();
            let changed = before.as_ref().map_or(0, |(o, _)| *o) != i64::from(wake) || renamed;
            let ts = ua_core::time::now();
            if wake {
                if renamed {
                    // Offers made through another node no longer count.
                    invalidate_offers(tx, &sid, now_f())?;
                }
                tx.execute(
                    "INSERT INTO session_wake (session_id, opted_in, requested_at, node, updated_at) \
                     VALUES (?1, 1, ?2, ?3, ?2) \
                     ON CONFLICT(session_id) DO UPDATE SET opted_in = 1, \
                     requested_at = COALESCE(requested_at, excluded.requested_at), \
                     node = COALESCE(excluded.node, node), \
                     offered_at = CASE WHEN ?4 THEN NULL ELSE offered_at END, \
                     offered_seq = CASE WHEN ?4 THEN NULL ELSE offered_seq END, \
                     offered_id = CASE WHEN ?4 THEN NULL ELSE offered_id END, \
                     updated_at = excluded.updated_at",
                    params![sid, ts, node, renamed],
                )?;
            } else if changed {
                tx.execute(
                    "UPDATE session_wake SET opted_in = 0, requested_at = NULL, offered_at = NULL, offered_seq = NULL, \
                     offered_id = NULL, updated_at = ?2 WHERE session_id = ?1",
                    params![sid, ts],
                )?;
                invalidate_offers(tx, &sid, now_f())?;
            }
            if changed {
                record(
                    tx,
                    CHANNEL_REQUEST,
                    if wake { "requested" } else { "withdrawn" },
                    json!({ "session_id": sid, "agent": agent, "node": node }),
                    &who,
                )?;
            }
            Ok(json!({ "session_id": sid, "requested": wake, "changed": changed, "state": state(tx, &sid)? }))
        })
        .await
}

pub(crate) async fn session_wake_grant(ctx: ToolCtx, a: GrantArgs) -> UaResult<Value> {
    let Some(actor) = verified(&ctx.caller).filter(|_| ctx.caller.is_human()).map(str::to_string) else {
        return Err(UaError::denied(
            "human_required",
            "only a verified human may grant or revoke session wakes; a session may only ask for them",
        ));
    };
    let sid = check_session_id(&a.session_id)?;
    let grant = a.grant.unwrap_or(true);
    ctx.hub
        .db()
        .write_async(move |tx| {
            let (agent, _) = session_agent(tx, &sid)?;
            let before: Option<(i64, bool)> = tx
                .query_row(
                    "SELECT opted_in, granted_at IS NOT NULL FROM session_wake WHERE session_id = ?1",
                    [&sid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let requested = before.is_some_and(|(o, _)| o != 0);
            let changed = before.is_some_and(|(_, g)| g) != grant;
            if changed {
                let ts = ua_core::time::now();
                if grant {
                    // A grant is the human changing their mind: it clears a decline.
                    tx.execute(
                        "INSERT INTO session_wake (session_id, granted_at, granted_by, updated_at) \
                         VALUES (?1, ?2, ?3, ?2) ON CONFLICT(session_id) DO UPDATE SET \
                         granted_at = excluded.granted_at, granted_by = excluded.granted_by, declined_at = NULL, \
                         declined_by = NULL, decline_reason = NULL, updated_at = excluded.updated_at",
                        params![sid, ts, actor],
                    )?;
                } else {
                    invalidate_offers(tx, &sid, now_f())?;
                    tx.execute(
                        "UPDATE session_wake SET granted_at = NULL, granted_by = NULL, offered_at = NULL, \
                         offered_seq = NULL, offered_id = NULL, updated_at = ?2 WHERE session_id = ?1",
                        params![sid, ts],
                    )?;
                }
                record(
                    tx,
                    CHANNEL_GRANT,
                    if grant { "granted" } else { "revoked" },
                    json!({ "session_id": sid, "agent": agent }),
                    &actor,
                )?;
            }
            Ok(json!({ "session_id": sid, "granted": grant, "requested": requested, "changed": changed }))
        })
        .await
}

pub(crate) async fn session_wake_decline(ctx: ToolCtx, a: DeclineArgs) -> UaResult<Value> {
    let actor = verified_identity(&ctx.caller, "session_wake_decline")?;
    let sid = check_session_id(&a.session_id)?;
    let reason = a
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_DECLINE_REASON).collect::<String>());
    // A decline only restricts, so any verified human may make one, as may a
    // lifecycle operator or the session's own agent.
    let human = ctx.caller.is_human();
    let maintainer = human
        || Authz::new(ctx.hub.cfg()).holds(
            &ctx.caller,
            &[Authority::Operator, Authority::LifecycleOperator],
            ua_core::DEFAULT_ORG,
        );
    ctx.hub
        .db()
        .write_async(move |tx| {
            let (agent, _) = session_agent(tx, &sid)?;
            if !maintainer && agent != actor {
                return Err(UaError::denied(
                    "not_authorized",
                    "a wake request is declined by a verified human, a lifecycle operator or the session's own agent",
                ));
            }
            let declined: Option<bool> = tx
                .query_row("SELECT declined_at IS NOT NULL FROM session_wake WHERE session_id = ?1", [&sid], |r| {
                    r.get(0)
                })
                .optional()?;
            let changed = !declined.unwrap_or(false);
            if changed {
                invalidate_offers(tx, &sid, now_f())?;
                let ts = ua_core::time::now();
                tx.execute(
                    "INSERT INTO session_wake (session_id, declined_at, declined_by, decline_reason, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?2) ON CONFLICT(session_id) DO UPDATE SET \
                     declined_at = excluded.declined_at, declined_by = excluded.declined_by, \
                     decline_reason = excluded.decline_reason, granted_at = NULL, granted_by = NULL, \
                     offered_at = NULL, offered_seq = NULL, offered_id = NULL, updated_at = excluded.updated_at",
                    params![sid, ts, actor, reason],
                )?;
                record(tx, CHANNEL_GRANT, "declined", json!({ "session_id": sid, "agent": agent }), &actor)?;
            }
            let mut out = state(tx, &sid)?;
            out["session_id"] = json!(sid);
            out["changed"] = json!(changed);
            Ok(out)
        })
        .await
}

/// One session's wake state for display.
fn state(c: &Connection, sid: &str) -> UaResult<Value> {
    Ok(c.query_row(
        "SELECT w.session_id, s.agent, s.status, s.host, w.opted_in, w.requested_at, w.granted_at, w.granted_by, \
         w.declined_at, w.declined_by, w.decline_reason, w.offered_at, w.retry_at, w.last_wake_at, w.last_wake_seq, \
         w.wakes_last_hour, w.unacked_wakes, w.unacked_attempts, w.paused_reason, w.last_outcome, w.last_reason, \
         w.attempts \
         FROM session_wake w JOIN agent_sessions s ON s.id = w.session_id WHERE w.session_id = ?1",
        [sid],
        state_json,
    )
    .optional()?
    .unwrap_or_else(|| json!({ "session_id": sid, "requested": false, "granted": false, "declined": false })))
}

fn state_json(r: &Row<'_>) -> rusqlite::Result<Value> {
    let t = |v: Option<f64>| v.map(iso);
    let now = now_f();
    let offered_at: Option<f64> = r.get(11)?;
    Ok(json!({
        "session_id": r.get::<_, String>(0)?,
        "agent": r.get::<_, String>(1)?,
        "session_status": r.get::<_, String>(2)?,
        "host": r.get::<_, Option<String>>(3)?,
        "requested": r.get::<_, i64>(4)? != 0,
        "requested_at": r.get::<_, Option<String>>(5)?,
        "granted": r.get::<_, Option<String>>(6)?.is_some(),
        "granted_at": r.get::<_, Option<String>>(6)?,
        "granted_by": r.get::<_, Option<String>>(7)?,
        "declined": r.get::<_, Option<String>>(8)?.is_some(),
        "declined_at": r.get::<_, Option<String>>(8)?,
        "declined_by": r.get::<_, Option<String>>(9)?,
        "decline_reason": r.get::<_, Option<String>>(10)?,
        "offer_outstanding": offered_at.is_some_and(|o| now - o < OFFER_LEASE_S),
        "retry_at": t(r.get(12)?),
        "last_wake_at": t(r.get(13)?),
        "last_wake_seq": r.get::<_, i64>(14)?,
        "wakes_last_hour": r.get::<_, i64>(15)?,
        "unacked_wakes": r.get::<_, i64>(16)?,
        "unacked_attempts": r.get::<_, i64>(17)?,
        "paused_reason": r.get::<_, Option<String>>(18)?,
        "last_outcome": r.get::<_, Option<String>>(19)?,
        "last_reason": r.get::<_, Option<String>>(20)?,
        "attempts": r.get::<_, i64>(21)?,
    }))
}

pub(crate) async fn session_wake_status(ctx: ToolCtx, a: StatusArgs) -> UaResult<Value> {
    let who = verified_identity(&ctx.caller, "session_wake_status")?;
    let maintainer = Authz::new(ctx.hub.cfg()).holds(
        &ctx.caller,
        &[Authority::Operator, Authority::LifecycleOperator],
        ua_core::DEFAULT_ORG,
    );
    let sid = a.session_id.as_deref().map(check_session_id).transpose()?;
    ctx.hub
        .db()
        .read_async(move |c| {
            if let Some(sid) = sid {
                let (agent, _) = session_agent(c, &sid)?;
                if !maintainer && agent != who {
                    return Err(UaError::not_found(format!("session {sid:?} does not exist")));
                }
                return state(c, &sid);
            }
            let mut stmt = c.prepare(
                "SELECT w.session_id, s.agent, s.status, s.host, w.opted_in, w.requested_at, w.granted_at, \
                 w.granted_by, w.declined_at, w.declined_by, w.decline_reason, w.offered_at, w.retry_at, \
                 w.last_wake_at, w.last_wake_seq, w.wakes_last_hour, w.unacked_wakes, w.unacked_attempts, \
                 w.paused_reason, w.last_outcome, w.last_reason, w.attempts \
                 FROM session_wake w JOIN agent_sessions s ON s.id = w.session_id \
                 WHERE (?1 OR s.agent = ?2) ORDER BY w.requested_at, w.session_id LIMIT 500",
            )?;
            let rows = stmt.query_map(params![maintainer, who], state_json)?.collect::<Result<Vec<_>, _>>()?;
            let open = |v: &Value| matches!(v["session_status"].as_str(), Some("starting" | "running" | "waiting"));
            let requested: Vec<&Value> = rows.iter().filter(|v| open(v) && v["requested"] == json!(true)).collect();
            let awaiting: Vec<&Value> = requested
                .iter()
                .copied()
                .filter(|v| v["granted"] == json!(false) && v["declined"] == json!(false))
                .collect();
            let woken: i64 = c.query_row(
                "SELECT COUNT(DISTINCT o.session_id) FROM session_wake_offers o \
                 JOIN agent_sessions s ON s.id = o.session_id WHERE o.outcome = 'delivered' AND (?1 OR s.agent = ?2)",
                params![maintainer, who],
                |r| r.get(0),
            )?;
            Ok(json!({
                "summary": {
                    "opted_in": requested.len(),
                    "granted": requested.iter().filter(|v| v["granted"] == json!(true)).count(),
                    "awaiting": awaiting.len(),
                    "awaiting_ids": awaiting.iter().take(5).map(|v| v["session_id"].clone()).collect::<Vec<_>>(),
                    "paused": requested.iter().filter(|v| !v["paused_reason"].is_null()).count(),
                    "woken": woken,
                },
                "sessions": rows,
                "count": rows.len(),
            }))
        })
        .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "node_wake",
            "Device plane: long-poll (wait_s up to 30, offer_version 3, at most 2 open per node) for idle-session \
             wakes your node should deliver: your own granted, opted-in sessions whose wake node this is, with \
             new trigger mail (request, query, handoff or expects_reply) past the debounce, floor, hourly caps \
             and breaker. Returns {wakes: [{session_id, external_session_id, unread, newest_seq, expires_at, \
             offer_id}]}, ids and counts only. live_sessions (native ids with a pane here) keeps those idle \
             granted sessions open.",
            node_wake,
        )
        .family("nodes"),
    );
    r.add(
        tool(
            "node_wake_check",
            "Device plane: reserve one delivery attempt for a wake offer right before typing it. Checks live \
             consent, the offer generation and deadline, and the attempt budget. Returns {session_id, valid, \
             remaining_s}; type only when valid, within remaining_s.",
            node_wake_check,
        )
        .family("nodes"),
    );
    r.add(
        tool(
            "node_wake_receipt",
            "Device plane: report a wake offer's outcome: delivered (with delivered_at), failed or skipped (with \
             reason). Echo the offer's seq, expires_at and offer_id. Idempotent: a resend, or a receipt for a \
             lapsed offer, returns {recorded: false, duplicate: true}.",
            node_wake_receipt,
        )
        .family("nodes"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_compare_by_short_name() {
        assert_eq!(host_key("Box.local"), "box");
        assert_eq!(host_key(" box "), "box");
        assert_eq!(host_key(""), "");
    }

    #[test]
    fn the_wake_text_is_a_constant_and_a_number() {
        assert_eq!(wake_text(3), "You have 3 new hub messages; run message_inbox");
    }

    /// Review finding: an idle long-poll took the write lock every second.
    /// The poll now reads first and writes only when something is due.
    #[tokio::test]
    async fn an_idle_poll_has_nothing_to_write() {
        use ua_core::{ActorKind, Profile, identity::Transport};
        let mut cfg = ua_core::Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        let hub = crate::Hub::in_memory(cfg).unwrap();
        let reg = crate::builtin_registry();
        let who = |label: &str, kind| Caller {
            label: label.into(),
            kind,
            profile: Profile::Developer,
            enforce_profile: true,
            session_key: None,
            transport: Transport::Http,
            org_id: ua_core::DEFAULT_ORG.into(),
        };
        let me = who("builder-1", ActorKind::Agent);
        reg.call(&hub, &me, "node_register", json!({ "node": "box", "facts": { "backends": ["codex"] } }))
            .await
            .unwrap();
        let s = reg
            .call(
                &hub,
                &me,
                "session_start",
                json!({ "kind": "interactive", "external_session_id": "x", "host": "box" }),
            )
            .await
            .unwrap();
        let sid = s["session_id"].as_str().unwrap().to_string();
        let params = json!({ "session_id": sid });
        for (caller, action) in
            [(&me, "session_wake_opt_in"), (&who("operator", ActorKind::Human), "session_wake_grant")]
        {
            reg.call(&hub, caller, "coordination_manage", json!({ "action": action, "params": params }))
                .await
                .unwrap();
        }
        let pending = || hub.db().read(|c| poll_pending(c, "box", "builder-1", now_f())).unwrap();
        assert!(!pending(), "no mail: nothing to write");
        reg.call(
            &hub,
            &who("lead-1", ActorKind::Agent),
            "message_send",
            json!({ "act": "request", "to_agent": "builder-1", "body": "b" }),
        )
        .await
        .unwrap();
        assert!(!pending(), "debounce: still nothing to write");
        hub.db()
            .write(|tx| {
                tx.execute_batch(
                    "UPDATE message_index SET created_at = strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now', '-90 seconds')",
                )?;
                Ok(())
            })
            .unwrap();
        assert!(pending(), "due: the poll writes the offer");
        assert!(
            !hub.db().read(|c| poll_pending(c, "box", "intruder", now_f())).unwrap(),
            "only the owner's sessions"
        );
    }

    #[test]
    fn reasons_are_bounded() {
        assert!(check_reason(Some("focused")).is_ok());
        assert!(check_reason(Some("Has Spaces")).is_err());
        assert!(check_reason(Some(&"a".repeat(65))).is_err());
    }
}
