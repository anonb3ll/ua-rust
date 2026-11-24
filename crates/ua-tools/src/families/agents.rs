//! Agent registry, sessions and lifecycle capture.
//!
//! Tools: `agent_heartbeat`, `agent_list`, `agent_context`, `session_start`,
//! `session_end`, `session_list`, `lifecycle_record`. The rows live in the
//! shared `agents`, `agent_sessions` and `idempotency_keys` tables
//! (`core_schema.rs`); this family adds no tables of its own.
//!
//! Liveness is derived at read time from timestamps and never stored: an agent
//! is `online`/`idle`/`stale`/`offline` by the age of its `last_seen` (`unknown`
//! when never seen), and a session is `live` while it is open and was seen
//! within [`SESSION_LIVE_MINUTES`]. Open sessions with no heartbeat for
//! [`SESSION_ABANDON_MINUTES`] are reaped to `abandoned` before session reads.
//!
//! Identity: a verified caller (an agent or human with a credential) acts as
//! itself and cannot name another label. An unverified local caller may name
//! the label it acts for and defaults to its configured local label.

use jiff::{SignedDuration, Timestamp};
use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, Row, params, params_from_iter};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::time::{format_ts, parse_ts};
use ua_core::{ActorKind, Caller, UaError, UaResult};
use ua_store::{EventInput, WriteTx, ledger};

use crate::registry::{Registry, ToolCtx, tool};

/// An open session not seen for this long is not `live` (not offered as a
/// message target).
pub const SESSION_LIVE_MINUTES: i64 = 30;
/// An open session with no heartbeat for this long is reaped to `abandoned`.
pub const SESSION_ABANDON_MINUTES: i64 = 30;
/// `(online, idle, stale)` cutoffs in seconds for agent status; older is `offline`.
pub const STATUS_THRESHOLDS: (i64, i64, i64) = (120, 900, 86_400);

const OPEN_STATUSES: [&str; 3] = ["starting", "running", "waiting"];
const SESSION_STATUSES: [&str; 6] = ["starting", "running", "waiting", "completed", "failed", "abandoned"];
const PEER_SESSION_CAP: usize = 10;
const MAX_LABEL_LEN: usize = 128;

const LIFECYCLE_KINDS: [&str; 8] = [
    "session_start",
    "session_end",
    "prompt_metadata",
    "tool_start",
    "tool_end",
    "compaction",
    "stop",
    "handoff",
];
/// The channel a hook-reported `handoff` observation is recorded on. It is not
/// `agent.lifecycle.handoff`, which carries only the authoritative handoff-note
/// events, so a caller cannot place a note-shaped row in another session's
/// view.
pub(crate) const HOOK_HANDOFF_CHANNEL: &str = "agent.lifecycle.handoff_hook";

/// The ledger channel for a lifecycle `kind`.
fn lifecycle_channel(kind: &str) -> String {
    match kind {
        "handoff" => HOOK_HANDOFF_CHANNEL.to_string(),
        other => format!("agent.lifecycle.{other}"),
    }
}
/// Tools whose lifecycle observations are never captured.
const LIFECYCLE_EXCLUDED_TOOLS: [&str; 2] = ["gemini_ask", "pi_run_task"];
/// Payload keys dropped (not redacted) at any depth, compared case-insensitively,
/// so a stored observation can never carry a transcript, prompt or credential.
const LIFECYCLE_EXCLUDED_KEYS: [&str; 14] = [
    "transcript",
    "transcript_path",
    "transcript_uri",
    "prompt",
    "messages",
    "system",
    "developer",
    "raw_prompt",
    "completion",
    "authorization",
    "token",
    "api_key",
    "password",
    "secret",
];
const LIFECYCLE_MAX_PAYLOAD_BYTES: usize = 16 * 1024;

const RULES: [&str; 5] = [
    "identity_is_authenticated_and_session_scoped",
    "task_claim_is_atomic_and_claimed_by_is_authoritative",
    "note_markers_are_descriptive_not_authorization",
    "development_workspaces_are_separate_from_shared_control_state",
    "remote_cutover_requires_human_approval",
];

// --- shared helpers (also used by the messaging family) ---------------------------

/// The caller's verified label, or `None` for an unverified or in-process caller.
pub(crate) fn verified(caller: &Caller) -> Option<&str> {
    matches!(caller.kind, ActorKind::Agent | ActorKind::Human).then_some(caller.label.as_str())
}

/// Trimmed, non-empty text, else `None`.
pub(crate) fn clean(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// A well-formed agent label: 1-128 letters, digits, `_`, `-`, `.`, `:` or `@`.
pub(crate) fn validate_label(label: Option<&str>, field: &str) -> UaResult<String> {
    let name = label.map(str::trim).unwrap_or("");
    if name.is_empty() {
        return Err(UaError::invalid(format!("{field} is required")));
    }
    let ok = name.len() <= MAX_LABEL_LEN
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '@'));
    if !ok {
        return Err(UaError::invalid(format!(
            "{field} {name:?} is not a valid agent label (1-{MAX_LABEL_LEN} letters, digits, '_', '-', '.', ':' or '@')"
        )));
    }
    Ok(name.to_string())
}

/// Unix seconds now.
pub(crate) fn now_s() -> i64 {
    ua_core::time::now_ms() / 1000
}

/// The stored timestamp `secs` seconds ago.
pub(crate) fn ago(secs: i64) -> String {
    let now = Timestamp::now();
    format_ts(now.checked_sub(SignedDuration::from_secs(secs)).unwrap_or(now))
}

fn age_s(ts: Option<&str>, now: i64) -> Option<i64> {
    ts.and_then(parse_ts).map(|t| (now - t.as_second()).max(0))
}

/// `online`, `idle`, `stale`, `offline`, or `unknown` for a label never seen.
pub(crate) fn derive_status(last_seen: Option<&str>, now: i64) -> &'static str {
    let Some(age) = age_s(last_seen, now) else { return "unknown" };
    let (online, idle, stale) = STATUS_THRESHOLDS;
    if age <= online {
        "online"
    } else if age <= idle {
        "idle"
    } else if age <= stale {
        "stale"
    } else {
        "offline"
    }
}

fn is_open(status: &str) -> bool {
    OPEN_STATUSES.contains(&status)
}

fn is_live(status: &str, heartbeat: Option<&str>, now: i64) -> bool {
    is_open(status) && age_s(heartbeat, now).is_some_and(|a| a <= SESSION_LIVE_MINUTES * 60)
}

fn load_meta(raw: Option<String>) -> Value {
    raw.and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn open_marks() -> String {
    OPEN_STATUSES.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(",")
}

/// Record that `label` was alive just now. Returns true when this created the
/// agent's row; the first sighting is written to the ledger, later heartbeats
/// are not (they only move `last_seen`).
pub(crate) fn touch_agent(
    tx: &mut WriteTx<'_>,
    label: &str,
    via: &str,
    kind: Option<&str>,
    host: Option<&str>,
    version: Option<&str>,
    verified_self: bool,
) -> UaResult<bool> {
    let existed: bool =
        tx.query_row("SELECT 1 FROM agents WHERE label = ?1", [label], |_| Ok(())).optional()?.is_some();
    let ts = ua_core::time::now();
    tx.execute(
        "INSERT INTO agents (label, kind, host, known, first_seen, last_seen, last_seen_via, version, \
         created_at, updated_at, meta) \
         VALUES (?1, COALESCE(?2, 'unknown'), ?3, ?4, ?5, ?5, ?6, ?7, ?5, ?5, '{}') \
         ON CONFLICT(label) DO UPDATE SET \
           last_seen = excluded.last_seen, \
           last_seen_via = excluded.last_seen_via, \
           known = MAX(agents.known, excluded.known), \
           first_seen = COALESCE(agents.first_seen, excluded.first_seen), \
           kind = CASE WHEN excluded.kind = 'unknown' THEN agents.kind ELSE excluded.kind END, \
           host = COALESCE(excluded.host, agents.host), \
           version = COALESCE(excluded.version, agents.version), \
           updated_at = excluded.updated_at",
        params![label, kind, host, i64::from(verified_self), ts, via, version],
    )?;
    if !existed {
        ledger::append(
            tx,
            EventInput::new(
                ua_core::DEFAULT_ORG,
                "agent.agent.registered",
                json!({ "label": label, "kind": kind, "via": via }),
            )
            .by(label.to_string())
            .dedupe(format!("agent.registered:{label}")),
        )?;
    }
    Ok(!existed)
}

/// Mark open sessions with no heartbeat for [`SESSION_ABANDON_MINUTES`] as
/// `abandoned`. Returns how many were reaped.
pub(crate) fn reap(tx: &mut WriteTx<'_>) -> UaResult<usize> {
    let cutoff = ago(SESSION_ABANDON_MINUTES * 60);
    let ids: Vec<String> = {
        let mut stmt = tx.prepare(&format!(
            "SELECT id FROM agent_sessions WHERE status IN ({}) AND last_heartbeat_at < ?1 ORDER BY id",
            open_marks()
        ))?;
        stmt.query_map([&cutoff], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    if ids.is_empty() {
        return Ok(0);
    }
    let now = ua_core::time::now();
    for id in &ids {
        tx.execute(
            "UPDATE agent_sessions SET status = 'abandoned', ended_at = ?2, \
             exit_status = COALESCE(exit_status, 'no_heartbeat') WHERE id = ?1",
            params![id, now],
        )?;
    }
    ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            "agent.session.reaped",
            json!({ "session_ids": ids, "count": ids.len() }),
        )
        .by("system"),
    )?;
    Ok(ids.len())
}

/// The parts of a session the messaging family needs.
#[derive(Debug, Clone)]
pub(crate) struct SessionRef {
    pub agent: String,
    pub status: String,
    pub live: bool,
}

impl SessionRef {
    pub fn ended(&self) -> bool {
        matches!(self.status.as_str(), "completed" | "failed")
    }
}

pub(crate) fn session_ref(conn: &Connection, id: &str) -> UaResult<Option<SessionRef>> {
    let row = conn
        .query_row("SELECT agent, status, last_heartbeat_at FROM agent_sessions WHERE id = ?1", [id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })
        .optional()?;
    Ok(row.map(|(agent, status, hb)| {
        let live = is_live(&status, Some(&hb), now_s());
        SessionRef { agent, status, live }
    }))
}

/// Count a call as the session's heartbeat. `revive` also reopens a session
/// the reaper marked `abandoned`; a session ended by its agent stays ended.
pub(crate) fn touch_session(conn: &Connection, id: &str, revive: bool) -> UaResult<bool> {
    let states =
        if revive { "'starting','running','waiting','abandoned'" } else { "'starting','running','waiting'" };
    let n = conn.execute(
        &format!(
            "UPDATE agent_sessions SET last_heartbeat_at = ?2, \
             status = CASE WHEN status = 'abandoned' THEN 'running' ELSE status END, \
             ended_at = CASE WHEN status = 'abandoned' THEN NULL ELSE ended_at END, \
             exit_status = CASE WHEN status = 'abandoned' THEN NULL ELSE exit_status END \
             WHERE id = ?1 AND status IN ({states})"
        ),
        params![id, ua_core::time::now()],
    )?;
    Ok(n > 0)
}

/// Check that `id` is a session of `owner` and count the call as its
/// heartbeat. One error covers "no such session" and "someone else's", so a
/// probe learns nothing about other agents' sessions. Needs a write connection.
pub(crate) fn own_session(conn: &Connection, id: &str, owner: &str, revive: bool) -> UaResult<SessionRef> {
    match session_ref(conn, id)? {
        Some(s) if s.agent == owner => {
            touch_session(conn, id, revive)?;
            Ok(s)
        }
        _ => Err(UaError::invalid(format!("session {id:?} is not a session of {owner:?}"))),
    }
}

/// Whether `label` can take a message now: `available` (a live session or a
/// recent heartbeat), `degraded` (known but quiet; the message waits) or
/// `unknown` (no liveness record). Returns the availability object and the
/// delivery warning, if any. Never refuses a send: label mail is durable.
pub(crate) fn availability(conn: &Connection, label: &str) -> UaResult<(Value, Option<String>)> {
    let now = now_s();
    let live_cutoff = ago(SESSION_LIVE_MINUTES * 60);
    let live: bool = conn
        .query_row(
            &format!(
                "SELECT 1 FROM agent_sessions WHERE agent = ?1 AND status IN ({}) AND last_heartbeat_at >= ?2 LIMIT 1",
                open_marks()
            ),
            params![label, live_cutoff],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let last_seen: Option<Option<String>> =
        conn.query_row("SELECT last_seen FROM agents WHERE label = ?1", [label], |r| r.get(0)).optional()?;
    let (state, reason, warning) = if live {
        ("available", "live_session", None)
    } else {
        match last_seen {
            Some(seen) if matches!(derive_status(seen.as_deref(), now), "online" | "idle") => {
                ("available", "recent_heartbeat", None)
            }
            Some(_) => (
                "degraded",
                "no_live_session_or_recent_heartbeat",
                Some(format!(
                    "{label} has no live session or recent heartbeat; the message is stored and will wait"
                )),
            ),
            None => ("unknown", "no_liveness_record", None),
        }
    };
    Ok((json!({ "agent": label, "availability": state, "reason": reason }), warning))
}

// --- session rows ---------------------------------------------------------------

/// A session row with its task's title and status. `?1` is the reader's
/// organization: another organization's task shows no title or status.
const SESSION_SELECT: &str = "SELECT s.*, t.title AS task_title, t.status AS task_status \
                              FROM agent_sessions s LEFT JOIN tasks t ON t.id = s.task_id AND t.org_id = ?1";

fn session_json(r: &Row<'_>, now: i64) -> rusqlite::Result<Value> {
    let status: String = r.get("status")?;
    let started: String = r.get("started_at")?;
    let ended: Option<String> = r.get("ended_at")?;
    let hb: String = r.get("last_heartbeat_at")?;
    let reference = ended.as_deref().and_then(parse_ts).map(|t| t.as_second()).unwrap_or(now);
    let since = |ts: &str| parse_ts(ts).map(|t| (reference - t.as_second()).max(0));
    Ok(json!({
        "id": r.get::<_, String>("id")?,
        "agent": r.get::<_, String>("agent")?,
        "kind": r.get::<_, String>("kind")?,
        "status": status,
        "started_at": started,
        "ended_at": ended,
        "last_heartbeat_at": hb,
        "last_seen_at": hb,
        "live": is_live(&status, Some(&hb), now),
        "duration_s": since(&started),
        "heartbeat_age_s": since(&hb),
        "task_id": r.get::<_, Option<i64>>("task_id")?,
        "task_title": r.get::<_, Option<String>>("task_title")?,
        "task_status": r.get::<_, Option<String>>("task_status")?,
        "delegation_id": r.get::<_, Option<i64>>("delegation_id")?,
        "worktree_path": r.get::<_, Option<String>>("worktree_path")?,
        "branch": r.get::<_, Option<String>>("branch")?,
        "external_session_id": r.get::<_, Option<String>>("external_session_id")?,
        "transcript_path": r.get::<_, Option<String>>("transcript_path")?,
        "host": r.get::<_, Option<String>>("host")?,
        "pid": r.get::<_, Option<i64>>("pid")?,
        "exit_status": r.get::<_, Option<String>>("exit_status")?,
        "summary": r.get::<_, Option<String>>("summary")?,
        "model": r.get::<_, Option<String>>("model")?,
        "meta": load_meta(r.get("meta")?),
    }))
}

fn get_session(conn: &Connection, org: &str, id: &str) -> UaResult<Option<Value>> {
    let now = now_s();
    Ok(conn
        .query_row(&format!("{SESSION_SELECT} WHERE s.id = ?2"), [org, id], |r| session_json(r, now))
        .optional()?)
}

fn list_sessions(
    conn: &Connection,
    org: &str,
    agent: Option<&str>,
    status: Option<&str>,
    limit: i64,
    live_only: bool,
) -> UaResult<Vec<Value>> {
    let mut clauses: Vec<String> = Vec::new();
    // `?1` in SESSION_SELECT; the bare `?`s that follow number from 2.
    let mut args: Vec<SqlValue> = vec![SqlValue::Text(org.to_string())];
    if let Some(a) = agent {
        clauses.push("s.agent = ?".into());
        args.push(SqlValue::Text(a.to_string()));
    }
    match status {
        Some("open") => clauses.push(format!("s.status IN ({})", open_marks())),
        Some(s) => {
            clauses.push("s.status = ?".into());
            args.push(SqlValue::Text(s.to_string()));
        }
        None => {}
    }
    if live_only {
        clauses.push(format!("s.status IN ({})", open_marks()));
        clauses.push("s.last_heartbeat_at >= ?".into());
        args.push(SqlValue::Text(ago(SESSION_LIVE_MINUTES * 60)));
    }
    let filter = if clauses.is_empty() { String::new() } else { format!(" WHERE {}", clauses.join(" AND ")) };
    args.push(SqlValue::Integer(limit.clamp(1, 500)));
    let now = now_s();
    let mut stmt =
        conn.prepare(&format!("{SESSION_SELECT}{filter} ORDER BY s.started_at DESC, s.id DESC LIMIT ?"))?;
    let rows = stmt.query_map(params_from_iter(args), |r| session_json(r, now))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Live sessions as compact message targets, newest first. `task_source` is
/// `session` when the session names its task, `claim` when it names none and
/// its agent holds exactly one `doing` task, else the task is null.
fn live_sessions_compact(conn: &Connection, org: &str) -> UaResult<Vec<Value>> {
    let rows = list_sessions(conn, org, None, None, 500, true)?;
    let mut claims: std::collections::BTreeMap<String, Vec<(i64, String)>> = Default::default();
    if rows.iter().any(|s| s["task_id"].is_null()) {
        let mut stmt = conn.prepare(
            "SELECT id, title, claimed_by FROM tasks WHERE org_id = ?1 AND status = 'doing' \
             AND claimed_by IS NOT NULL ORDER BY id",
        )?;
        let found = stmt.query_map([org], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })?;
        for row in found {
            let (id, title, by) = row?;
            claims.entry(by).or_default().push((id, title));
        }
    }
    Ok(rows
        .into_iter()
        .map(|s| {
            let (mut task_id, mut task_title, mut source) =
                (s["task_id"].clone(), s["task_title"].clone(), Value::from("session"));
            if task_id.is_null() {
                source = Value::Null;
                if let Some([(id, title)]) =
                    s["agent"].as_str().and_then(|a| claims.get(a)).map(Vec::as_slice)
                {
                    task_id = json!(id);
                    task_title = json!(title);
                    source = json!("claim");
                }
            }
            json!({
                "session_id": s["id"],
                "agent": s["agent"],
                "kind": s["kind"],
                "host": s["host"],
                "branch": s["branch"],
                "task_id": task_id,
                "task_title": task_title,
                "task_source": source,
                "started_at": s["started_at"],
                "last_seen_at": s["last_seen_at"],
                "heartbeat_age_s": s["heartbeat_age_s"],
            })
        })
        .collect())
}

// --- agent rows -----------------------------------------------------------------

fn agent_json(r: &Row<'_>, now: i64) -> rusqlite::Result<Value> {
    let last_seen: Option<String> = r.get("last_seen")?;
    Ok(json!({
        "label": r.get::<_, String>("label")?,
        "kind": r.get::<_, String>("kind")?,
        "host": r.get::<_, Option<String>>("host")?,
        "known": r.get::<_, i64>("known")? != 0,
        "first_seen": r.get::<_, Option<String>>("first_seen")?,
        "status": derive_status(last_seen.as_deref(), now),
        "last_seen": last_seen,
        "last_seen_via": r.get::<_, Option<String>>("last_seen_via")?,
        "pid": r.get::<_, Option<i64>>("pid")?,
        "version": r.get::<_, Option<String>>("version")?,
        "meta": load_meta(r.get("meta")?),
    }))
}

fn get_agent(conn: &Connection, label: &str) -> UaResult<Option<Value>> {
    let now = now_s();
    Ok(conn.query_row("SELECT * FROM agents WHERE label = ?1", [label], |r| agent_json(r, now)).optional()?)
}

/// Every agent, with its open sessions and its `doing` tasks in the
/// reader's organization `org`.
pub(crate) fn list_agents(conn: &Connection, org: &str) -> UaResult<Vec<Value>> {
    let now = now_s();
    let count_by = |sql: &str, p: &[&str]| -> UaResult<std::collections::BTreeMap<String, i64>> {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(p.iter()), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    };
    let open = count_by(
        &format!(
            "SELECT agent, COUNT(*) FROM agent_sessions WHERE status IN ({}) GROUP BY agent",
            open_marks()
        ),
        &[],
    )?;
    let active = count_by(
        "SELECT claimed_by, COUNT(*) FROM tasks WHERE org_id = ?1 AND claimed_by IS NOT NULL AND status = 'doing' \
         GROUP BY claimed_by",
        &[org],
    )?;
    let mut stmt =
        conn.prepare("SELECT * FROM agents ORDER BY (last_seen IS NULL), last_seen DESC, label")?;
    let rows = stmt.query_map([], |r| agent_json(r, now))?;
    let mut out = Vec::new();
    for row in rows {
        let mut agent = row?;
        let label = agent["label"].as_str().unwrap_or_default().to_string();
        agent["open_sessions"] = json!(open.get(&label).copied().unwrap_or(0));
        agent["active_tasks"] = json!(active.get(&label).copied().unwrap_or(0));
        out.push(agent);
    }
    Ok(out)
}

// --- tool arguments -------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatArgs {
    /// Agent label. Ignored for a verified caller, whose own label is used.
    pub agent: Option<String>,
    /// Agent kind, e.g. `claude-code` or `executor`.
    pub kind: Option<String>,
    /// Agent software version.
    pub version: Option<String>,
    /// Machine the agent runs on; stored on the agent row.
    pub host: Option<String>,
    /// A `system_doctor` snapshot. Accepted for compatibility; this hub keeps
    /// no host registry, so it is not stored.
    pub doctor: Option<Value>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentListArgs {
    /// Include configured labels never seen. This hub has no configured
    /// roster, so every listed agent has been seen; accepted for compatibility.
    pub include_configured: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentContextArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionStartArgs {
    /// What kind of session this is, e.g. `interactive`, `executor`, `review`.
    pub kind: String,
    /// Agent label. A verified caller may only name itself.
    pub agent: Option<String>,
    /// Task this session works on.
    pub task_id: Option<i64>,
    /// Worktree the session works in.
    pub worktree_path: Option<String>,
    /// Git branch the session works on.
    pub branch: Option<String>,
    /// The client's own session id. Registering the same `(agent,
    /// external_session_id)` again returns the same `session_id` with
    /// `created: false`, refreshes the heartbeat and reopens an ended row.
    pub external_session_id: Option<String>,
    /// Where the client keeps its transcript (a path, never the transcript).
    pub transcript_path: Option<String>,
    /// Free-form JSON object stored with a new session.
    pub meta: Option<Value>,
    /// Attach a resume packet. Not available in this hub; the result says so.
    #[serde(default)]
    pub include_packet: bool,
    /// Attach the packet of the latest other session on `task_id`. Packets are
    /// not available in this hub; `recalled_from_session_id` is still reported.
    #[serde(default)]
    pub recall_prior_packet: bool,
    /// Machine the agent runs on. A new session without one takes the host the
    /// label last heartbeated from; a refresh keeps the stored host.
    pub host: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionEndArgs {
    /// Hub session id from `session_start`.
    pub session_id: String,
    /// `completed` (default), `failed` or `abandoned`.
    pub status: Option<String>,
    /// Short machine-readable exit status, e.g. `ok` or `error`.
    pub exit_status: Option<String>,
    /// One-line human summary of what the session did.
    pub summary: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionListArgs {
    /// Only this agent's sessions.
    pub agent: Option<String>,
    /// A literal status (`starting`, `running`, `waiting`, `completed`,
    /// `failed`, `abandoned`) or `open` for the first three.
    pub status: Option<String>,
    /// 1-500, default 50.
    pub limit: Option<i64>,
    /// Only open sessions seen within the live window, filtered before `limit`.
    #[serde(default)]
    pub live_only: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LifecycleArgs {
    /// `session_start`, `session_end`, `prompt_metadata`, `tool_start`,
    /// `tool_end`, `compaction`, `stop` or `handoff`.
    pub kind: String,
    /// Hub session id the observation belongs to.
    pub session_id: Option<String>,
    /// Task the observation belongs to.
    pub task_id: Option<i64>,
    /// Agent label. Ignored for a verified caller.
    pub agent: Option<String>,
    /// Tool name, for `tool_start` / `tool_end`.
    pub tool: Option<String>,
    /// Observation details. Keys such as `transcript`, `prompt`, `messages`,
    /// `system`, `token`, `api_key` and `password` are dropped at any depth.
    pub payload: Option<Map<String, Value>>,
    /// A repeated key returns the first committed result without a second event.
    pub idempotency_key: Option<String>,
}

// --- tool bodies ----------------------------------------------------------------

/// The label a call acts as: the verified identity, else the named one, else
/// the local caller's configured label.
fn acting_label(caller: &Caller, named: Option<&str>, field: &str) -> UaResult<String> {
    match verified(caller) {
        Some(label) => Ok(label.to_string()),
        None => validate_label(Some(clean(named).as_deref().unwrap_or(&caller.label)), field),
    }
}

async fn heartbeat(ctx: ToolCtx, a: HeartbeatArgs) -> UaResult<Value> {
    let label = acting_label(&ctx.caller, a.agent.as_deref(), "agent")?;
    let verified_self = verified(&ctx.caller).is_some();
    let host = clean(a.host.as_deref());
    ctx.hub
        .db()
        .write_async(move |tx| {
            touch_agent(
                tx,
                &label,
                "heartbeat_tool",
                clean(a.kind.as_deref()).as_deref(),
                host.as_deref(),
                clean(a.version.as_deref()).as_deref(),
                verified_self,
            )?;
            let row = get_agent(tx, &label)?.unwrap_or_else(|| json!({}));
            Ok(json!({
                "agent": label,
                "recorded": true,
                "host_recorded": host.is_some(),
                "status": row["status"],
                "known": row["known"],
            }))
        })
        .await
}

/// `agent_list`, also the `agent_list` action of `coordination_manage`.
pub(crate) async fn agent_list(ctx: ToolCtx, _a: AgentListArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let agents = list_agents(c, &org)?;
            let mut counts = Map::new();
            for a in &agents {
                let status = a["status"].as_str().unwrap_or("unknown").to_string();
                let n = counts.get(&status).and_then(Value::as_i64).unwrap_or(0) + 1;
                counts.insert(status, json!(n));
            }
            let unregistered: Vec<String> = {
                let mut stmt =
                    c.prepare("SELECT label FROM agents WHERE known = 0 AND last_seen >= ?1 ORDER BY label")?;
                stmt.query_map([ago(7 * 86_400)], |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            Ok(json!({ "agents": agents, "counts": counts, "unregistered": unregistered }))
        })
        .await
}

/// `agent_context`, also the `agent_context` action of `coordination_manage`.
pub(crate) async fn agent_context(ctx: ToolCtx, _a: AgentContextArgs) -> UaResult<Value> {
    let identity = verified(&ctx.caller).map(str::to_string);
    let profile = ctx.caller.profile.as_str();
    let workspace = ctx.hub.cfg().workspace_root().to_string_lossy().into_owned();
    let org = ctx.caller.org_id.clone();
    let (agents, live) = ctx
        .hub
        .db()
        .write_async(move |tx| {
            reap(tx)?;
            Ok((list_agents(tx, &org)?, live_sessions_compact(tx, &org)?))
        })
        .await?;
    let peers: Vec<Value> = agents
        .into_iter()
        .map(|p| {
            let label = p["label"].as_str().unwrap_or_default();
            let sessions: Vec<&Value> =
                live.iter().filter(|s| s["agent"].as_str() == Some(label)).take(PEER_SESSION_CAP).collect();
            json!({
                "label": p["label"],
                "kind": p["kind"],
                "host": p["host"],
                "status": p["status"],
                "known": p["known"],
                "live_sessions": sessions,
            })
        })
        .collect();
    Ok(json!({
        "identity": identity,
        "profile": profile,
        "workspace": workspace,
        "session_live_minutes": SESSION_LIVE_MINUTES,
        "peers": peers,
        "rules": RULES,
    }))
}

async fn session_start(ctx: ToolCtx, a: SessionStartArgs) -> UaResult<Value> {
    let named = clean(a.agent.as_deref());
    if let (Some(me), Some(n)) = (verified(&ctx.caller), named.as_deref())
        && me != n
    {
        return Err(UaError::denied(
            "identity_mismatch",
            format!(
                "a verified caller registers sessions only under its own label: agent {n:?} is not {me:?}"
            ),
        ));
    }
    let label = acting_label(&ctx.caller, named.as_deref(), "agent")?;
    let kind = a.kind.trim().to_string();
    if kind.is_empty() || kind.len() > 64 {
        return Err(UaError::invalid("kind must be 1-64 characters"));
    }
    let meta = match a.meta {
        None | Some(Value::Null) => json!({}),
        Some(m @ Value::Object(_)) => m,
        Some(_) => return Err(UaError::invalid("meta must be a JSON object")),
    };
    let verified_self = verified(&ctx.caller).is_some();
    let org = ctx.caller.org_id.clone();
    let ext = clean(a.external_session_id.as_deref());
    let (worktree, branch, transcript, host) = (
        clean(a.worktree_path.as_deref()),
        clean(a.branch.as_deref()),
        clean(a.transcript_path.as_deref()),
        clean(a.host.as_deref()),
    );
    let (task_id, include_packet, recall) = (a.task_id, a.include_packet, a.recall_prior_packet);
    ctx.hub
        .db()
        .write_async(move |tx| {
            reap(tx)?;
            if let Some(tid) = task_id {
                let found = tx
                    .query_row("SELECT 1 FROM tasks WHERE org_id = ?1 AND id = ?2", params![org, tid], |_| Ok(()))
                    .optional()?;
                if found.is_none() {
                    return Err(UaError::not_found(format!("no task with id {tid}")));
                }
            }
            let existing: Option<(String, String)> = match &ext {
                Some(e) => tx
                    .query_row(
                        "SELECT id, status FROM agent_sessions WHERE agent = ?1 AND external_session_id = ?2 \
                         ORDER BY started_at DESC, id DESC LIMIT 1",
                        params![label, e],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?,
                None => None,
            };
            let now = ua_core::time::now();
            let (session_id, created, reopened_from) = match existing {
                Some((id, previous)) => {
                    tx.execute(
                        "UPDATE agent_sessions SET status = 'running', ended_at = NULL, exit_status = NULL, \
                         last_heartbeat_at = ?2, task_id = COALESCE(?3, task_id), \
                         worktree_path = COALESCE(?4, worktree_path), branch = COALESCE(?5, branch), \
                         transcript_path = COALESCE(?6, transcript_path), host = COALESCE(?7, host) WHERE id = ?1",
                        params![id, now, task_id, worktree, branch, transcript, host],
                    )?;
                    let reopened = (!is_open(&previous)).then_some(previous);
                    (id, false, reopened)
                }
                None => {
                    let host = match host.clone() {
                        Some(h) => Some(h),
                        None => tx
                            .query_row("SELECT host FROM agents WHERE label = ?1", [&label], |r| {
                                r.get::<_, Option<String>>(0)
                            })
                            .optional()?
                            .flatten(),
                    };
                    let id = ulid::Ulid::generate().to_string();
                    tx.execute(
                        "INSERT INTO agent_sessions (id, agent, kind, status, started_at, last_heartbeat_at, task_id, \
                         worktree_path, branch, external_session_id, transcript_path, host, meta) \
                         VALUES (?1, ?2, ?3, 'running', ?4, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                        params![
                            id,
                            label,
                            kind,
                            now,
                            task_id,
                            worktree,
                            branch,
                            ext,
                            transcript,
                            host,
                            meta.to_string()
                        ],
                    )?;
                    (id, true, None)
                }
            };
            touch_agent(tx, &label, "session_start", None, host.as_deref(), None, verified_self)?;
            if created {
                ledger::append(
                    tx,
                    EventInput::new(ua_core::DEFAULT_ORG,
                        "agent.session.started",
                        json!({
                            "session_id": session_id, "agent": label, "kind": kind, "task_id": task_id,
                            "branch": branch, "external_session_id": ext,
                        }),
                    )
                    .by(label.clone()),
                )?;
            } else if let Some(previous) = &reopened_from {
                ledger::append(
                    tx,
                    EventInput::new(ua_core::DEFAULT_ORG,
                        "agent.session.reopened",
                        json!({ "session_id": session_id, "agent": label, "previous_status": previous }),
                    )
                    .by(label.clone()),
                )?;
            }
            let row = get_session(tx, &org, &session_id)?.unwrap_or_else(|| json!({}));
            let mut out = json!({
                "session_id": session_id,
                "agent": label,
                "kind": row["kind"],
                "created": created,
                "reopened": reopened_from.is_some(),
                "status": row["status"],
                "host": row["host"],
                "task_id": row["task_id"],
                "last_seen_at": row["last_seen_at"],
                "live": row["live"],
            });
            if include_packet {
                out["packet"] = Value::Null;
                out["packet_unavailable"] = json!("session packets are not available in this hub");
            }
            if recall && let Some(tid) = task_id {
                let prior: Option<String> = tx
                    .query_row(
                        "SELECT id FROM agent_sessions WHERE task_id = ?1 AND id != ?2 \
                         ORDER BY started_at DESC, id DESC LIMIT 1",
                        params![tid, session_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                out["recalled_packet"] = Value::Null;
                out["recalled_from_session_id"] = json!(prior);
                out["packet_unavailable"] = json!("session packets are not available in this hub");
            }
            Ok(out)
        })
        .await
}

async fn session_end(ctx: ToolCtx, a: SessionEndArgs) -> UaResult<Value> {
    let status = a.status.as_deref().map(str::trim).unwrap_or("completed").to_string();
    if !matches!(status.as_str(), "completed" | "failed" | "abandoned") {
        return Err(UaError::invalid("status must be completed, failed or abandoned"));
    }
    let me = verified(&ctx.caller).map(str::to_string);
    let originator = ctx.caller.label.clone();
    let session_id = a.session_id.trim().to_string();
    let (exit_status, summary) = (clean(a.exit_status.as_deref()), clean(a.summary.as_deref()));
    ctx.hub
        .db()
        .write_async(move |tx| {
            let row: Option<(String, String, Option<i64>)> = tx
                .query_row(
                    "SELECT agent, status, task_id FROM agent_sessions WHERE id = ?1",
                    [&session_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((owner, previous, task_id)) = row else {
                return Err(UaError::not_found(format!("no such session: {session_id}")));
            };
            if let Some(me) = &me
                && me != &owner
            {
                return Err(UaError::denied(
                    "not_owner",
                    format!("session {session_id} is owned by {owner:?}; verified caller is {me:?}"),
                ));
            }
            let now = ua_core::time::now();
            tx.execute(
                "UPDATE agent_sessions SET status = ?2, ended_at = ?3, last_heartbeat_at = ?3, \
                 exit_status = COALESCE(?4, exit_status), summary = COALESCE(?5, summary) WHERE id = ?1",
                params![session_id, status, now, exit_status, summary],
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "agent.session.ended",
                    json!({
                        "session_id": session_id, "agent": owner, "status": status,
                        "previous_status": previous, "exit_status": exit_status, "task_id": task_id,
                    }),
                )
                .by(me.unwrap_or(originator)),
            )?;
            Ok(json!({
                "session_id": session_id,
                "agent": owner,
                "status": status,
                "previous_status": previous,
                "closed": true,
            }))
        })
        .await
}

async fn session_list(ctx: ToolCtx, a: SessionListArgs) -> UaResult<Value> {
    let status = clean(a.status.as_deref());
    if let Some(s) = &status
        && s != "open"
        && !SESSION_STATUSES.contains(&s.as_str())
    {
        return Err(UaError::invalid(format!(
            "status must be open or one of {}",
            SESSION_STATUSES.join(", ")
        )));
    }
    let agent = clean(a.agent.as_deref());
    let limit = a.limit.unwrap_or(50);
    let live_only = a.live_only;
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            reap(tx)?;
            let status = if live_only { Some("open".to_string()) } else { status };
            let sessions = list_sessions(tx, &org, agent.as_deref(), status.as_deref(), limit, live_only)?;
            let open = sessions.iter().filter(|s| s["status"].as_str().is_some_and(is_open)).count();
            let live = sessions.iter().filter(|s| s["live"] == json!(true)).count();
            let total = sessions.len();
            Ok(json!({ "sessions": sessions, "open": open, "live": live, "total": total }))
        })
        .await
}

/// Drop excluded keys at any depth.
fn strip_excluded(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(k, _)| !LIFECYCLE_EXCLUDED_KEYS.contains(&k.to_ascii_lowercase().as_str()))
                .map(|(k, v)| (k, strip_excluded(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(strip_excluded).collect()),
        other => other,
    }
}

async fn lifecycle_record(ctx: ToolCtx, a: LifecycleArgs) -> UaResult<Value> {
    let kind = a.kind.trim().to_string();
    if !LIFECYCLE_KINDS.contains(&kind.as_str()) {
        return Ok(json!({ "accepted": false, "reason": "unknown_kind" }));
    }
    let tool_name = clean(a.tool.as_deref());
    if tool_name.as_deref().is_some_and(|t| LIFECYCLE_EXCLUDED_TOOLS.contains(&t)) {
        return Ok(json!({ "accepted": false, "reason": "excluded" }));
    }
    let agent = acting_label(&ctx.caller, a.agent.as_deref(), "agent")?;
    let body = strip_excluded(Value::Object(a.payload.unwrap_or_default()));
    if body.to_string().len() > LIFECYCLE_MAX_PAYLOAD_BYTES {
        return Ok(json!({ "accepted": false, "reason": "payload_too_large" }));
    }
    let session_id = clean(a.session_id.as_deref());
    let task_id = a.task_id;
    let key = clean(a.idempotency_key.as_deref())
        .map(|k| format!("lifecycle:{}:{kind}:{k}", session_id.as_deref().unwrap_or("_")));
    // The key is the caller's organization's: another organization's use of
    // the same session id, kind and key is a fresh capture, never a replay.
    let org = ctx.caller.org_id.clone();
    let outcome = ctx
        .hub
        .db()
        .write_async(move |tx| {
            if let Some(k) = &key {
                let cached: Option<String> = tx
                    .query_row(
                        "SELECT result_json FROM idempotency_keys \
                         WHERE org_id = ?1 AND key = ?2 AND tool = 'lifecycle_record'",
                        [org.as_str(), k.as_str()],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(text) = cached {
                    let mut out: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({}));
                    out["duplicate"] = json!(true);
                    return Ok(out);
                }
            }
            let event = ledger::append(
                tx,
                EventInput {
                    channel: lifecycle_channel(&kind),
                    payload: json!({
                        "kind": kind, "session_id": session_id, "task_id": task_id,
                        "tool": tool_name, "payload": body,
                    }),
                    originator: Some(agent),
                    episode_id: session_id.clone(),
                    org_id: ua_core::DEFAULT_ORG.into(),
                    dedupe_key: None,
                    causal_parent_id: None,
                },
            )?
            .ok_or_else(|| UaError::internal("lifecycle event was not appended"))?;
            let out = json!({
                "accepted": true,
                "duplicate": false,
                "kind": kind,
                "session_id": session_id,
                "task_id": task_id,
                "event_id": event.ulid,
            });
            if let Some(k) = &key {
                tx.execute(
                    "INSERT INTO idempotency_keys (org_id, key, tool, result_json, created_at) \
                     VALUES (?1, ?2, 'lifecycle_record', ?3, ?4)",
                    params![org, k, out.to_string(), ua_core::time::now()],
                )?;
            }
            Ok(out)
        })
        .await;
    // Capture is fire-and-forget: a storage failure is reported, not raised.
    Ok(outcome.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "lifecycle_record capture failed");
        json!({ "accepted": false, "reason": "capture_failed" })
    }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "agent_heartbeat",
            "Declare that an agent is alive now. A verified caller's own label wins over `agent`. Returns {agent, recorded, host_recorded, status, known}.",
            heartbeat,
        )
        .family("agents"),
    );
    r.add(
        tool(
            "agent_list",
            "List agents with liveness derived at read time (online/idle/stale/offline, unknown when never seen), open session and active task counts. Returns {agents, counts, unregistered}.",
            agent_list,
        )
        .family("agents")
        .read_only(),
    );
    r.add(
        tool(
            "agent_context",
            "The verified caller's identity and profile, and each peer with its live sessions (pass a session_id as message_send(to_session=...) to reach that session alone). No tokens are returned.",
            agent_context,
        )
        .family("agents"),
    );
    r.add(
        tool(
            "session_start",
            "Open a session row and return its id. Idempotent on (agent, external_session_id): a repeat returns the same session_id with created=false, refreshes its heartbeat and reopens an ended row, so it doubles as a heartbeat.",
            session_start,
        )
        .family("agents"),
    );
    r.add(
        tool(
            "session_end",
            "Close a session: status completed (default), failed or abandoned. Only the owning agent may close it.",
            session_end,
        )
        .family("agents"),
    );
    r.add(
        tool(
            "session_list",
            "List sessions newest first, joined to their task. status takes a literal status or `open`; each row has `live` (open and seen within the live window); live_only returns only live ones. Stale sessions are reaped to abandoned first.",
            session_list,
        )
        .family("agents"),
    );
    r.add(
        tool(
            "lifecycle_record",
            "Record one sanitized lifecycle observation on agent.lifecycle.<kind> (kind handoff goes to agent.lifecycle.handoff_hook, readable only by its writer and note-reading operators). Unknown kinds, excluded tools and storage failures return {accepted: false, reason}. A repeated idempotency_key returns the first result. Transcripts, prompts and credentials in the payload are dropped.",
            lifecycle_record,
        )
        .family("agents"),
    );
}
