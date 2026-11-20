//! Observability: activity, metrics, performance, anomalies, the capability
//! doctor and MCP schema telemetry.
//!
//! Tools: `observability_manage` (actions `activity`, `metrics`, `anomalies`,
//! `performance`, `agents`, `context`, `delegation_stats`), the legacy standalone tools
//! `agent_activity`, `metrics_snapshot`, `perf_summary` and `check_anomalies`,
//! plus `system_doctor` and `mcp_health_telemetry`.
//!
//! Everything here reads existing rows and never writes: activity comes from
//! the ledger (`event_log`), performance from `tool_calls` (one row per
//! completed call, written by the registry wrapper), task health from `tasks`
//! and `approvals`, delegation stats from `delegations`. The family owns no tables.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, params_from_iter};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::time::{format_ts, parse_ts};
use ua_core::{Config, UaError, UaResult};
use ua_store::ledger;

use crate::families::agents::{self, AgentContextArgs, AgentListArgs};
use crate::families::nodes;
use crate::families::plans::parse_params;
use crate::registry::{Registry, ToolCtx, tool};

const ACTIVITY_LIMIT_CAP: i64 = 1000;
const PERF_WINDOW_HOURS_DEFAULT: f64 = 24.0;
/// Rows read for one percentile computation; older rows past this are ignored.
const PERF_ROW_CAP: usize = 500_000;

// Anomaly thresholds (the original hub's defaults).
const STALE_DOING_DAYS: i64 = 5;
const REVIEW_WAIT_HOURS: i64 = 2;
const REASSIGN_WINDOW_DAYS: i64 = 7;
const REASSIGN_MIN_CLAIMS: i64 = 3;
const NEVER_COMPLETES_MIN_CLAIMS: i64 = 3;
const APPROVAL_AGE_HOURS: i64 = 2;
const LOW_MEM_PERCENT: f64 = 15.0;
const TOOL_ERROR_MIN_CALLS: i64 = 20;
const TOOL_ERROR_RATE: f64 = 0.5;
/// WAL size past which the doctor reports a lagging checkpoint.
const WAL_WARN_BYTES: u64 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Shared helpers (also used by the evidence and export families).

/// Normalize a lower-bound timestamp argument to the storage form.
///
/// Accepts a date (`2026-07-10`, start of day UTC), an RFC 3339 timestamp, or
/// a naive `YYYY-MM-DDTHH:MM:SS` read as UTC.
pub(crate) fn normalize_since(field: &str, raw: &str) -> UaResult<String> {
    normalize_ts(field, raw, false)
}

/// Like [`normalize_since`], but a bare date means the end of that day.
pub(crate) fn normalize_until(field: &str, raw: &str) -> UaResult<String> {
    normalize_ts(field, raw, true)
}

fn normalize_ts(field: &str, raw: &str, end_of_day: bool) -> UaResult<String> {
    let s = raw.trim();
    if let Ok(d) = s.parse::<jiff::civil::Date>()
        && s.len() == 10
    {
        let time = if end_of_day { "23:59:59" } else { "00:00:00" };
        return Ok(format!("{d}T{time}+00:00"));
    }
    if let Some(ts) = parse_ts(s) {
        return Ok(format_ts(ts));
    }
    if let Ok(dt) = s.parse::<jiff::civil::DateTime>()
        && let Some(ts) = parse_ts(&format!("{dt}Z"))
    {
        return Ok(format_ts(ts));
    }
    Err(UaError::invalid(format!(
        "{field} must be an ISO-8601 date or timestamp (e.g. 2026-07-10 or 2026-07-10T00:00:00+00:00), got {raw:?}"
    )))
}

/// The ledger `kind` of a channel: `agent.task.updated` -> `task`.
pub(crate) fn channel_kind(channel: &str) -> String {
    let rest = channel.strip_prefix("agent.").unwrap_or(channel);
    rest.split('.').next().unwrap_or(rest).to_string()
}

/// The object a ledger payload is about, as text.
pub(crate) fn payload_ref(payload: &Value) -> Option<String> {
    const KEYS: [&str; 9] = [
        "task_id",
        "id",
        "note_id",
        "plan_id",
        "session_id",
        "delegation_id",
        "goal_id",
        "approval_id",
        "outbox_id",
    ];
    KEYS.iter().find_map(|k| match payload.get(*k)? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    })
}

/// Nearest-rank percentile of an ascending slice.
pub(crate) fn percentile(sorted: &[i64], p: f64) -> Option<i64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}

fn round(x: f64, places: i32) -> f64 {
    let f = 10f64.powi(places);
    (x * f).round() / f
}

fn rate(errors: i64, calls: i64) -> f64 {
    if calls == 0 { 0.0 } else { round(errors as f64 / calls as f64, 4) }
}

/// The database file and WAL sizes, in bytes (`None` in memory).
pub(crate) fn db_file_sizes(cfg_db: Option<&Path>) -> (Option<u64>, Option<u64>) {
    let Some(path) = cfg_db else { return (None, None) };
    let main = std::fs::metadata(path).ok().map(|m| m.len());
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let wal = std::fs::metadata(Path::new(&wal)).ok().map(|m| m.len());
    (main, wal)
}

fn pragma_i64(c: &Connection, name: &str) -> UaResult<i64> {
    Ok(c.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))?)
}

// ---------------------------------------------------------------------------
// agent_activity

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivityArgs {
    /// Exact agent label (the ledger originator).
    pub agent: Option<String>,
    /// ISO-8601 lower bound, e.g. `2026-07-10` or `2026-07-10T12:00:00+00:00`.
    pub since: Option<String>,
    /// Event kind: the ledger channel's noun, e.g. `task`, `memory`, `plan`.
    pub kind: Option<String>,
    /// Default 200, capped at 1000.
    pub limit: Option<i64>,
}

fn agent_activity(c: &Connection, a: ActivityArgs) -> UaResult<Value> {
    let mut sql =
        String::from("SELECT seq, originator, created_at, channel, payload FROM event_log WHERE 1=1");
    let mut args: Vec<String> = Vec::new();
    if let Some(agent) = a.agent.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        sql.push_str(" AND originator = ?");
        args.push(agent.to_string());
    }
    if let Some(since) = a.since.as_deref() {
        sql.push_str(" AND created_at >= ?");
        args.push(normalize_since("since", since)?);
    }
    if let Some(kind) = a.kind.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let prefix = format!("agent.{kind}.");
        sql.push_str(" AND (substr(channel, 1, length(?)) = ? OR channel = ?)");
        args.push(prefix.clone());
        args.push(prefix);
        args.push(format!("agent.{kind}"));
    }
    let capped = a.limit.unwrap_or(200).clamp(1, ACTIVITY_LIMIT_CAP);
    sql.push_str(&format!(" ORDER BY created_at DESC, seq DESC LIMIT {}", capped + 1));
    let mut stmt = c.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    let mut events = Vec::new();
    for row in rows {
        let (seq, agent, ts, channel, payload) = row?;
        let payload: Value = serde_json::from_str(&payload).unwrap_or(Value::Null);
        events.push(json!({
            "id": seq,
            "agent": agent,
            "ts": ts,
            "kind": channel_kind(&channel),
            "ref_id": payload_ref(&payload),
            "summary": channel,
        }));
    }
    let truncated = events.len() as i64 > capped;
    events.truncate(capped as usize);
    Ok(json!({ "events": events, "truncated": truncated }))
}

// ---------------------------------------------------------------------------
// metrics_snapshot

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

fn metrics_snapshot(c: &Connection, db_path: Option<&Path>) -> UaResult<Value> {
    let week = agents::ago(7 * 86_400);
    let mut events: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
    {
        let mut stmt = c.prepare(
            "SELECT COALESCE(originator, '(unattributed)'), channel, COUNT(*) FROM event_log \
             WHERE created_at >= ?1 GROUP BY 1, 2",
        )?;
        let rows = stmt.query_map([&week], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
        })?;
        for row in rows {
            let (agent, channel, n) = row?;
            *events.entry(agent).or_default().entry(channel_kind(&channel)).or_default() += n;
        }
    }
    let mut by_status = Map::new();
    {
        let mut stmt = c.prepare("SELECT status, COUNT(*) FROM tasks GROUP BY status")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (s, n) = row?;
            by_status.insert(s, json!(n));
        }
    }
    let mut cycle: Vec<f64> = Vec::new();
    {
        let mut stmt = c.prepare(
            "SELECT created_at, completed_at FROM tasks WHERE status = 'done' AND completed_at IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (created, completed) = row?;
            if let (Some(a), Some(b)) = (parse_ts(&created), parse_ts(&completed)) {
                cycle.push(((b.as_second() - a.as_second()) as f64 / 86_400.0).max(0.0));
            }
        }
    }
    let (calls, errors): (i64, i64) = c.query_row(
        "SELECT COUNT(*), COALESCE(SUM(outcome != 'ok'), 0) FROM tool_calls WHERE started_at >= ?1 AND page = 0",
        [&week],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let size = match db_file_sizes(db_path) {
        (Some(main), _) => main as i64,
        _ => pragma_i64(c, "page_count")? * pragma_i64(c, "page_size")?,
    };
    let stat = |f: fn(&[f64]) -> f64| if cycle.is_empty() { Value::Null } else { json!(round(f(&cycle), 3)) };
    Ok(json!({
        "generated_at": ua_core::time::now(),
        "events_last_7_days": events,
        "tasks_by_status": by_status,
        "done_task_cycle_days": {
            "count": cycle.len(),
            "avg": stat(|v| v.iter().sum::<f64>() / v.len() as f64),
            "min": stat(|v| v.iter().copied().fold(f64::INFINITY, f64::min)),
            "max": stat(|v| v.iter().copied().fold(0.0, f64::max)),
        },
        "tool_calls_last_7_days": { "calls": calls, "errors": errors, "error_rate": rate(errors, calls) },
        "db_size_bytes": size,
    }))
}

// ---------------------------------------------------------------------------
// perf_summary

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfArgs {
    /// Window in hours (default 24; non-positive values use the default).
    pub since_hours: Option<f64>,
}

#[derive(Default)]
struct Bucket {
    durations: Vec<i64>,
    errors: i64,
    outcomes: BTreeMap<String, i64>,
}

impl Bucket {
    fn add(&mut self, ms: i64, outcome: &str) {
        self.durations.push(ms);
        if outcome != "ok" {
            self.errors += 1;
        }
        *self.outcomes.entry(outcome.to_string()).or_default() += 1;
    }

    fn summary(mut self, with_outcomes: bool) -> Value {
        self.durations.sort_unstable();
        let d = &self.durations;
        let calls = d.len() as i64;
        let avg = if d.is_empty() {
            Value::Null
        } else {
            json!(round(d.iter().sum::<i64>() as f64 / d.len() as f64, 3))
        };
        let mut out = json!({
            "calls": calls,
            "errors": self.errors,
            "error_rate": rate(self.errors, calls),
            "avg_latency_ms": avg,
            "min_latency_ms": d.first(),
            "max_latency_ms": d.last(),
            "p50_latency_ms": percentile(d, 50.0),
            "p95_latency_ms": percentile(d, 95.0),
        });
        if with_outcomes {
            out["outcomes"] = json!(self.outcomes);
        }
        out
    }
}

/// Current resident set size of this process, where the OS exposes it.
fn rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

fn perf_summary(c: &Connection, a: PerfArgs) -> UaResult<Value> {
    let hours = a.since_hours.filter(|h| h.is_finite() && *h > 0.0).unwrap_or(PERF_WINDOW_HOURS_DEFAULT);
    let cutoff = agents::ago((hours * 3600.0).min(1e12) as i64);
    let mut stmt = c.prepare(
        "SELECT tool, caller, duration_ms, outcome FROM tool_calls WHERE started_at >= ?1 AND page = 0 \
         ORDER BY id DESC",
    )?;
    let rows = stmt.query_map([&cutoff], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?))
    })?;
    let mut by_tool: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut by_caller: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut total = Bucket::default();
    let mut capped = false;
    for (n, row) in rows.enumerate() {
        if n >= PERF_ROW_CAP {
            capped = true;
            break;
        }
        let (tool, caller, ms, outcome) = row?;
        by_tool.entry(tool).or_default().add(ms, &outcome);
        by_caller.entry(caller).or_default().add(ms, &outcome);
        total.add(ms, &outcome);
    }
    let rss = rss_bytes();
    Ok(json!({
        "window_hours": hours,
        "since": cutoff,
        "source": "tool_calls",
        "by_tool": by_tool.into_iter().map(|(k, b)| (k, b.summary(true))).collect::<Map<_, _>>(),
        "by_caller": by_caller.into_iter().map(|(k, b)| (k, b.summary(false))).collect::<Map<_, _>>(),
        "total": total.summary(true),
        "row_cap_reached": capped,
        "memory_rss_bytes": {
            "count": u64::from(rss.is_some()),
            "avg": rss, "min": rss, "max": rss, "latest": rss,
        },
    }))
}

// ---------------------------------------------------------------------------
// check_anomalies

fn anomaly(rule: &str, subject: String, detail: String, severity: &str) -> Value {
    json!({ "rule": rule, "subject": subject, "detail": detail, "severity": severity })
}

fn mem_available_percent() -> Option<(f64, u64, u64)> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let field = |name: &str| -> Option<u64> {
        text.lines().find(|l| l.starts_with(name))?.split_whitespace().nth(1)?.parse().ok()
    };
    let total = field("MemTotal:")?;
    let avail = field("MemAvailable:")?;
    (total > 0).then(|| (avail as f64 * 100.0 / total as f64, avail, total))
}

fn check_anomalies(c: &Connection) -> UaResult<Value> {
    let mut out: Vec<Value> = Vec::new();

    // stale_doing_task
    {
        let cutoff = agents::ago(STALE_DOING_DAYS * 86_400);
        let mut stmt = c.prepare(
            "SELECT id, title, updated_at, claimed_by FROM tasks \
             WHERE status = 'doing' AND archived_at IS NULL AND updated_at < ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([&cutoff], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?;
        for row in rows {
            let (id, title, updated, holder) = row?;
            out.push(anomaly(
                "stale_doing_task",
                format!("task:{id}"),
                format!(
                    "{title:?} has been doing since {updated} (over {STALE_DOING_DAYS} days), claimed by {}",
                    holder.as_deref().unwrap_or("nobody")
                ),
                "warning",
            ));
        }
    }

    // review_wait
    {
        let cutoff = agents::ago(REVIEW_WAIT_HOURS * 3600);
        let mut stmt = c.prepare(
            "SELECT id, updated_at FROM tasks WHERE status NOT IN ('done','cancelled') AND archived_at IS NULL \
             AND instr(COALESCE(notes, ''), '[waiting-for: review]') > 0 \
             AND instr(COALESCE(notes, ''), '[review:') = 0 AND updated_at < ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([&cutoff], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (id, updated) = row?;
            out.push(anomaly(
                "review_wait",
                format!("task:{id}"),
                format!("waiting for review with no outcome since {updated} (over {REVIEW_WAIT_HOURS} h)"),
                "warning",
            ));
        }
    }

    // Claims from the ledger: (task, agent, created_at), renewals excluded.
    let mut claims: Vec<(i64, String, String)> = Vec::new();
    {
        let mut stmt = c.prepare(
            "SELECT payload, COALESCE(originator, ''), created_at FROM event_log WHERE channel = 'agent.task.claimed'",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })?;
        for row in rows {
            let (payload, originator, at) = row?;
            let p: Value = serde_json::from_str(&payload).unwrap_or(Value::Null);
            if p.get("renewal").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let Some(task) = p.get("task_id").and_then(Value::as_i64) else { continue };
            let agent = p.get("agent").and_then(Value::as_str).map(str::to_string).unwrap_or(originator);
            claims.push((task, agent, at));
        }
    }
    let task_status = |id: i64| -> UaResult<Option<String>> {
        Ok(c.query_row("SELECT status FROM tasks WHERE id = ?1", [id], |r| r.get(0)).optional()?)
    };

    // task_reassignment_thrash
    {
        let cutoff = agents::ago(REASSIGN_WINDOW_DAYS * 86_400);
        let mut per_task: BTreeMap<i64, (i64, BTreeSet<String>)> = BTreeMap::new();
        for (task, agent, at) in &claims {
            if at.as_str() >= cutoff.as_str() {
                let e = per_task.entry(*task).or_default();
                e.0 += 1;
                e.1.insert(agent.clone());
            }
        }
        for (task, (n, agents_seen)) in per_task {
            let threshold =
                if agents_seen.len() >= 2 { REASSIGN_MIN_CLAIMS } else { REASSIGN_MIN_CLAIMS * 2 };
            if n < threshold {
                continue;
            }
            match task_status(task)?.as_deref() {
                Some("done") | Some("cancelled") | None => continue,
                _ => {}
            }
            out.push(anomaly(
                "task_reassignment_thrash",
                format!("task:{task}"),
                format!(
                    "claimed {n} times in {REASSIGN_WINDOW_DAYS} days by {}",
                    agents_seen.into_iter().collect::<Vec<_>>().join(", ")
                ),
                "warning",
            ));
        }
    }

    // agent_never_completes
    {
        let mut per_agent: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
        for (task, agent, _) in &claims {
            if !agent.is_empty() {
                per_agent.entry(agent.clone()).or_default().insert(*task);
            }
        }
        for (agent, tasks) in per_agent {
            if (tasks.len() as i64) < NEVER_COMPLETES_MIN_CLAIMS {
                continue;
            }
            let mut any_done = false;
            for t in &tasks {
                if task_status(*t)?.as_deref() == Some("done") {
                    any_done = true;
                    break;
                }
            }
            if !any_done {
                out.push(anomaly(
                    "agent_never_completes",
                    format!("agent:{agent}"),
                    format!("claimed {} distinct tasks and none is done", tasks.len()),
                    "warning",
                ));
            }
        }
    }

    // approval_queue_age
    {
        let cutoff = agents::ago(APPROVAL_AGE_HOURS * 3600);
        let (n, oldest): (i64, Option<String>) = c.query_row(
            "SELECT COUNT(*), MIN(created_at) FROM approvals WHERE status = 'pending' AND created_at < ?1",
            [&cutoff],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if n > 0 {
            out.push(anomaly(
                "approval_queue_age",
                "approvals:pending".into(),
                format!(
                    "{n} pending approval(s) older than {APPROVAL_AGE_HOURS} h; oldest since {}",
                    oldest.unwrap_or_default()
                ),
                "warning",
            ));
        }
    }

    // unverified_done
    {
        let mut stmt = c.prepare(
            "SELECT id FROM tasks WHERE status = 'done' AND archived_at IS NULL \
             AND instr(COALESCE(notes, ''), '[code-task]') > 0 \
             AND COALESCE(trim(evidence_ref), '') = '' \
             AND instr(COALESCE(notes, ''), '[review:') = 0 \
             AND instr(COALESCE(notes, ''), '[merged commit:') = 0 ORDER BY id",
        )?;
        let ids = stmt.query_map([], |r| r.get::<_, i64>(0))?;
        for id in ids {
            let id = id?;
            out.push(anomaly(
                "unverified_done",
                format!("task:{id}"),
                "a [code-task] reached done with no evidence_ref and no review or merge marker".into(),
                "warning",
            ));
        }
    }

    // tool_error_rate (from tool_calls, last 24 h)
    {
        let cutoff = agents::ago(86_400);
        let mut stmt = c.prepare(
            "SELECT tool, COUNT(*), SUM(outcome != 'ok') FROM tool_calls WHERE started_at >= ?1 AND page = 0 \
             GROUP BY tool HAVING COUNT(*) >= ?2 ORDER BY tool",
        )?;
        let rows = stmt.query_map(rusqlite::params![cutoff, TOOL_ERROR_MIN_CALLS], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
        })?;
        for row in rows {
            let (tool, calls, errors) = row?;
            let r = rate(errors, calls);
            if r >= TOOL_ERROR_RATE {
                out.push(anomaly(
                    "tool_error_rate",
                    format!("tool:{tool}"),
                    format!("{errors} of {calls} calls failed in the last 24 h ({:.0}%)", r * 100.0),
                    "warning",
                ));
            }
        }
    }

    // ledger_chain
    {
        let report = ledger::verify(c)?;
        if !report.ok {
            out.push(anomaly(
                "ledger_chain",
                "ledger:event_log".into(),
                format!(
                    "hash chain broken at seq {}: {}",
                    report.first_bad_seq.unwrap_or_default(),
                    report.reason.unwrap_or_default()
                ),
                "critical",
            ));
        }
    }

    // host_low_memory
    if let Some((pct, avail, total)) = mem_available_percent()
        && pct < LOW_MEM_PERCENT
    {
        out.push(anomaly(
            "host_low_memory",
            "host:memory".into(),
            format!("{pct:.1}% of RAM available ({avail} of {total} kB), below {LOW_MEM_PERCENT}%"),
            "warning",
        ));
    }

    Ok(json!({ "anomalies": out, "count": out.len(), "checked_at": ua_core::time::now() }))
}

// ---------------------------------------------------------------------------
// delegation_stats

const DELEGATION_WINDOW_DAYS_DEFAULT: f64 = 30.0;
/// Delegation rows read for one report; older rows past this are ignored.
const DELEGATION_ROW_CAP: usize = 100_000;

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegationStatsArgs {
    /// Only delegations this agent sent or received.
    pub agent: Option<String>,
    /// Window in days, counted back from now (default 30; non-positive values
    /// use the default). Ignored when `since` is given.
    pub window_days: Option<f64>,
    /// ISO-8601 lower bound on the delegation's `created_at`.
    pub since: Option<String>,
}

#[derive(Default)]
struct DelegationBucket {
    sent: i64,
    received: i64,
    by_state: BTreeMap<String, i64>,
    completion_secs: Vec<i64>,
    first_claim_secs: Vec<i64>,
}

fn secs_between(from: &str, to: Option<&str>) -> Option<i64> {
    let (a, b) = (parse_ts(from)?, parse_ts(to?)?);
    let d = b.as_second() - a.as_second();
    (d >= 0).then_some(d)
}

fn latency(mut v: Vec<i64>) -> Value {
    v.sort_unstable();
    let avg = (!v.is_empty()).then(|| round(v.iter().sum::<i64>() as f64 / v.len() as f64, 1));
    json!({
        "count": v.len(),
        "avg": avg,
        "p50": percentile(&v, 50.0),
        "p95": percentile(&v, 95.0),
        "max": v.last(),
    })
}

/// Per-agent delegation counts, states and latencies over a window, read
/// from the `delegations` table. Latencies are in seconds: `completion` from
/// creation to a terminal state (`completed_at`), `first_claim` from creation
/// to the claim of delegations claimed exactly once.
fn delegation_stats(c: &Connection, a: DelegationStatsArgs) -> UaResult<Value> {
    let now = Timestamp::now();
    let since = match a.since.as_deref() {
        Some(raw) => normalize_since("since", raw)?,
        None => {
            let days =
                a.window_days.filter(|d| d.is_finite() && *d > 0.0).unwrap_or(DELEGATION_WINDOW_DAYS_DEFAULT);
            let secs = (days * 86_400.0) as i64;
            format_ts(now.checked_sub(jiff::SignedDuration::from_secs(secs)).unwrap_or(now))
        }
    };
    let agent = a.agent.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let mut sql = String::from(
        "SELECT from_agent, to_agent, status, created_at, completed_at, attempts, last_attempt_at \
         FROM delegations WHERE created_at >= ?1",
    );
    let mut args = vec![since.clone()];
    if let Some(ag) = &agent {
        sql.push_str(" AND (from_agent = ?2 OR to_agent = ?2)");
        args.push(ag.clone());
    }
    sql.push_str(&format!(" ORDER BY created_at DESC LIMIT {}", DELEGATION_ROW_CAP + 1));
    let mut stmt = c.prepare(&sql)?;
    type DelegationRow = (String, String, String, String, Option<String>, i64, Option<String>);
    let mut rows: Vec<DelegationRow> = stmt
        .query_map(params_from_iter(args.iter()), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        })?
        .collect::<Result<_, _>>()?;
    let truncated = rows.len() > DELEGATION_ROW_CAP;
    rows.truncate(DELEGATION_ROW_CAP);

    let mut per_agent: BTreeMap<String, DelegationBucket> = BTreeMap::new();
    let mut pairs: BTreeMap<(String, String), BTreeMap<String, i64>> = BTreeMap::new();
    let mut states: BTreeMap<String, i64> =
        crate::families::delegation::DELEGATION_STATUSES.iter().map(|s| (s.to_string(), 0)).collect();
    for (from, to, status, created, completed, attempts, claimed) in &rows {
        *states.entry(status.clone()).or_default() += 1;
        per_agent.entry(from.clone()).or_default().sent += 1;
        let recv = per_agent.entry(to.clone()).or_default();
        recv.received += 1;
        *recv.by_state.entry(status.clone()).or_default() += 1;
        if matches!(status.as_str(), "completed" | "failed" | "cancelled")
            && let Some(d) = secs_between(created, completed.as_deref())
        {
            recv.completion_secs.push(d);
        }
        if *attempts == 1
            && let Some(d) = secs_between(created, claimed.as_deref())
        {
            recv.first_claim_secs.push(d);
        }
        *pairs.entry((from.clone(), to.clone())).or_default().entry(status.clone()).or_default() += 1;
    }
    let agents: Vec<Value> = per_agent
        .into_iter()
        .filter(|(label, _)| agent.as_ref().is_none_or(|a| a == label))
        .map(|(label, b)| {
            let count = |s: &str| b.by_state.get(s).copied().unwrap_or(0);
            let finished = count("completed") + count("failed") + count("cancelled");
            let rate = (finished > 0).then(|| round(count("completed") as f64 / finished as f64, 4));
            json!({
                "agent": label,
                "sent": b.sent,
                "received": b.received,
                "received_by_state": b.by_state,
                "open": count("pending") + count("in_flight"),
                "completion_rate": rate,
                "latency_seconds": {
                    "completion": latency(b.completion_secs),
                    "first_claim": latency(b.first_claim_secs),
                },
            })
        })
        .collect();
    let pairs: Vec<Value> = pairs
        .into_iter()
        .map(|((from, to), by_state)| {
            let total: i64 = by_state.values().sum();
            json!({ "from_agent": from, "to_agent": to, "total": total, "by_state": by_state })
        })
        .collect();
    Ok(json!({
        "window": { "since": since, "until": format_ts(now) },
        "agent": agent,
        "total": rows.len(),
        "truncated": truncated,
        "states": states,
        "agents": agents,
        "pairs": pairs,
    }))
}

// ---------------------------------------------------------------------------
// observability_manage

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManageArgs {
    /// One of activity, metrics, anomalies, performance, agents, context,
    /// delegation_stats. The underlying function names (agent_activity,
    /// metrics_snapshot, check_anomalies, perf_summary, agent_list,
    /// agent_context, delegation_ledger) are accepted too.
    pub action: String,
    /// The action's keyword arguments.
    pub params: Option<Value>,
}

const ACTIONS: [&str; 7] =
    ["activity", "metrics", "anomalies", "performance", "agents", "context", "delegation_stats"];

pub(crate) fn canonical_action(action: &str) -> UaResult<&'static str> {
    let a = action.trim().to_ascii_lowercase();
    let a = match a.as_str() {
        "agent_activity" => "activity",
        "metrics_snapshot" => "metrics",
        "check_anomalies" => "anomalies",
        "perf_summary" => "performance",
        "agent_list" => "agents",
        "agent_context" => "context",
        "delegation_ledger" => "delegation_stats",
        other => other,
    };
    ACTIONS.iter().find(|x| **x == a).copied().ok_or_else(|| {
        UaError::invalid(format!(
            "action must be one of {ACTIONS:?} (heartbeat, run and budget actions are not in this build)"
        ))
    })
}

async fn read<T: Send + 'static>(
    ctx: &ToolCtx,
    f: impl FnOnce(&Connection) -> UaResult<T> + Send + 'static,
) -> UaResult<T> {
    ctx.hub.db().read_async(f).await
}

async fn manage(ctx: ToolCtx, a: ManageArgs) -> UaResult<Value> {
    let act = canonical_action(&a.action)?;
    let p = a.params;
    match act {
        "activity" => {
            let args: ActivityArgs = parse_params("observability", act, p)?;
            read(&ctx, move |c| agent_activity(c, args)).await
        }
        "metrics" => {
            let _: NoArgs = parse_params("observability", act, p)?;
            let path = ctx.hub.db().path().map(Path::to_path_buf);
            read(&ctx, move |c| metrics_snapshot(c, path.as_deref())).await
        }
        "anomalies" => {
            let _: NoArgs = parse_params("observability", act, p)?;
            read(&ctx, check_anomalies).await
        }
        "performance" => {
            let args: PerfArgs = parse_params("observability", act, p)?;
            read(&ctx, move |c| perf_summary(c, args)).await
        }
        "agents" => {
            let args: AgentListArgs = parse_params("observability", act, p)?;
            agents::agent_list(ctx, args).await
        }
        "context" => {
            let args: AgentContextArgs = parse_params("observability", act, p)?;
            agents::agent_context(ctx, args).await
        }
        "delegation_stats" => {
            let args: DelegationStatsArgs = parse_params("observability", act, p)?;
            read(&ctx, move |c| delegation_stats(c, args)).await
        }
        other => Err(UaError::invalid(format!("unknown observability action {other:?}"))),
    }
}

// ---------------------------------------------------------------------------
// system_doctor

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorArgs {
    /// Run the slower probes too (SQLite `quick_check`). Every report is
    /// computed fresh; there is no shared cache.
    #[serde(default)]
    pub refresh: bool,
}

const LIVE: &str = "LIVE";
const DORMANT: &str = "DORMANT";
const DEGRADED: &str = "DEGRADED";
const MISCONFIGURED: &str = "MISCONFIGURED";
const UNKNOWN: &str = "UNKNOWN";

fn finding(capability: &str, status: &str, detail: impl Into<String>, gate: &str) -> Value {
    json!({ "capability": capability, "status": status, "detail": detail.into(), "gate": gate })
}

/// What the doctor reads from the database in one pass.
struct DbFacts {
    journal_mode: String,
    page_count: i64,
    page_size: i64,
    freelist: i64,
    applied_parts: BTreeMap<String, String>,
    chain: ledger::VerifyReport,
    notes: i64,
    embedded: i64,
    active_tokens: i64,
    last_delivery: Option<(String, Option<String>)>,
    quick_check: Option<String>,
    /// Registered nodes, or why they could not be read.
    fleet: Result<nodes::Fleet, String>,
}

fn db_facts(c: &Connection, deep: bool) -> UaResult<DbFacts> {
    let mut applied = BTreeMap::new();
    {
        let mut stmt = c.prepare("SELECT name, checksum FROM schema_parts")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (n, s) = row?;
            applied.insert(n, s);
        }
    }
    let count = |sql: &str| -> UaResult<i64> { Ok(c.query_row(sql, [], |r| r.get(0)).unwrap_or(0)) };
    let last_delivery = c
        .query_row("SELECT status, last_error FROM notify_outbox ORDER BY id DESC LIMIT 1", [], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
        })
        .optional()
        .unwrap_or(None);
    let quick_check =
        if deep { Some(c.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))?) } else { None };
    Ok(DbFacts {
        journal_mode: c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?,
        page_count: pragma_i64(c, "page_count")?,
        page_size: pragma_i64(c, "page_size")?,
        freelist: pragma_i64(c, "freelist_count")?,
        applied_parts: applied,
        chain: ledger::verify(c)?,
        notes: count("SELECT COUNT(*) FROM memory")?,
        embedded: count("SELECT COUNT(*) FROM memory_embeddings e JOIN memory m ON m.id = e.note_id")?,
        active_tokens: count("SELECT COUNT(*) FROM agent_tokens WHERE status = 'active'")?,
        last_delivery,
        quick_check,
        fleet: nodes::fleet(c, Timestamp::now()).map_err(|e| e.to_string()),
    })
}

#[cfg(unix)]
fn writable(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else { return false };
    // SAFETY: `c` is a valid NUL-terminated path; access(2) only reads it.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(not(unix))]
fn writable(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| !m.permissions().readonly()).unwrap_or(false)
}

fn env_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

fn hub_auth_check(cfg: &Config, facts: &DbFacts) -> Value {
    let static_tokens = cfg.static_tokens().len();
    let issued = facts.active_tokens;
    let any = static_tokens > 0 || issued > 0;
    let detail = format!(
        "enforce_auth={}; static tokens configured: {static_tokens}; active issued tokens: {issued}; humans configured: {}",
        cfg.enforce_auth,
        cfg.human_identities.len()
    );
    let status = match (cfg.enforce_auth, any) {
        (true, true) => LIVE,
        (true, false) => MISCONFIGURED,
        (false, true) => DEGRADED,
        (false, false) => DORMANT,
    };
    finding("hub_auth", status, detail, "UA_ENFORCE_AUTH, UA_AGENT_TOKENS")
}

fn bind_check(cfg: &Config) -> Value {
    let loopback = cfg.bind.ip().is_loopback();
    let (status, detail) = match (loopback, cfg.enforce_auth) {
        (true, _) => (LIVE, format!("listening on loopback port {}", cfg.bind.port())),
        (false, true) => {
            (LIVE, format!("listening beyond loopback on port {} with auth enforced", cfg.bind.port()))
        }
        (false, false) => (
            MISCONFIGURED,
            format!("listening beyond loopback on port {} without enforced auth", cfg.bind.port()),
        ),
    };
    finding("http_bind", status, detail, "UA_BIND, UA_ENFORCE_AUTH")
}

fn approval_check(cfg: &Config, reg: &Registry) -> Value {
    let always: Vec<&str> = reg.all().filter(|t| t.always_gated).map(|t| t.name).collect();
    let unknown: Vec<&str> =
        cfg.approval_tools.iter().map(String::as_str).filter(|t| reg.get(t).is_none()).collect();
    let configured = cfg.approval_tools.len();
    let mut detail = format!("{configured} configured gated tool(s); {} always-gated tool(s)", always.len());
    let status = if configured == 0 && always.is_empty() {
        DORMANT
    } else if cfg.human_identities.is_empty() {
        detail.push_str("; no human identities are configured, so nobody can resolve an approval");
        MISCONFIGURED
    } else if !unknown.is_empty() {
        detail.push_str(&format!("; not registered here: {}", unknown.join(", ")));
        DEGRADED
    } else if configured == 0 {
        detail.push_str("; only the built-in always-gated tools are gated");
        LIVE
    } else {
        LIVE
    };
    finding("approval_gating", status, detail, "UA_APPROVAL_TOOLS, UA_HUMAN_IDENTITIES")
}

fn vault_check(cfg: &Config) -> Value {
    let gate = "UA_VAULT_PATH, UA_VAULT_WRITE_DIRS";
    let Some(vault) = &cfg.vault_path else {
        return finding("vault", DORMANT, "no vault path is configured", gate);
    };
    if !vault.is_dir() {
        return finding(
            "vault",
            MISCONFIGURED,
            "the configured vault path is not a directory on this host",
            gate,
        );
    }
    let mut missing = Vec::new();
    let mut readonly = Vec::new();
    for d in &cfg.vault_write_dirs {
        let p = vault.join(d);
        if !p.is_dir() {
            missing.push(d.as_str());
        } else if !writable(&p) {
            readonly.push(d.as_str());
        }
    }
    let n = cfg.vault_write_dirs.len();
    if !readonly.is_empty() {
        finding("vault", MISCONFIGURED, format!("write dirs not writable: {}", readonly.join(", ")), gate)
    } else if n == 0 {
        finding("vault", DEGRADED, "vault is readable; no write directories are configured", gate)
    } else if !missing.is_empty() {
        finding(
            "vault",
            DEGRADED,
            format!("write dirs missing (created on first write): {}", missing.join(", ")),
            gate,
        )
    } else {
        finding("vault", LIVE, format!("vault readable; {n} write dir(s) present and writable"), gate)
    }
}

fn workspace_check(cfg: &Config) -> Value {
    let gate = "UA_WORKSPACE, UA_AGENT_WORKSPACES";
    let root = cfg.workspace_root();
    let denied = cfg.agent_workspaces.values().filter(|v| v.trim().eq_ignore_ascii_case("deny")).count();
    let missing = cfg
        .agent_workspaces
        .values()
        .filter(|v| !v.trim().eq_ignore_ascii_case("deny"))
        .filter(|v| {
            let raw = v.trim();
            let p = match raw.strip_prefix("~/").zip(std::env::var_os("HOME")) {
                Some((rest, home)) => Path::new(&home).join(rest),
                None => Path::new(raw).to_path_buf(),
            };
            !p.is_dir()
        })
        .count();
    let bindings = format!("{} per-agent binding(s), {denied} deny", cfg.agent_workspaces.len());
    if !root.is_dir() {
        let status = if cfg.workspace.is_some() { MISCONFIGURED } else { DORMANT };
        return finding("workspace_root", status, format!("workspace root does not exist; {bindings}"), gate);
    }
    if missing > 0 {
        return finding(
            "workspace_root",
            DEGRADED,
            format!("workspace root present; {missing} per-agent root(s) missing; {bindings}"),
            gate,
        );
    }
    let w = if writable(&root) { "writable" } else { "read-only" };
    let status = if w == "writable" { LIVE } else { DEGRADED };
    finding("workspace_root", status, format!("workspace root present and {w}; {bindings}"), gate)
}

fn search_check(reg: &Registry) -> Value {
    let gate = "UA_SEARCH_PROVIDER, BRAVE_API_KEY, TAVILY_API_KEY";
    if reg.get("web_search").is_none() {
        return finding("search_provider", DORMANT, "web search tools are not part of this build", gate);
    }
    let brave = env_set("BRAVE_API_KEY");
    let tavily = env_set("TAVILY_API_KEY");
    let named = std::env::var("UA_SEARCH_PROVIDER").ok().filter(|s| !s.trim().is_empty());
    let resolved = match named.as_deref().map(str::trim) {
        Some("brave") if brave => Some("brave"),
        Some("tavily") if tavily => Some("tavily"),
        Some(other) if other != "brave" && other != "tavily" => Some("other"),
        Some(_) => None,
        None if brave => Some("brave"),
        None if tavily => Some("tavily"),
        None => None,
    };
    match (named.is_some(), resolved) {
        (_, Some(p)) => finding("search_provider", LIVE, format!("provider resolves to {p}"), gate),
        (true, None) => finding("search_provider", MISCONFIGURED, "named provider has no API key set", gate),
        (false, None) => finding("search_provider", DORMANT, "no provider key is set", gate),
    }
}

fn embeddings_check(facts: &DbFacts) -> Value {
    let gate = "cargo feature `embeddings`, UA_EMBED_MODEL";
    if !ua_memory::EMBEDDINGS_ENABLED {
        return finding(
            "semantic_search",
            DORMANT,
            "built without the `embeddings` feature; memory search is lexical (FTS5) only",
            gate,
        );
    }
    let missing = facts.notes - facts.embedded;
    if facts.notes == 0 {
        finding("semantic_search", DORMANT, "no memory notes to embed yet", gate)
    } else if missing > 0 {
        finding(
            "semantic_search",
            MISCONFIGURED,
            format!("{missing} of {} notes have no embedding", facts.notes),
            gate,
        )
    } else {
        finding(
            "semantic_search",
            UNKNOWN,
            format!("all {} notes are embedded; model readiness in this process is unverified", facts.notes),
            gate,
        )
    }
}

fn ledger_check(facts: &DbFacts) -> Value {
    let c = &facts.chain;
    let gate = "event_log";
    if !c.ok {
        return finding(
            "ledger_chain",
            DEGRADED,
            format!(
                "hash chain broken at seq {}: {}",
                c.first_bad_seq.unwrap_or_default(),
                c.reason.clone().unwrap_or_default()
            ),
            gate,
        );
    }
    if c.checked == 0 {
        let text = if c.unhashed_legacy_prefix > 0 {
            format!("only {} imported legacy (unhashed) rows; nothing hashed yet", c.unhashed_legacy_prefix)
        } else {
            "the ledger is empty".to_string()
        };
        return finding("ledger_chain", DORMANT, text, gate);
    }
    finding(
        "ledger_chain",
        LIVE,
        format!("{} entries verify ({} unhashed legacy prefix)", c.checked, c.unhashed_legacy_prefix),
        gate,
    )
}

fn database_check(facts: &DbFacts, path: Option<&Path>) -> (Value, Value) {
    let (main, wal) = db_file_sizes(path);
    let mut detail = format!(
        "journal_mode={}; {} pages of {} bytes; {} free pages",
        facts.journal_mode, facts.page_count, facts.page_size, facts.freelist
    );
    if let Some(m) = main {
        detail.push_str(&format!("; file {m} bytes"));
    }
    if let Some(w) = wal {
        detail.push_str(&format!("; WAL {w} bytes"));
    }
    let mut status = LIVE;
    if path.is_none() {
        detail.push_str("; in-memory database");
    } else if !facts.journal_mode.eq_ignore_ascii_case("wal") {
        status = DEGRADED;
        detail.push_str("; expected WAL mode");
    } else if wal.unwrap_or(0) > WAL_WARN_BYTES {
        status = DEGRADED;
        detail.push_str("; WAL is large, checkpoints may be lagging");
    }
    if let Some(q) = &facts.quick_check {
        if q != "ok" {
            status = MISCONFIGURED;
        }
        detail.push_str(&format!("; quick_check={q}"));
    }
    let stats = json!({
        "file_bytes": main,
        "wal_bytes": wal,
        "page_count": facts.page_count,
        "page_size": facts.page_size,
        "freelist_count": facts.freelist,
        "journal_mode": facts.journal_mode,
        "quick_check": facts.quick_check,
    });
    (finding("database", status, detail, "UA_DB_PATH"), stats)
}

fn schema_check(facts: &DbFacts) -> Value {
    let expected = crate::schema_parts();
    let mut missing = Vec::new();
    let mut drifted = Vec::new();
    for part in &expected {
        let sum = hex::encode(Sha256::digest(part.sql.as_bytes()));
        match facts.applied_parts.get(part.name) {
            None => missing.push(part.name),
            Some(s) if *s != sum => drifted.push(part.name),
            Some(_) => {}
        }
    }
    let known: BTreeSet<&str> = expected.iter().map(|p| p.name).collect();
    let extra = facts.applied_parts.keys().filter(|k| !known.contains(k.as_str())).count();
    let gate = "schema_parts";
    if !missing.is_empty() {
        finding("schema", MISCONFIGURED, format!("schema parts not applied: {}", missing.join(", ")), gate)
    } else if !drifted.is_empty() {
        finding(
            "schema",
            DEGRADED,
            format!("applied parts differ from this build: {}", drifted.join(", ")),
            gate,
        )
    } else {
        let note = if extra > 0 { format!("; {extra} part(s) from another build") } else { String::new() };
        finding("schema", LIVE, format!("all {} schema parts applied{note}", expected.len()), gate)
    }
}

fn notify_check(cfg: &Config, facts: &DbFacts) -> Value {
    let gate = "UA_NOTIFY_WEBHOOK_URL, UA_NOTIFY_WEBHOOK_SECRET";
    let Some(raw) = cfg.notify_webhook_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return finding(
            "notify_webhook",
            DORMANT,
            "no webhook URL is configured; notifications stay in the outbox",
            gate,
        );
    };
    // Webhook URLs often embed a credential in their path: report only scheme and host.
    let Ok(url) = reqwest::Url::parse(raw) else {
        return finding("notify_webhook", MISCONFIGURED, "the webhook URL does not parse", gate);
    };
    let host = url.host_str().unwrap_or("").to_string();
    let loopback = host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
    let secret = cfg.notify_webhook_secret.is_some();
    let base = format!("{}://{host}; secret header configured: {secret}", url.scheme());
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => {
            return finding("notify_webhook", DEGRADED, format!("{base}; plain http to a remote host"), gate);
        }
        _ => return finding("notify_webhook", MISCONFIGURED, "the webhook URL must be http or https", gate),
    }
    match &facts.last_delivery {
        Some((status, _)) if status == "failed" => {
            finding("notify_webhook", DEGRADED, format!("{base}; the last delivery failed"), gate)
        }
        _ => finding("notify_webhook", LIVE, base, gate),
    }
}

/// Zulip: DORMANT until site, email and key are all set; the API key's value
/// is never read here beyond whether it is present.
fn zulip_check(cfg: &Config) -> Value {
    use secrecy::ExposeSecret;

    use crate::families::zulip;
    let gate = "UA_ZULIP_SITE, UA_ZULIP_EMAIL, UA_ZULIP_API_KEY, UA_ZULIP_RETIRED, zulip_channels";
    let set = |v: Option<&str>| v.is_some_and(|s| !s.trim().is_empty());
    let site = set(cfg.zulip_site.as_deref());
    let email = set(cfg.zulip_email.as_deref());
    let key = cfg.zulip_api_key.as_ref().is_some_and(|k| !k.expose_secret().trim().is_empty());
    match (site, email, key) {
        (false, false, false) => {
            return finding(
                "zulip",
                DORMANT,
                "Zulip is not configured; zulip_* tools refuse every call",
                gate,
            );
        }
        (true, true, true) => {}
        _ => {
            return finding(
                "zulip",
                MISCONFIGURED,
                "zulip_site, zulip_email and UA_ZULIP_API_KEY must all be set",
                gate,
            );
        }
    }
    let raw = cfg.zulip_site.as_deref().unwrap_or("");
    let Ok(url) = zulip::parse_site(raw, cfg.fetch_allow_loopback) else {
        return finding(
            "zulip",
            MISCONFIGURED,
            "zulip_site must be an https URL without credentials, a query or a fragment",
            gate,
        );
    };
    let host = url.host_str().unwrap_or("");
    let channels = zulip::channels(cfg).len();
    let send = if zulip::zulip_retired(cfg.zulip_retired.as_deref()) {
        "send retired"
    } else {
        "send open behind a human approval per message"
    };
    finding(
        "zulip",
        LIVE,
        format!("{host}; {channels} channel(s); {send}; {} link host(s) allowed", cfg.zulip_link_hosts.len()),
        gate,
    )
}

fn policy_check(cfg: &Config) -> Value {
    let gate = "UA_POLICY_FILE";
    match &cfg.policy_file {
        None => finding("policy_file", DORMANT, "no policy file is configured", gate),
        Some(p) if p.is_file() => finding("policy_file", LIVE, "policy file present", gate),
        Some(_) => finding("policy_file", MISCONFIGURED, "the configured policy file does not exist", gate),
    }
}

/// `90s`, `12m`, `3h`, `2d`.
fn human_age(secs: i64) -> String {
    match secs.max(0) {
        s if s < 120 => format!("{s}s"),
        s if s < 7200 => format!("{}m", s / 60),
        s if s < 172_800 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

/// Registered remote nodes: LIVE when every node in service is live,
/// DEGRADED naming the ones that are not, DORMANT when none is registered.
/// Retired nodes are not hosts; they are named once and never change the status.
fn fleet_nodes_check(facts: &DbFacts) -> Value {
    let gate = "node_register / node_heartbeat (POST /api/node/*)";
    let fleet = match &facts.fleet {
        Ok(f) => f,
        Err(e) => {
            return finding("fleet_nodes", UNKNOWN, format!("cannot read the node registry: {e}"), gate);
        }
    };
    let now = Timestamp::now().as_second();
    let describe = |n: &nodes::FleetNode| match n.last_heartbeat.as_deref().and_then(parse_ts) {
        Some(beat) if beat.as_second() > now => {
            format!(
                "{} {} (heartbeat stamped {} in the future)",
                n.node,
                n.status,
                human_age(beat.as_second() - now)
            )
        }
        Some(beat) => {
            format!("{} {} (last heartbeat {} ago)", n.node, n.status, human_age(now - beat.as_second()))
        }
        None => format!("{} {} (no readable heartbeat)", n.node, n.status),
    };
    let live: Vec<&str> =
        fleet.active.iter().filter(|n| n.status == "live").map(|n| n.node.as_str()).collect();
    let down: Vec<String> = fleet.active.iter().filter(|n| n.status != "live").map(describe).collect();
    let mut parts = Vec::new();
    let status = if fleet.active.is_empty() {
        parts.push("no node registered".to_string());
        DORMANT
    } else if down.is_empty() {
        parts.push(format!("{} node(s) live: {}", live.len(), live.join(", ")));
        LIVE
    } else {
        parts.extend(down);
        if !live.is_empty() {
            parts.push(format!("live: {}", live.join(", ")));
        }
        DEGRADED
    };
    if !fleet.retired.is_empty() {
        parts.push(format!(
            "{} retired node row(s) excluded: {}",
            fleet.retired.len(),
            fleet.retired.join(", ")
        ));
    }
    let mut row = finding("fleet_nodes", status, parts.join("; "), gate);
    row["hosts"] = fleet
        .active
        .iter()
        .map(|n| json!({ "node": n.node, "state": n.status, "last_heartbeat": n.last_heartbeat }))
        .collect();
    if !fleet.retired.is_empty() {
        row["retired"] = json!(fleet.retired);
    }
    row
}

fn host_name() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

async fn system_doctor(ctx: ToolCtx, a: DoctorArgs) -> UaResult<Value> {
    let clock = std::time::Instant::now();
    let deep = a.refresh;
    let facts = ctx.hub.db().read_async(move |c| db_facts(c, deep)).await?;
    let org = ctx.hub.db().read_async(super::org::registry_health).await?;
    let org_status = if org.live { LIVE } else { MISCONFIGURED };
    let cfg = ctx.hub.cfg();
    let reg = crate::builtin_registry_shared();
    let path = ctx.hub.db().path();
    let (db_row, db_stats) = database_check(&facts, path);
    let checks = vec![
        hub_auth_check(cfg, &facts),
        bind_check(cfg),
        approval_check(cfg, reg),
        vault_check(cfg),
        workspace_check(cfg),
        search_check(reg),
        embeddings_check(&facts),
        ledger_check(&facts),
        db_row,
        schema_check(&facts),
        notify_check(cfg, &facts),
        zulip_check(cfg),
        policy_check(cfg),
        fleet_nodes_check(&facts),
        finding("org_registry", org_status, org.detail, "org registry"),
        finding("edition", LIVE, format!("edition {}", cfg.edition), "UA_EDITION"),
    ];
    let mut summary: BTreeMap<String, i64> = ["live", "dormant", "degraded", "misconfigured", "unknown"]
        .iter()
        .map(|k| (k.to_string(), 0))
        .collect();
    for c in &checks {
        if let Some(s) = c["status"].as_str() {
            *summary.entry(s.to_ascii_lowercase()).or_default() += 1;
        }
    }
    Ok(json!({
        "checks": checks,
        "summary": summary,
        "host": host_name(),
        "as_of": ua_core::time::now(),
        "cached": false,
        "refreshing": false,
        "deep_checks": deep,
        "run_duration_s": round(clock.elapsed().as_secs_f64(), 3),
        "database": db_stats,
        "build": {
            "name": "ua-rust",
            "version": env!("CARGO_PKG_VERSION"),
            "features": { "embeddings": ua_memory::EMBEDDINGS_ENABLED },
            "tool_count": reg.len(),
        },
    }))
}

// ---------------------------------------------------------------------------
// mcp_health_telemetry

/// Version 1: tool names plus required and optional argument keys, 16 hex.
pub(crate) fn schema_fingerprint<'a>(tools: impl Iterator<Item = &'a crate::ToolDef>) -> String {
    let mut lines: Vec<String> = tools
        .map(|t| {
            let required: BTreeSet<String> = t.input_schema["required"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let all: BTreeSet<String> = t.input_schema["properties"]
                .as_object()
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            let optional: Vec<&String> = all.difference(&required).collect();
            let required: Vec<&String> = required.iter().collect();
            format!(
                "{}:{}|{}",
                t.name,
                required.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","),
                optional.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
            )
        })
        .collect();
    lines.sort();
    hex::encode(Sha256::digest(lines.join("\n").as_bytes()))[..16].to_string()
}

/// Version 2: names plus the full canonical input schemas, full SHA-256.
pub(crate) fn semantic_fingerprint<'a>(tools: impl Iterator<Item = &'a crate::ToolDef>) -> String {
    let mut entries: Vec<(String, String)> =
        tools.map(|t| (t.name.to_string(), ua_core::canonical::to_string(&t.input_schema))).collect();
    entries.sort();
    let mut h = Sha256::new();
    for (name, schema) in entries {
        h.update(name.as_bytes());
        h.update([0u8]);
        h.update(schema.as_bytes());
        h.update(*b"\n");
    }
    hex::encode(h.finalize())
}

fn call_counts(c: &Connection) -> UaResult<Value> {
    let day = agents::ago(86_400);
    let (total, last_call): (i64, Option<String>) =
        c.query_row("SELECT COUNT(*), MAX(started_at) FROM tool_calls WHERE page = 0", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let (calls, errors): (i64, i64) = c.query_row(
        "SELECT COUNT(*), COALESCE(SUM(outcome != 'ok'), 0) FROM tool_calls WHERE started_at >= ?1 AND page = 0",
        [&day],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut by_transport = Map::new();
    {
        let mut stmt = c.prepare(
            "SELECT transport, COUNT(*), SUM(outcome != 'ok') FROM tool_calls WHERE started_at >= ?1 AND page = 0 \
             GROUP BY transport ORDER BY transport",
        )?;
        let rows = stmt
            .query_map([&day], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))?;
        for row in rows {
            let (t, n, e) = row?;
            by_transport.insert(t, json!({ "calls": n, "errors": e }));
        }
    }
    let mut top = Vec::new();
    {
        let mut stmt = c.prepare(
            "SELECT tool, COUNT(*), SUM(outcome != 'ok') FROM tool_calls WHERE started_at >= ?1 AND page = 0 \
             GROUP BY tool ORDER BY COUNT(*) DESC, tool LIMIT 20",
        )?;
        let rows = stmt
            .query_map([&day], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))?;
        for row in rows {
            let (t, n, e) = row?;
            top.push(json!({ "tool": t, "calls": n, "errors": e }));
        }
    }
    Ok(json!({
        "total_calls": total,
        "last_call_at": last_call,
        "last_24h": { "calls": calls, "errors": errors, "error_rate": rate(errors, calls) },
        "by_transport_24h": by_transport,
        "top_tools_24h": top,
    }))
}

async fn mcp_health_telemetry(ctx: ToolCtx, _a: NoArgs) -> UaResult<Value> {
    let reg = crate::builtin_registry_shared();
    let calls = ctx.hub.db().read_async(call_counts).await?;
    let callable = || reg.visible_to(&ctx.caller);
    let callable_count = callable().count();
    let schema = schema_fingerprint(callable());
    let semantic = semantic_fingerprint(callable());
    let calls_24 = calls["last_24h"]["calls"].as_i64().unwrap_or(0);
    let rate_24 = calls["last_24h"]["error_rate"].as_f64().unwrap_or(0.0);
    let status =
        if calls_24 >= TOOL_ERROR_MIN_CALLS && rate_24 >= TOOL_ERROR_RATE { "degraded" } else { "healthy" };
    Ok(json!({
        "status": status,
        "server": { "name": "ua-rust", "version": env!("CARGO_PKG_VERSION") },
        "profile": ctx.caller.profile.as_str(),
        "profile_enforced": ctx.caller.enforce_profile,
        "transport": ctx.caller.transport,
        "tool_count": reg.len(),
        "callable_tool_count": callable_count,
        "schema_fingerprint": schema,
        "manifest_schema_fingerprint": schema,
        "registry_schema_fingerprint": schema_fingerprint(reg.all()),
        "semantic_schema_fingerprint_version": 2,
        "semantic_schema_fingerprint": semantic,
        "manifest_semantic_schema_fingerprint": semantic,
        "registry_semantic_schema_fingerprint": semantic_fingerprint(reg.all()),
        "calls": calls,
        "checked_at": Timestamp::now().to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Registration.

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "observability_manage",
            "Agent visibility, metrics, anomalies and performance in one tool. action: activity (ledger activity, \
             newest first), metrics (cluster snapshot), anomalies (deterministic health rules), performance \
             (p50/p95 latency and error rates per tool and caller from tool_calls), agents (agent_list), \
             context (agent_context), delegation_stats (params agent, window_days, since: per-agent delegation \
             counts sent and received, states, completion rate, and completion and first-claim latencies in \
             seconds, plus per-pair state counts). `params` holds the action's arguments. Read-only.",
            manage,
        )
        .family("observability")
        .read_only(),
    );
    r.add(
        tool(
            "agent_activity",
            "Ledger activity newest first, filtered by agent label, since (ISO-8601) and kind (the channel noun: \
             task, memory, plan...). limit defaults to 200, max 1000. Returns {events: [{id, agent, ts, kind, \
             ref_id, summary}], truncated}.",
            |ctx: ToolCtx, a: ActivityArgs| async move { read(&ctx, move |c| agent_activity(c, a)).await },
        )
        .family("observability")
        .read_only(),
    );
    r.add(
        tool(
            "metrics_snapshot",
            "Cluster snapshot: per-agent ledger event counts by kind for the last 7 days, tasks by status, \
             done-task cycle time in days, tool-call totals and the database size.",
            |ctx: ToolCtx, _a: NoArgs| async move {
                let path = ctx.hub.db().path().map(Path::to_path_buf);
                read(&ctx, move |c| metrics_snapshot(c, path.as_deref())).await
            },
        )
        .family("observability")
        .read_only(),
    );
    r.add(
        tool(
            "perf_summary",
            "Latency and error rates from tool_calls over the last since_hours (default 24): per tool (calls, \
             errors, error_rate, avg/min/max/p50/p95 latency in ms, outcome codes), per caller, and in total.",
            |ctx: ToolCtx, a: PerfArgs| async move { read(&ctx, move |c| perf_summary(c, a)).await },
        )
        .family("observability")
        .read_only(),
    );
    r.add(
        tool(
            "check_anomalies",
            "Run the deterministic anomaly rules (no LLM): stale_doing_task, review_wait, \
             task_reassignment_thrash, agent_never_completes, approval_queue_age, unverified_done, \
             tool_error_rate, ledger_chain, host_low_memory. Returns {anomalies: [{rule, subject, detail, \
             severity}]}; empty when healthy.",
            |ctx: ToolCtx, _a: NoArgs| async move { read(&ctx, check_anomalies).await },
        )
        .family("observability")
        .read_only(),
    );
    r.add(
        tool(
            "system_doctor",
            "Read-only LIVE/DORMANT/DEGRADED/MISCONFIGURED/UNKNOWN report over every config-gated capability of \
             this build: hub auth and token sources, HTTP bind, approval gating, vault, workspace root, search \
             provider, semantic search (embeddings feature), ledger chain, database size and WAL, schema parts, \
             notification webhook, policy file and the org registry. Each finding names the setting that gates it. Never returns \
             secret values. refresh=true adds SQLite quick_check.",
            system_doctor,
        )
        .family("observability")
        .read_only(),
    );
    r.add(
        tool(
            "mcp_health_telemetry",
            "Tool-surface health: schema_fingerprint (16 hex over the callable tools' names and argument keys; \
             re-list tools when it changes), registry and semantic (full input-schema) fingerprints, tool counts, \
             and tool-call counts and error rates from tool_calls. No secrets.",
            mcp_health_telemetry,
        )
        .family("observability")
        .read_only(),
    );
}
