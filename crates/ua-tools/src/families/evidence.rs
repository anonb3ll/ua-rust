//! Evidence reports and state consistency checks.
//!
//! Tools: `evidence_report`, `evidence_append` and `state_sync_verify`.
//!
//! `evidence_append` is the canonical writer for client evidence: one ledger
//! event on an `sdk.` channel, attributed to the verified caller (never to a
//! label in the body), deduplicated per caller by an optional key.
//!
//! Client evidence is budgeted per identity per rolling hour
//! (`evidence_append_max_per_hour`, `evidence_append_max_bytes_per_hour`),
//! counted from the ledger itself so a restart does not reset it.
//!
//! `evidence_report` assembles, per task, the ledger events that mention it
//! (with their hashes), the task row, its approvals and delegations, and the
//! tool calls its participants made inside the task's lifetime, plus the
//! ledger's chain verification. Tool calls carry no task id, so they are
//! attributed by window and caller, and labelled as such.
//!
//! An `sdk.` event is whatever its client wrote, `task_id` included, so it
//! never attributes a task, makes a participant or counts as proof. Events
//! that name a task are listed apart under the record's `client_asserted`
//! section, flagged as client assertions, with their payloads marked
//! untrusted.
//!
//! `state_sync_verify` compares every external-content FTS5 index with its
//! base table, lists dangling references (`PRAGMA foreign_key_check` plus
//! `memory.superseded_by`) and verifies the ledger. A drifted index is rebuilt
//! and the result reports `resynced`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use rusqlite::{Connection, OptionalExtension, ToSql, params_from_iter};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{ActorKind, UaError, UaResult};
use ua_store::{EventInput, ledger};

use crate::families::events::{EventReader, VISIBLE_MESSAGE};
use crate::families::injection::mark_untrusted;
use crate::families::observability::{normalize_since, normalize_until};
use crate::families::plans::row_map;
use crate::families::platform::object_ref;
use crate::registry::{Registry, ToolCtx, tool};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 500;
const UNATTRIBUTED: &str = "unattributed";
const COVERAGE_THRESHOLD: f64 = 0.95;
pub const REPORT_SCHEMA_VERSION: &str = "ua-rust.1";

type Re = LazyLock<Option<Regex>>;

static PR_RE: Re = LazyLock::new(|| Regex::new(r"https://github\.com/[^\s/]+/[^\s/]+/pull/\d+").ok());
static SHA_RE: Re = LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{7,40}\b").ok());
static NOTE_SHA_RE: Re = LazyLock::new(|| Regex::new(r"(?i)\b(?:SHA|commit):\s*([0-9a-f]{7,40})\b").ok());
static MERGED_RE: Re =
    LazyLock::new(|| Regex::new(r"(?i)\[review:\s*(?:merged|merged-upstream)\b|\[merged commit:").ok());
static CONTENT_RE: Re = LazyLock::new(|| Regex::new(r"content\s*=\s*'([A-Za-z0-9_]+)'").ok());
static ROWID_RE: Re = LazyLock::new(|| Regex::new(r"content_rowid\s*=\s*'([A-Za-z0-9_]+)'").ok());

/// The first match of `re` in `text`.
fn first<'t>(re: &Re, text: &'t str) -> Option<&'t str> {
    re.as_ref()?.find(text).map(|m| m.as_str())
}

/// The first capture group of `re` in `text`.
fn group<'t>(re: &Re, text: &'t str) -> Option<&'t str> {
    re.as_ref()?.captures(text)?.get(1).map(|m| m.as_str())
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportArgs {
    /// Only this task.
    pub task_id: Option<i64>,
    /// A project root task (its notes carry `[project-spec]`): report its whole
    /// subtree and add a `project_chain` summary.
    pub project_id: Option<i64>,
    /// ISO lower bound: a task matches when created, updated or completed after it.
    pub since: Option<String>,
    /// ISO upper bound (a bare date means the end of that day).
    pub until: Option<String>,
    /// Agent label: the claimant, a `claimed-by:` note, or a ledger originator on the task
    /// (client `sdk.` events do not count).
    pub agent: Option<String>,
    /// Project stream name.
    pub project: Option<String>,
    /// PR URL or commit SHA fragment matched in evidence_ref or notes.
    pub pr: Option<String>,
    /// Records to return (default 50, 500 with project_id; max 500).
    pub limit: Option<i64>,
    /// Node dispatch item (`nd-<16 hex>` or `node:<node>:<item>`). This build
    /// has no node dispatch, so a valid item yields no records.
    pub item: Option<String>,
}

fn chain_integrity(c: &Connection) -> UaResult<Value> {
    let report = ledger::verify(c)?;
    let head: Option<(String, String)> = c
        .query_row(
            "SELECT entry_hash, ulid FROM event_log WHERE entry_hash IS NOT NULL ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let status = if !report.ok {
        "tampered"
    } else if report.checked == 0 {
        "empty"
    } else {
        "valid"
    };
    Ok(json!({
        "status": status,
        "verified": report.ok && report.checked > 0,
        "head_hash": head.as_ref().map(|h| &h.0),
        "head_ulid": head.as_ref().map(|h| &h.1),
        "total_verified": report.checked,
        "unhashed_legacy_prefix": report.unhashed_legacy_prefix,
        "first_bad_seq": report.first_bad_seq,
        "reason": report.reason,
    }))
}

fn valid_item(item: &str) -> bool {
    let s = item.trim();
    if let Some(hex) = s.strip_prefix("nd-") {
        return hex.len() == 16 && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    parts.len() == 3 && parts[0] == "node" && !parts[1].is_empty() && !parts[2].is_empty()
}

/// `[project-spec]` that is not inside backticks.
fn has_project_marker(notes: &str) -> bool {
    notes.match_indices("[project-spec]").any(|(i, _)| !notes[..i].ends_with('`'))
}

fn merge_claim(notes: &str, pr_url: Option<&str>) -> Value {
    if !MERGED_RE.as_ref().is_some_and(|r| r.is_match(notes)) {
        return json!({ "status": "none", "source": "none", "verified": false, "conflict": false });
    }
    let note_prs: BTreeSet<String> = PR_RE
        .as_ref()
        .map(|r| r.find_iter(notes).map(|m| m.as_str().to_string()).collect())
        .unwrap_or_default();
    let conflict = pr_url.is_some_and(|p| !note_prs.is_empty() && !note_prs.contains(p));
    json!({
        "status": if conflict { "conflict" } else { "inferred" },
        "source": "task.notes",
        "verified": false,
        "conflict": conflict,
        "reported_pr_url": pr_url,
        "note_pr_urls": note_prs,
    })
}

fn proof(task: &Map<String, Value>, events: &[Value], chain_ok: bool) -> Value {
    let s = |k: &str| task.get(k).and_then(Value::as_str);
    let evidence_ref = s("evidence_ref");
    let notes = s("notes").unwrap_or("");
    let mut pr_url = evidence_ref.and_then(|e| first(&PR_RE, e)).map(str::to_string);
    // A SHA is looked for outside the PR URL, so the PR number is never taken for one.
    let mut sha = evidence_ref
        .map(|e| PR_RE.as_ref().map(|r| r.replace_all(e, "").into_owned()).unwrap_or_else(|| e.to_string()))
        .and_then(|e| first(&SHA_RE, &e).map(str::to_string));
    if pr_url.is_none() {
        pr_url = first(&PR_RE, notes).map(str::to_string);
    }
    if sha.is_none() {
        sha = group(&NOTE_SHA_RE, notes).map(str::to_string);
    }
    let hashes: Vec<Value> = events
        .iter()
        .filter(|e| !e["entry_hash"].is_null())
        .map(|e| {
            json!({
                "ulid": e["ulid"], "channel": e["channel"], "created_at": e["created_at"],
                "entry_hash": e["entry_hash"], "prev_hash": e["prev_hash"],
            })
        })
        .collect();
    json!({
        "evidence_ref": evidence_ref,
        "pr_url": pr_url,
        "commit_sha": sha,
        "merge_verified": false,
        "merge_claim": merge_claim(notes, pr_url.as_deref()),
        "created_at": s("created_at"),
        "updated_at": s("updated_at"),
        "completed_at": s("completed_at"),
        "tamper_evident": chain_ok && !hashes.is_empty(),
        "events_count": events.len(),
        "event_hashes": hashes,
    })
}

/// Rows of `sql` with one bound list of task ids, grouped by the first column.
fn grouped(
    c: &Connection,
    sql: &str,
    ids: &[i64],
    extra: &[&dyn ToSql],
) -> UaResult<BTreeMap<i64, Vec<Map<String, Value>>>> {
    let marks = vec!["?"; ids.len()].join(",");
    let sql = sql.replace("{ids}", &marks);
    let mut stmt = c.prepare(&sql)?;
    let params = ids.iter().map(|id| id as &dyn ToSql).chain(extra.iter().copied());
    let rows = stmt.query_map(params_from_iter(params), row_map)?;
    let mut out: BTreeMap<i64, Vec<Map<String, Value>>> = BTreeMap::new();
    for row in rows {
        let mut m = row?;
        let key = m.remove("_task").and_then(|v| v.as_i64()).unwrap_or_default();
        out.entry(key).or_default().push(m);
    }
    Ok(out)
}

fn tool_call_window(c: &Connection, callers: &BTreeSet<String>, since: &str, until: &str) -> UaResult<Value> {
    if callers.is_empty() {
        return Ok(json!({
            "attribution": "caller_and_window",
            "window": { "since": since, "until": until },
            "callers": [], "total": 0, "errors": 0, "by_tool": {},
        }));
    }
    let marks = vec!["?"; callers.len()].join(",");
    let sql = format!(
        "SELECT tool, COUNT(*), SUM(outcome != 'ok') FROM tool_calls \
         WHERE caller IN ({marks}) AND started_at >= ? AND started_at <= ? AND page = 0 GROUP BY tool ORDER BY tool"
    );
    let mut args: Vec<String> = callers.iter().cloned().collect();
    args.push(since.to_string());
    args.push(until.to_string());
    let mut stmt = c.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
    })?;
    let (mut total, mut errors) = (0i64, 0i64);
    let mut by_tool = Map::new();
    for row in rows {
        let (t, n, e) = row?;
        total += n;
        errors += e;
        by_tool.insert(t, json!({ "calls": n, "errors": e }));
    }
    Ok(json!({
        "attribution": "caller_and_window",
        "window": { "since": since, "until": until },
        "callers": callers,
        "total": total,
        "errors": errors,
        "by_tool": by_tool,
    }))
}

/// The `client_asserted` section of one record: `sdk.` events whose
/// payload names the task. Listed, never counted as attribution or proof.
fn client_asserted(rows: &[Map<String, Value>]) -> Value {
    let events: Vec<Value> = rows
        .iter()
        .take(CLIENT_EVENTS_CAP)
        .map(|row| {
            let mut e = row.clone();
            let inline =
                e.remove("payload").and_then(|p| p.as_str().and_then(|s| serde_json::from_str(s).ok()));
            e.insert("payload_inline".into(), json!(inline.is_some()));
            e.insert("payload".into(), inline.unwrap_or(Value::Null));
            let ulid = e.get("ulid").and_then(Value::as_str).unwrap_or_default().to_string();
            e.insert("platform".into(), json!(object_ref("evidence_event", &ulid)));
            let originator = e.get("originator").and_then(Value::as_str).map(str::to_string);
            let mut v = Value::Object(e);
            mark_untrusted(&mut v, CLIENT_EVIDENCE_SOURCE, originator.as_deref());
            v
        })
        .collect();
    json!({
        "asserted_by": "client",
        "verified": false,
        "counts_as_attribution": false,
        "note": "sdk. events written through evidence_append; their task_id is the client's claim",
        "total": rows.len(),
        "truncated": rows.len() > CLIENT_EVENTS_CAP,
        "events": events,
    })
}

fn build_report(
    c: &Connection,
    a: &ReportArgs,
    org: &str,
    caller_label: &str,
    verified_caller: bool,
    reader: &EventReader,
) -> UaResult<Value> {
    let since = a.since.as_deref().map(|s| normalize_since("since", s)).transpose()?;
    let until = a.until.as_deref().map(|s| normalize_until("until", s)).transpose()?;
    if let Some(item) = &a.item
        && !valid_item(item)
    {
        return Err(UaError::invalid("item must be nd-<16 hex> or node:<node>:<item>"));
    }
    let limit = match a.limit {
        Some(n) if n >= 1 => n.min(MAX_LIMIT),
        _ if a.project_id.is_some() => MAX_LIMIT,
        _ => DEFAULT_LIMIT,
    };
    let chain = chain_integrity(c)?;
    let chain_ok = chain["verified"].as_bool().unwrap_or(false);

    if let Some(pid) = a.project_id {
        let notes: Option<Option<String>> =
            c.query_row("SELECT notes FROM tasks WHERE id = ?1", [pid], |r| r.get(0)).optional()?;
        let Some(notes) = notes else { return Err(UaError::not_found(format!("no task with id {pid}"))) };
        if !has_project_marker(notes.as_deref().unwrap_or("")) {
            return Err(UaError::invalid(format!("task {pid} does not carry [project-spec]")));
        }
    }

    let mut sql = String::new();
    let mut args: Vec<&dyn ToSql> = Vec::new();
    let visibility = reader.bindings();
    let claimed_by_marker = a.agent.as_ref().map(|agent| format!("claimed-by: {agent}"));
    if let Some(pid) = &a.project_id {
        sql.push_str(
            "WITH RECURSIVE sub(id, depth, path) AS (SELECT id, 0, printf('%020d', id) FROM tasks WHERE id = ? \
             UNION ALL SELECT t.id, s.depth + 1, s.path || '.' || printf('%020d', t.id) \
             FROM tasks t JOIN sub s ON t.parent_id = s.id) \
             SELECT tasks.*, sub.depth AS project_depth FROM tasks JOIN sub ON sub.id = tasks.id WHERE 1=1",
        );
        args.push(pid);
    } else {
        sql.push_str("SELECT tasks.*, NULL AS project_depth FROM tasks WHERE 1=1");
    }
    if a.item.is_some() {
        sql.push_str(" AND 0");
    }
    if let Some(t) = &a.task_id {
        sql.push_str(" AND tasks.id = ?");
        args.push(t);
    }
    if let Some(p) = &a.project {
        sql.push_str(" AND tasks.project = ?");
        args.push(p);
    }
    if let Some(agent) = &a.agent {
        sql.push_str(&format!(
            " AND (tasks.claimed_by = ? OR instr(COALESCE(tasks.notes, ''), ?) > 0 OR EXISTS (\
             SELECT 1 FROM event_log WHERE originator = ? AND NOT (channel >= 'sdk.' AND channel < 'sdk/') \
             AND json_valid(payload) AND CAST(json_extract(payload, '$.task_id') AS INTEGER) = tasks.id \
             AND ({VISIBLE_MESSAGE})))",
        ));
        args.extend([agent as &dyn ToSql, &claimed_by_marker, agent]);
        args.extend(visibility);
    }
    if since.is_some() || until.is_some() {
        let mut clauses = Vec::new();
        for col in ["created_at", "updated_at", "completed_at"] {
            let mut parts = vec![format!("tasks.{col} IS NOT NULL")];
            if let Some(s) = &since {
                parts.push(format!("tasks.{col} >= ?"));
                args.push(s);
            }
            if let Some(u) = &until {
                parts.push(format!("tasks.{col} <= ?"));
                args.push(u);
            }
            clauses.push(format!("({})", parts.join(" AND ")));
        }
        sql.push_str(&format!(" AND ({})", clauses.join(" OR ")));
    }
    if let Some(pr) = &a.pr {
        sql.push_str(" AND (instr(COALESCE(tasks.evidence_ref, ''), ?) > 0 OR instr(COALESCE(tasks.notes, ''), ?) > 0)");
        args.extend([pr as &dyn ToSql, pr]);
    }
    sql.push_str(if a.project_id.is_some() { " ORDER BY sub.path" } else { " ORDER BY tasks.id DESC" });
    sql.push_str(&format!(" LIMIT {}", limit + 1));

    let mut tasks: Vec<Map<String, Value>> = {
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), row_map)?;
        rows.collect::<Result<_, _>>()?
    };
    let truncated = tasks.len() as i64 > limit;
    tasks.truncate(limit as usize);
    let ids: Vec<i64> = tasks.iter().filter_map(|t| t.get("id").and_then(Value::as_i64)).collect();

    let (events, client_events, approvals, delegations) = if ids.is_empty() {
        Default::default()
    } else {
        (
            grouped(
                c,
                &format!(
                    "SELECT CAST(json_extract(payload, '$.task_id') AS INTEGER) AS _task, seq, ulid, channel, \
                     originator, created_at, prev_hash, entry_hash FROM event_log WHERE json_valid(payload) \
                     AND NOT (channel >= 'sdk.' AND channel < 'sdk/') \
                     AND CAST(json_extract(payload, '$.task_id') AS INTEGER) IN ({{ids}}) \
                     AND ({VISIBLE_MESSAGE}) ORDER BY seq"
                ),
                &ids,
                &visibility,
            )?,
            grouped(
                c,
                &format!(
                    "SELECT CAST(json_extract(payload, '$.task_id') AS INTEGER) AS _task, seq, ulid, channel, \
                     originator, created_at, entry_hash, length(CAST(payload AS BLOB)) AS payload_bytes, \
                     CASE WHEN length(CAST(payload AS BLOB)) <= {CLIENT_PAYLOAD_INLINE} THEN payload END \
                     AS payload FROM event_log WHERE channel >= 'sdk.' AND channel < 'sdk/' \
                     AND json_valid(payload) AND CAST(json_extract(payload, '$.task_id') AS INTEGER) IN ({{ids}}) \
                     ORDER BY seq"
                ),
                &ids,
                &[],
            )?,
            grouped(
                c,
                "SELECT CAST(COALESCE(json_extract(payload, '$.task_id'), json_extract(payload, '$.parent_task_id')) \
                 AS INTEGER) AS _task, id, tool, status, requested_by, resolved_by, reason, created_at, resolved_at \
                 FROM approvals WHERE json_valid(payload) AND CAST(COALESCE(json_extract(payload, '$.task_id'), \
                 json_extract(payload, '$.parent_task_id')) AS INTEGER) IN ({ids}) AND org_id = ? ORDER BY id",
                &ids,
                // Only the reader's organization's approvals.
                &[&org],
            )?,
            grouped(
                c,
                "SELECT task_id AS _task, id, from_agent, to_agent, status, created_at, completed_at \
                 FROM delegations WHERE task_id IN ({ids}) ORDER BY id",
                &ids,
                &[],
            )?,
        )
    };

    let now = ua_core::time::now();
    let mut records = Vec::new();
    for task in &tasks {
        let id = task.get("id").and_then(Value::as_i64).unwrap_or_default();
        let s = |k: &str| task.get(k).and_then(Value::as_str).map(str::to_string);
        let evs: Vec<Value> =
            events.get(&id).cloned().unwrap_or_default().into_iter().map(Value::Object).collect();
        let apps = approvals.get(&id).cloned().unwrap_or_default();
        let asserted = client_asserted(client_events.get(&id).map(Vec::as_slice).unwrap_or_default());
        let dels = delegations.get(&id).cloned().unwrap_or_default();

        let claim_originator = evs
            .iter()
            .rev()
            .find(|e| e["channel"] == "agent.task.claimed")
            .and_then(|e| e["originator"].as_str().map(str::to_string));
        let creator = evs
            .iter()
            .find(|e| e["channel"] == "agent.task.created")
            .and_then(|e| e["originator"].as_str().map(str::to_string));
        let agent =
            s("claimed_by").or(claim_originator).or(creator).unwrap_or_else(|| UNATTRIBUTED.to_string());

        let mut participants: BTreeSet<String> =
            evs.iter().filter_map(|e| e["originator"].as_str().map(str::to_string)).collect();
        if agent != UNATTRIBUTED {
            participants.insert(agent.clone());
        }
        for d in &dels {
            if let Some(to) = d.get("to_agent").and_then(Value::as_str) {
                participants.insert(to.to_string());
            }
        }
        let window_since = s("created_at").unwrap_or_default();
        let window_until = s("completed_at").unwrap_or_else(|| now.clone());
        let calls = tool_call_window(c, &participants, &window_since, &window_until)?;

        let human = apps
            .iter()
            .filter(|a| matches!(a.get("status").and_then(Value::as_str), Some("approved" | "consumed")))
            .find_map(|a| a.get("resolved_by").and_then(Value::as_str).map(str::to_string));
        records.push(json!({
            "task_id": id,
            "project": s("project"),
            "human": human,
            "human_provenance": {
                "value": human,
                "source": if human.is_some() { "approvals.resolved_by" } else { "none" },
                "verified": false,
            },
            "device": s("source_host").unwrap_or_else(|| UNATTRIBUTED.to_string()),
            "agent": agent,
            "participants": participants,
            "action": {
                "type": "task",
                "title": s("title"),
                "status": s("status"),
                "priority": s("priority"),
                "lane": s("lane"),
                "parent_id": task.get("parent_id"),
                "project_depth": task.get("project_depth"),
                "approvals": apps,
            },
            "delegations": dels,
            "proof": proof(task, &evs, chain_ok),
            "events": evs,
            "client_asserted": asserted,
            "tool_calls": calls,
        }));
    }

    let project_chain = a.project_id.map(|pid| {
        let done: Vec<&Value> =
            records.iter().filter(|r| r["task_id"] != pid && r["action"]["status"] == "done").collect();
        let evidence: Vec<Value> = done
            .iter()
            .filter(|r| {
                ["evidence_ref", "pr_url", "commit_sha"].iter().any(|k| !r["proof"][k].is_null())
                    || r["proof"]["events_count"].as_u64().unwrap_or(0) > 0
            })
            .map(|r| {
                json!({
                    "task_id": r["task_id"],
                    "evidence_ref": r["proof"]["evidence_ref"],
                    "pr_url": r["proof"]["pr_url"],
                    "commit_sha": r["proof"]["commit_sha"],
                    "merge_verified": false,
                    "completed_at": r["proof"]["completed_at"],
                })
            })
            .collect();
        json!({
            "project_id": pid,
            // Merges cannot be verified against a forge in this build.
            "status": "partial",
            "task_ids": records.iter().map(|r| r["task_id"].clone()).collect::<Vec<_>>(),
            "done_task_ids": done.iter().map(|r| r["task_id"].clone()).collect::<Vec<_>>(),
            "evidence": evidence,
            "merged_prs": [],
            "last_merge": null,
        })
    });

    let attributed = records.iter().filter(|r| r["agent"] != UNATTRIBUTED).count();
    let ratio = if records.is_empty() { None } else { Some(attributed as f64 / records.len() as f64) };
    let gate = match ratio {
        None => "no_data",
        Some(r) if r >= COVERAGE_THRESHOLD => "pass",
        Some(_) => "fail",
    };
    let mut gate_failures = Vec::new();
    if !chain_ok {
        gate_failures.push("evidence_chain_integrity");
    }
    if gate == "fail" {
        gate_failures.push("attribution_coverage");
    }
    let next_cursor = if truncated { ids.last().copied() } else { None };
    Ok(json!({
        "report_type": "user_attributable_evidence",
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": ua_core::time::now(),
        "chain_integrity": chain,
        "attestation": {
            "generated_by": caller_label,
            "credential_verified": verified_caller,
            "signed": false,
        },
        "filter": {
            "task_id": a.task_id, "project_id": a.project_id, "since": since, "until": until,
            "agent": a.agent, "project": a.project, "pr": a.pr, "limit": limit, "item": a.item,
        },
        "total_records": records.len(),
        "records": records,
        "truncated": truncated,
        "next_cursor": next_cursor,
        "project_chain": project_chain,
        "attribution_coverage": {
            "attributed": attributed,
            "total": records.len(),
            "ratio": ratio,
            "threshold": COVERAGE_THRESHOLD,
            "gate": gate,
        },
        "gate_failures": gate_failures,
        "clean_pass": chain_ok && gate == "pass",
    }))
}

async fn evidence_report(ctx: ToolCtx, a: ReportArgs) -> UaResult<Value> {
    let label = ctx.caller.label.clone();
    let verified = matches!(ctx.caller.kind, ActorKind::Agent | ActorKind::Human);
    let reader = EventReader::new(ctx.hub.cfg(), &ctx.caller);
    let org = ctx.caller.org_id.clone();
    ctx.hub.db().read_async(move |c| build_report(c, &a, &org, &label, verified, &reader)).await
}

// ---------------------------------------------------------------------------
// state_sync_verify

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyArgs {}

/// An external-content FTS5 index and the table it mirrors.
struct FtsIndex {
    name: String,
    content: String,
    rowid: String,
}

fn fts_indexes(c: &Connection) -> UaResult<Vec<FtsIndex>> {
    let mut stmt =
        c.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'table' AND sql LIKE '%USING fts5%'")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (name, sql) = row?;
        let sql = sql.unwrap_or_default();
        let Some(content) = group(&CONTENT_RE, &sql).map(str::to_string) else { continue };
        if content.is_empty() || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
            continue;
        }
        let rowid = group(&ROWID_RE, &sql).unwrap_or("rowid").to_string();
        out.push(FtsIndex { name, content, rowid });
    }
    Ok(out)
}

fn fts_check(c: &Connection, ix: &FtsIndex) -> UaResult<Value> {
    let count = |sql: String| -> UaResult<i64> { Ok(c.query_row(&sql, [], |r| r.get(0))?) };
    let (n, t, k) = (&ix.name, &ix.content, &ix.rowid);
    let base = count(format!("SELECT COUNT(*) FROM \"{t}\""))?;
    let indexed = count(format!("SELECT COUNT(*) FROM \"{n}_docsize\""))?;
    let orphans = count(format!(
        "SELECT COUNT(*) FROM \"{n}_docsize\" d WHERE NOT EXISTS (SELECT 1 FROM \"{t}\" b WHERE b.\"{k}\" = d.id)"
    ))?;
    let missing = count(format!(
        "SELECT COUNT(*) FROM \"{t}\" b WHERE NOT EXISTS (SELECT 1 FROM \"{n}_docsize\" d WHERE d.id = b.\"{k}\")"
    ))?;
    Ok(json!({
        "index": n,
        "table": t,
        "table_rows": base,
        "indexed_rows": indexed,
        "missing_from_index": missing,
        "orphaned_in_index": orphans,
        "in_sync": missing == 0 && orphans == 0 && base == indexed,
    }))
}

fn dangling(c: &Connection) -> UaResult<Value> {
    let mut by_ref: BTreeMap<String, i64> = BTreeMap::new();
    {
        let mut stmt = c.prepare("PRAGMA foreign_key_check")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(2)?)))?;
        for row in rows {
            let (table, parent) = row?;
            *by_ref.entry(format!("{table}->{parent}")).or_default() += 1;
        }
    }
    let superseded: i64 = c.query_row(
        "SELECT COUNT(*) FROM memory m WHERE m.superseded_by IS NOT NULL AND m.superseded_by != '' \
         AND NOT EXISTS (SELECT 1 FROM memory s WHERE s.id = m.superseded_by)",
        [],
        |r| r.get(0),
    )?;
    if superseded > 0 {
        by_ref.insert("memory.superseded_by->memory".into(), superseded);
    }
    let total: i64 = by_ref.values().sum();
    Ok(json!({ "total": total, "by_reference": by_ref }))
}

async fn state_sync_verify(ctx: ToolCtx, _a: VerifyArgs) -> UaResult<Value> {
    let (fts, refs, chain, counts) = ctx
        .hub
        .db()
        .read_async(|c| {
            let fts: Vec<Value> = fts_indexes(c)?.iter().map(|ix| fts_check(c, ix)).collect::<UaResult<_>>()?;
            let counts: (i64, i64) = (
                c.query_row(
                    "SELECT COUNT(*) FROM memory WHERE id NOT LIKE 'masterindex%' AND id NOT LIKE 'tagindex_%'",
                    [],
                    |r| r.get(0),
                )?,
                c.query_row("SELECT COUNT(*) FROM tasks", [], |r| r.get(0))?,
            );
            Ok((fts, dangling(c)?, chain_integrity(c)?, counts))
        })
        .await?;
    let drifted: Vec<String> = fts
        .iter()
        .filter(|f| f["in_sync"] == false)
        .filter_map(|f| f["index"].as_str().map(str::to_string))
        .collect();
    let mut resynced = false;
    if !drifted.is_empty() {
        let names = drifted.clone();
        let by = ctx.caller.label.clone();
        ctx.hub
            .db()
            .write_async(move |tx| {
                for n in &names {
                    tx.execute(&format!("INSERT INTO \"{n}\"(\"{n}\") VALUES ('rebuild')"), [])?;
                }
                ledger::append(
                    tx,
                    EventInput::new(
                        ua_core::DEFAULT_ORG,
                        "agent.state.resynced",
                        json!({ "fts_indexes": names }),
                    )
                    .by(by),
                )?;
                Ok(())
            })
            .await?;
        resynced = true;
    }
    let chain_ok = chain["status"] != "tampered";
    let refs_ok = refs["total"] == 0;
    Ok(json!({
        "in_sync": drifted.is_empty() && refs_ok && chain_ok,
        "memory_db_count": counts.0,
        "task_db_count": counts.1,
        "resynced": resynced,
        "drift_details": {
            "fts_drift": drifted,
            "dangling_references": refs["total"],
            "ledger_tampered": !chain_ok,
        },
        "checks": {
            "fts": fts,
            "dangling_references": refs,
            "ledger": chain,
        },
    }))
}

// ---------------------------------------------------------------------------
// Client evidence.

/// Channels `evidence_append` may write: a client cannot forge hub events.
pub const CLIENT_CHANNEL_PREFIX: &str = "sdk.";
/// The `trust.source` of a client evidence payload.
pub const CLIENT_EVIDENCE_SOURCE: &str = "sdk_evidence";
/// Whether `channel` holds client-written evidence.
pub fn is_client_channel(channel: &str) -> bool {
    channel.starts_with(CLIENT_CHANNEL_PREFIX)
}
/// Client events listed per task in a report.
const CLIENT_EVENTS_CAP: usize = 20;
/// Largest client payload a report shows inline (bytes); larger ones are
/// read through their `platform` reference.
const CLIENT_PAYLOAD_INLINE: usize = 4096;
const CHANNEL_MAX: usize = 120;
const DEDUPE_MAX: usize = 256;
/// Largest serialized payload `evidence_append` stores.
const PAYLOAD_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppendArgs {
    /// Channel in the `sdk.` namespace, at most 120 characters.
    pub channel: String,
    /// The event body (a JSON object, at most 64 KiB serialized).
    pub payload: Map<String, Value>,
    /// Idempotency key (1-256 characters): a repeat with the same key from the
    /// same caller appends nothing and returns the first event.
    pub dedupe_key: Option<String>,
}

/// The stored dedupe key: namespaced by caller, so one identity can neither
/// observe nor pre-empt another's keys.
fn client_dedupe_key(label: &str, key: &str) -> String {
    format!("sdk-evidence:{label}:{key}")
}

/// `sdk.` events and their stored payload bytes that `label` appended in the
/// last hour, read from the ledger.
fn client_usage(c: &Connection, label: &str) -> UaResult<(i64, i64)> {
    let cutoff = jiff::Timestamp::from_millisecond(ua_core::time::now_ms() - 3_600_000)
        .map(ua_core::time::format_ts)
        .map_err(|e| UaError::internal(format!("clock: {e}")))?;
    Ok(c.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(CAST(payload AS BLOB))), 0) FROM event_log \
         WHERE channel >= 'sdk.' AND channel < 'sdk/' AND originator = ?1 AND created_at > ?2",
        rusqlite::params![label, cutoff],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}

async fn evidence_append(ctx: ToolCtx, a: AppendArgs) -> UaResult<Value> {
    if !matches!(ctx.caller.kind, ActorKind::Agent | ActorKind::Human) {
        return Err(UaError::denied(
            "identity_required",
            "evidence_append requires an authenticated identity; evidence is attributed to it",
        ));
    }
    let channel = a.channel.trim().to_string();
    if !channel.starts_with(CLIENT_CHANNEL_PREFIX)
        || channel.len() <= CLIENT_CHANNEL_PREFIX.len()
        || channel.chars().count() > CHANNEL_MAX
        || channel.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(UaError::invalid(format!(
            "channel must use the {CLIENT_CHANNEL_PREFIX} namespace (at most {CHANNEL_MAX} characters, no spaces)"
        )));
    }
    let dedupe = match a.dedupe_key {
        None => None,
        Some(k) if !k.trim().is_empty() && k.chars().count() <= DEDUPE_MAX => Some(k.trim().to_string()),
        Some(_) => {
            return Err(UaError::invalid(format!(
                "dedupe_key must be a non-empty string of at most {DEDUPE_MAX} characters"
            )));
        }
    };
    let payload = Value::Object(a.payload);
    let size = serde_json::to_vec(&payload)?.len();
    if size > PAYLOAD_MAX_BYTES {
        return Err(UaError::invalid(format!("payload is larger than {PAYLOAD_MAX_BYTES} bytes")));
    }
    let label = ctx.caller.label.clone();
    let stored_key = dedupe.as_deref().map(|k| client_dedupe_key(&label, k));
    let max_events = i64::from(ctx.hub.cfg().evidence_append_max_per_hour);
    let max_bytes = i64::try_from(ctx.hub.cfg().evidence_append_max_bytes_per_hour).unwrap_or(i64::MAX);
    let (ulid, inserted) = ctx
        .hub
        .db()
        .write_async(move |tx| {
            // A repeat returns the first event and costs nothing.
            if let Some(k) = &stored_key
                && let Some(ulid) = tx
                    .query_row("SELECT ulid FROM event_log WHERE dedupe_key = ?1", [k], |r| r.get(0))
                    .optional()?
            {
                return Ok((ulid, false));
            }
            // Counted inside the write transaction: the single writer
            // serializes appends, so concurrent calls cannot overshoot.
            let (events, bytes) = client_usage(tx, &label)?;
            if events + 1 > max_events || bytes.saturating_add(size as i64) > max_bytes {
                return Err(UaError::denied(
                    "rate_limited",
                    format!(
                        "evidence budget spent: {label} appended {events} events ({bytes} bytes) in the last hour; \
                         the limit is {max_events} events and {max_bytes} bytes per hour \
                         (evidence_append_max_per_hour, evidence_append_max_bytes_per_hour)"
                    ),
                ));
            }
            let mut input = EventInput::new(ua_core::DEFAULT_ORG, channel, payload).by(label);
            if let Some(k) = &stored_key {
                input = input.dedupe(k.clone());
            }
            match ledger::append(tx, input)? {
                Some(ev) => Ok((ev.ulid, true)),
                None => Err(UaError::internal("dedupe key appeared mid-transaction")),
            }
        })
        .await?;
    Ok(json!({ "event_ulid": ulid, "inserted": inserted }))
}

// ---------------------------------------------------------------------------
// Registration.

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "evidence_report",
            "Read-only evidence for task completion: per task, the ledger events that mention it with their \
             hashes, the task row, approvals, delegations, PR/commit references, and tool-call counts by its \
             participants inside the task's lifetime (attributed by caller and window), plus the ledger chain \
             verification. Client sdk. events never attribute a task; those naming it are listed apart under \
             client_asserted (payloads marked untrusted). project_id (a [project-spec] root) reports its \
             subtree with a project_chain. limit defaults to 50 (max 500).",
            evidence_report,
        )
        .family("evidence")
        .read_only(),
    );
    r.add(
        tool(
            "evidence_append",
            "Append one client evidence event to the tamper-evident ledger: channel in the sdk. namespace, a \
             JSON object payload (at most 64 KiB), optional dedupe_key. The originator is always the verified \
             caller. A repeat with the same dedupe_key from the same caller appends nothing. Each identity may \
             append evidence_append_max_per_hour events and evidence_append_max_bytes_per_hour payload bytes \
             per rolling hour (rate_limited past either). Client events never attribute a task in \
             evidence_report; they are listed under client_asserted. Returns {event_ulid, inserted}.",
            evidence_append,
        )
        .family("evidence"),
    );
    r.add(
        tool(
            "state_sync_verify",
            "Consistency checks: each full-text index against its base table, dangling references \
             (foreign keys and memory.superseded_by) and the ledger chain. A drifted index is rebuilt and \
             `resynced` is true. Returns {in_sync, memory_db_count, task_db_count, resynced, drift_details, checks}.",
            state_sync_verify,
        )
        .family("evidence"),
    );
}
