//! Remote executor nodes: registration, heartbeats, liveness and operator
//! retirement.
//!
//! Tools: `node_register` and `node_heartbeat` (an authenticated agent
//! reporting its own node), `node_list` (read-only), and the
//! `coordination_manage` actions `node_retire`, `node_unretire`,
//! `node_reassign` and `node_forget` (lifecycle operators only). The HTTP device plane (`POST /api/node/register`,
//! `POST /api/node/heartbeat`, `GET /api/nodes`) calls these tools.
//!
//! Ownership: a node row belongs to the agent label that first registered it.
//! The owner is always the verified caller, never a request field, and another
//! label using the same node name is refused. Only that check passing reveals
//! whether the node is retired. An agent holds at most `node_max_per_agent`
//! nodes in service. An operator moves a name to another label with
//! `node_reassign`, or deletes a retired row with `node_forget` so the name
//! can be registered afresh.
//!
//! Visibility: `node_list` gives full facts to the node's own agent and to
//! lifecycle operators; everyone else sees a summary without paths,
//! checkouts, harness binaries or session titles.
//!
//! Facts: a node reports host facts (OS, harnesses, worktree roots,
//! checkouts, discovered sessions, ...). They are bounded on write: a raw
//! report over [`MAX_FACTS_BYTES`] is refused, unknown keys are dropped (and
//! named in the reply), and every list and string is capped. Nothing a node
//! sends is stored verbatim. A heartbeat refreshes only the advisory
//! [`HEARTBEAT_KEYS`]; other keys are dropped and reported, so host facts
//! (roots, repos, harnesses) change only by registering again.
//!
//! Liveness is derived at read time: a node is live while its heartbeat is at
//! most [`NODE_LIVE_WINDOW_S`] old and at most [`NODE_CLOCK_SKEW_S`] in the
//! future. Heartbeats only move the row; they are not ledgered. A first
//! registration, or one that changes the version, backends, harness names,
//! roots or repos, appends `agent.node.register`; an identical
//! re-registration does not. Retire, un-retire, reassign and forget each
//! append one `agent.node.<kind>` event. Every event is written in the same
//! transaction as the change.
//!
//! Retirement keeps the row and its history but leaves the node out of the
//! listing and the doctor's fleet row, and refuses its registration and
//! heartbeats (`node_retired`) until an operator un-retires it. Retiring and
//! un-retiring both fence the stored heartbeat (`heartbeat_floor`): the node is
//! not live again until it registers or sends a newer heartbeat.
//!
//! Retiring, reassigning and forgetting are refused while the node still has
//! queued or claimed work. The sources of such work are listed in
//! [`RETIRE_BLOCKERS`].

use std::collections::BTreeSet;

use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, Row, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::time::parse_ts;
use ua_core::{ActorKind, Caller, UaError, UaResult};
use ua_org::authz::{Authority, Authz};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use super::agents::{STATUS_THRESHOLDS, validate_label, verified};
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "nodes.v1",
    sql: "
CREATE TABLE IF NOT EXISTS nodes (
    node TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    facts_json TEXT NOT NULL DEFAULT '{}',
    version TEXT,
    registered_at TEXT NOT NULL,
    last_heartbeat TEXT,
    heartbeat_floor TEXT,
    retired_at TEXT,
    retired_by TEXT,
    retired_reason TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_agent ON nodes(agent);
",
};

/// A node is live while its heartbeat is at most this old: three of the
/// node's default 30-second heartbeat intervals.
pub const NODE_LIVE_WINDOW_S: i64 = 90;
/// How far in the future a heartbeat may be stamped and still count as live:
/// ordinary clock skew, not a rolled-back hub clock.
pub const NODE_CLOCK_SKEW_S: i64 = 60;
/// A raw facts report larger than this (as JSON) is refused.
pub const MAX_FACTS_BYTES: usize = 64_000;
/// `code` of the refusal a retired node's registration or heartbeat gets.
pub const RETIRED_CODE: &str = "node_retired";

const MAX_NODE_NAME: usize = 128;
const MAX_VERSION: usize = 64;
const MAX_RETIRE_REASON: usize = 500;
const MAX_PATH: usize = 4096;
const MAX_NAME: usize = 64;
const MAX_ROOTS: usize = 32;
const MAX_REPOS: usize = 64;
const MAX_HARNESSES: usize = 32;
const MAX_BACKENDS: usize = 32;
const MAX_ARGV: usize = 16;
const MAX_FEATURES: usize = 16;
const MAX_FEATURE_LEN: usize = 40;
const MAX_SURFACE_KEYS: usize = 16;
const MAX_SURFACE_KEY_LEN: usize = 40;
const MAX_SURFACE_NAMES: usize = 50;
const MAX_NATIVE_SESSIONS: usize = 50;
const MAX_STAMP: usize = 40;
const MAX_TITLE: usize = 120;
const MAX_VAULT_SYNC_DETAIL: usize = 400;
const MAX_DROPPED_KEYS: usize = 32;
const NATIVE_HARNESSES: [&str; 2] = ["claude", "codex"];
const VAULT_SYNC_STATUSES: [&str; 4] = ["LIVE", "DORMANT", "MISCONFIGURED", "UNKNOWN"];
const REPO_FIELDS: [&str; 5] = ["root", "root_realpath", "name", "path", "realpath"];
/// Keys a heartbeat may refresh without replacing the registration's facts.
const HEARTBEAT_KEYS: [&str; 5] = ["code_sha", "harness_config", "native_sessions", "surfaces", "vault_sync"];
/// When bounded facts are still too large, these lists lose their last
/// entries first, then whole keys go in the same order.
const SHED_ORDER: [&str; 4] = ["native_sessions", "repos", "worktree_roots", "harnesses"];
/// Protocol features this hub serves to nodes, returned at registration.
/// `node_code_sha`: heartbeats may carry a `code_sha` fact.
/// `acp_session_mcp`: the hub mints session credentials for ACP items (code
/// support; whether it is switched on is checked per call).
/// `node_wake_v3`: the hub serves the idle-session wake long-poll
/// (`/api/node/wake`, offer version 3); `node_wake_live_sessions`: it reads
/// `live_sessions` on that poll.
const HUB_FEATURES: [&str; 4] = [
    "node_code_sha",
    super::node_queue::credentials::FEATURE,
    super::wake::FEATURE,
    super::wake::LIVE_SESSIONS_FEATURE,
];

/// Lists the ids of queued or claimed work items assigned to a node.
pub(crate) type OpenWork = fn(&Connection, &str) -> UaResult<Vec<String>>;

/// Every source of node work that must be settled before a node is retired.
/// Retiring is refused (conflict) while any of them reports an item, so no
/// work is stranded behind the `node_retired` refusal.
pub(crate) const RETIRE_BLOCKERS: &[OpenWork] = &[super::node_queue::open_work];

// --- names and identity ---------------------------------------------------------

/// 1-128 of `A-Z a-z 0-9 . _ -`, starting with a letter or digit.
pub(crate) fn validate_node_name(raw: &str) -> UaResult<String> {
    let name = raw.trim();
    let mut chars = name.chars();
    let ok = name.len() <= MAX_NODE_NAME
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(name.to_string())
    } else {
        Err(UaError::invalid("node must be 1-128 chars of [A-Za-z0-9._-], starting alphanumeric"))
    }
}

/// The agent label a node call acts for: the verified agent itself. A human
/// or an unverified caller has no node.
fn node_agent(caller: &Caller) -> UaResult<String> {
    match caller.kind {
        ActorKind::Agent => Ok(caller.label.clone()),
        ActorKind::Human => Err(UaError::denied(
            "agent_identity_required",
            "nodes register and heartbeat under an authenticated agent identity, not a human one",
        )),
        ActorKind::System | ActorKind::Anonymous => {
            Err(UaError::Unauthenticated("a node needs an authenticated agent identity".into()))
        }
    }
}

fn retired_message(node: &str) -> String {
    format!(
        "node {node:?} was retired by an operator; it registers and takes work again only after an \
         operator runs coordination_manage action node_unretire, or re-register this device under a new \
         node name"
    )
}

/// The stored owner and retirement of `node`, checked against `agent`:
/// another label's node is refused before retirement is revealed.
pub(crate) fn check_owner(owner: &str, retired: bool, node: &str, agent: &str) -> UaResult<()> {
    if owner != agent {
        return Err(UaError::denied(
            "node_owned_elsewhere",
            format!("node {node:?} is bound to a different agent"),
        ));
    }
    if retired {
        return Err(UaError::denied(RETIRED_CODE, retired_message(node)));
    }
    Ok(())
}

// --- bounded facts --------------------------------------------------------------

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// A string of 1..=`max` characters, else `None`.
fn name_within(v: &Value, max: usize) -> Option<&str> {
    v.as_str().filter(|s| !s.is_empty() && s.chars().count() <= max)
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-')
}

/// A backend or harness name: 1-64 of `A-Z a-z 0-9 : . _ -`.
fn backend_name(v: &str) -> bool {
    !v.is_empty() && v.len() <= MAX_NAME && v.chars().all(is_name_char)
}

/// Path components of an absolute, `..`-free path, else `None`. Empty and
/// `.` components are dropped, as a POSIX path normalizes them.
fn components(path: &str) -> Option<Vec<&str>> {
    if !path.starts_with('/') || path.len() > MAX_PATH || path.contains('\0') {
        return None;
    }
    let parts: Vec<&str> = path.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    (!parts.contains(&"..")).then_some(parts)
}

/// Whether `path` is one of `roots` or inside one, by whole components.
fn path_in_roots(path: &str, roots: &[String]) -> bool {
    let Some(candidate) = components(path) else { return false };
    roots.iter().filter_map(|r| components(r)).any(|root| candidate.starts_with(&root))
}

fn os_fact(v: &Value) -> Option<Value> {
    match v {
        Value::String(s) => Some(json!(clip(s, 128))),
        Value::Object(m) => Some(Value::Object(
            ["system", "release", "machine", "python"]
                .iter()
                .filter_map(|k| {
                    m.get(*k).and_then(Value::as_str).map(|s| (k.to_string(), json!(clip(s, MAX_NAME))))
                })
                .collect(),
        )),
        _ => None,
    }
}

fn backends_fact(v: &Value) -> Option<Value> {
    let items = v.as_array()?;
    let mut out: Vec<&str> = Vec::new();
    for b in items.iter().filter_map(Value::as_str).filter(|b| backend_name(b)) {
        if out.len() >= MAX_BACKENDS {
            break;
        }
        if !out.contains(&b) {
            out.push(b);
        }
    }
    Some(json!(out))
}

fn harnesses_fact(v: &Value) -> Option<Value> {
    let m = v.as_object()?;
    let mut out = Map::new();
    for (name, h) in m.iter().filter(|(k, _)| backend_name(k)).take(MAX_HARNESSES) {
        let Some(h) = h.as_object() else { continue };
        let mut row = Map::new();
        for (key, max) in [("bin", 256), ("path", MAX_PATH), ("version", 128)] {
            if let Some(s) = h.get(key).and_then(Value::as_str) {
                row.insert(key.into(), json!(clip(s, max)));
            }
        }
        if let Some(argv) = h.get("argv").and_then(Value::as_array) {
            let argv: Vec<String> =
                argv.iter().filter_map(Value::as_str).take(MAX_ARGV).map(|a| clip(a, 256)).collect();
            row.insert("argv".into(), json!(argv));
        }
        if let Some(acp) = h.get("acp").and_then(Value::as_bool) {
            row.insert("acp".into(), json!(acp));
        }
        out.insert(name.clone(), Value::Object(row));
    }
    Some(Value::Object(out))
}

/// Worktree roots as `{path, realpath?, exists?, worktrees?}`; a bare string
/// is a path. `realpath` is kept only when absolute and `..`-free.
fn roots_fact(v: &Value) -> Option<Value> {
    let items = v.as_array()?;
    let mut out = Vec::new();
    for entry in items {
        if out.len() >= MAX_ROOTS {
            break;
        }
        let row = match entry {
            Value::String(_) => name_within(entry, MAX_PATH).map(|p| json!({ "path": p })),
            Value::Object(m) => m.get("path").and_then(|p| name_within(p, MAX_PATH)).map(|path| {
                let mut row = json!({ "path": path });
                if let Some(real) =
                    m.get("realpath").and_then(Value::as_str).filter(|r| components(r).is_some())
                {
                    row["realpath"] = json!(real);
                }
                if let Some(exists) = m.get("exists").and_then(Value::as_bool) {
                    row["exists"] = json!(exists);
                }
                if let Some(n) = m.get("worktrees").and_then(Value::as_u64) {
                    row["worktrees"] = json!(n.min(1_000_000));
                }
                row
            }),
            _ => None,
        };
        out.extend(row);
    }
    Some(Value::Array(out))
}

/// The node-resolved realpath of every existing worktree root it reported.
/// Only these admit a discovered session: the hub cannot resolve a node's
/// paths itself.
fn root_paths(facts: &Map<String, Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for entry in facts.get("worktree_roots").and_then(Value::as_array).into_iter().flatten() {
        if entry.get("exists") == Some(&json!(false)) {
            continue;
        }
        if let Some(real) = entry.get("realpath").and_then(Value::as_str)
            && !out.iter().any(|r| r == real)
        {
            out.push(real.to_string());
        }
    }
    out
}

/// Checkouts under the roots; a row missing any field, or with one longer
/// than a path, is dropped.
fn repos_fact(v: &Value) -> Option<Value> {
    let items = v.as_array()?;
    let rows = items
        .iter()
        .take(MAX_REPOS)
        .filter_map(Value::as_object)
        .filter_map(|m| {
            let fields: Option<Map<String, Value>> = REPO_FIELDS
                .iter()
                .map(|f| m.get(*f).and_then(|v| name_within(v, MAX_PATH)).map(|s| (f.to_string(), json!(s))))
                .collect();
            fields.map(Value::Object)
        })
        .collect();
    Some(Value::Array(rows))
}

/// A surface key: 1-40 of `a-z 0-9 _`.
fn surface_key_ok(k: &str) -> bool {
    (1..=MAX_SURFACE_KEY_LEN).contains(&k.len())
        && k.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Named surfaces the node exposes (profiles, queues, assignees, ...): a map
/// of at most 16 keys of `[a-z0-9_]{1,40}`, each a list of at most 50 names of
/// 1-64 chars. A bad key, or a value that is not a list, is dropped; names
/// that are not short strings are skipped.
fn surfaces_fact(v: &Value) -> Option<Value> {
    let m = v.as_object()?;
    let out: Map<String, Value> = m
        .iter()
        .filter(|(k, _)| surface_key_ok(k))
        .filter_map(|(k, v)| {
            let names: Vec<&str> = v
                .as_array()?
                .iter()
                .filter_map(|n| name_within(n, MAX_NAME))
                .take(MAX_SURFACE_NAMES)
                .collect();
            Some((k.clone(), json!(names)))
        })
        .take(MAX_SURFACE_KEYS)
        .collect();
    Some(Value::Object(out))
}

fn features_fact(v: &Value) -> Option<Value> {
    let items = v.as_array()?;
    let names: Vec<&str> =
        items.iter().take(MAX_FEATURES).filter_map(|f| name_within(f, MAX_FEATURE_LEN)).collect();
    Some(json!(names))
}

fn session_id_ok(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() <= 200
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

/// Discovered native sessions: metadata only, and only inside the node's
/// resolved roots. Unknown fields are dropped, so no transcript text rides
/// along. `cwd` is the node-resolved path.
fn native_sessions(v: &Value, roots: &[String]) -> Vec<Value> {
    let Some(rows) = v.as_array() else { return Vec::new() };
    let mut out = Vec::new();
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for row in rows.iter().take(MAX_NATIVE_SESSIONS * 2) {
        if out.len() >= MAX_NATIVE_SESSIONS {
            break;
        }
        let Some(m) = row.as_object() else { continue };
        let Some(harness) = m.get("harness").and_then(Value::as_str).filter(|h| NATIVE_HARNESSES.contains(h))
        else {
            continue;
        };
        let Some(sid) = m.get("external_session_id").and_then(Value::as_str).filter(|s| session_id_ok(s))
        else {
            continue;
        };
        let Some(real) = m.get("cwd_realpath").and_then(Value::as_str).filter(|p| path_in_roots(p, roots))
        else {
            continue;
        };
        if !seen.insert((harness, sid)) {
            continue;
        }
        let stamp = |k: &str| m.get(k).and_then(Value::as_str).filter(|s| s.chars().count() <= MAX_STAMP);
        let title = m
            .get("title")
            .and_then(Value::as_str)
            .map(|t| clip(&t.split_whitespace().collect::<Vec<_>>().join(" "), MAX_TITLE));
        out.push(json!({
            "harness": harness,
            "external_session_id": sid,
            "cwd": real,
            "cwd_realpath": real,
            "last_activity": stamp("last_activity"),
            "scanned_at": stamp("scanned_at"),
            "title": title,
        }));
    }
    out
}

/// Harness-config state: skills count only with an in-sync, skill-bearing
/// surface that delivers them.
fn config_state(v: &Value) -> Option<Value> {
    let m = v.as_object()?;
    let version = m.get("bundle_version").and_then(|b| name_within(b, MAX_NAME))?;
    let names = |key: &str, limit: usize| -> Vec<String> {
        m.get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter().filter_map(|n| name_within(n, MAX_NAME)).take(limit).map(str::to_string).collect()
            })
            .unwrap_or_default()
    };
    let in_sync = names("in_sync", 32);
    let skill_surfaces: Vec<String> =
        names("skill_surfaces", 32).into_iter().filter(|s| in_sync.contains(s)).collect();
    let skills = if skill_surfaces.is_empty() { Vec::new() } else { names("skills", 64) };
    Some(json!({
        "bundle_version": version,
        "in_sync": in_sync,
        "skill_surfaces": skill_surfaces,
        "skills": skills,
    }))
}

/// The node's own vault-sync doctor row: status, detail, as_of.
fn vault_sync_state(v: &Value) -> Option<Value> {
    let m = v.as_object()?;
    let status = m.get("status").and_then(Value::as_str).filter(|s| VAULT_SYNC_STATUSES.contains(s))?;
    Some(json!({
        "status": status,
        "detail": m.get("detail").and_then(Value::as_str).map(|d| clip(d, MAX_VAULT_SYNC_DETAIL)).unwrap_or_default(),
        "as_of": m.get("as_of").and_then(Value::as_str).filter(|s| s.chars().count() <= MAX_STAMP),
    }))
}

/// A full lowercase hex commit id (40 or 64 characters).
fn code_sha(v: &Value) -> Option<Value> {
    let s = v.as_str()?;
    let hex = s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    (hex && matches!(s.len(), 40 | 64)).then(|| json!(s))
}

/// The bounded form of one fact, else `None` (malformed: not stored).
/// `roots` are the resolved roots native sessions are checked against.
fn bound_fact(key: &str, v: &Value, roots: &[String]) -> Option<Value> {
    match key {
        "os" => os_fact(v),
        "backends" => backends_fact(v),
        "harnesses" => harnesses_fact(v),
        "worktree_roots" => roots_fact(v),
        "repos" => repos_fact(v),
        "surfaces" => surfaces_fact(v),
        "node_features" => features_fact(v),
        "native_sessions" => v.is_array().then(|| Value::Array(native_sessions(v, roots))),
        "harness_config" => config_state(v),
        "vault_sync" => vault_sync_state(v),
        "code_sha" => code_sha(v),
        _ => None,
    }
}

fn encoded_len(m: &Map<String, Value>) -> usize {
    serde_json::to_vec(m).map(|v| v.len()).unwrap_or(usize::MAX)
}

/// Shed list entries, then whole keys, until `facts` fits [`MAX_FACTS_BYTES`].
fn fit(facts: &mut Map<String, Value>) {
    for key in SHED_ORDER {
        while encoded_len(facts) > MAX_FACTS_BYTES {
            let Some(list) = facts.get_mut(key).and_then(Value::as_array_mut) else { break };
            if list.pop().is_none() {
                break;
            }
        }
    }
    for key in SHED_ORDER.iter().chain(["surfaces", "os", "node_features"].iter()) {
        if encoded_len(facts) <= MAX_FACTS_BYTES {
            return;
        }
        facts.remove(*key);
    }
}

/// Validate a raw facts argument: absent, or a JSON object within the size cap.
fn raw_facts(v: Option<Value>) -> UaResult<Option<Map<String, Value>>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) => {
            if encoded_len(&m) > MAX_FACTS_BYTES {
                return Err(UaError::invalid(format!("facts exceed {MAX_FACTS_BYTES} bytes")));
            }
            Ok(Some(m))
        }
        Some(_) => Err(UaError::invalid("facts must be a JSON object")),
    }
}

/// A full fact set, bounded. Returns the stored facts and the reported keys
/// that were not stored (unknown or malformed).
fn bound_facts(raw: &Map<String, Value>) -> (Map<String, Value>, Vec<String>) {
    let mut out = Map::new();
    if let Some(roots) = raw.get("worktree_roots").and_then(roots_fact) {
        out.insert("worktree_roots".into(), roots);
    }
    let roots = root_paths(&out);
    let mut dropped = Vec::new();
    for (key, v) in raw {
        if key == "worktree_roots" {
            if !out.contains_key(key) {
                dropped.push(key.clone());
            }
            continue;
        }
        match bound_fact(key, v, &roots) {
            Some(b) => {
                out.insert(key.clone(), b);
            }
            None => dropped.push(clip(key, MAX_NAME)),
        }
    }
    dropped.truncate(MAX_DROPPED_KEYS);
    fit(&mut out);
    (out, dropped)
}

/// A heartbeat's facts applied to the stored ones: each of
/// [`HEARTBEAT_KEYS`] present replaces its stored value (a malformed value
/// clears its key) and the rest are kept. Any other key is dropped and
/// reported: roots, repos, harnesses and the like change only through a
/// (ledgered) registration.
fn heartbeat_facts(
    existing: Map<String, Value>,
    update: &Map<String, Value>,
) -> (Map<String, Value>, Vec<String>) {
    let roots = root_paths(&existing);
    let mut out = existing;
    let mut dropped = Vec::new();
    for (key, v) in update {
        if !HEARTBEAT_KEYS.contains(&key.as_str()) {
            dropped.push(clip(key, MAX_NAME));
            continue;
        }
        out.remove(key);
        match bound_fact(key, v, &roots) {
            Some(b) => {
                out.insert(key.clone(), b);
            }
            None => dropped.push(key.clone()),
        }
    }
    dropped.truncate(MAX_DROPPED_KEYS);
    fit(&mut out);
    (out, dropped)
}

fn load_facts(raw: &str) -> Map<String, Value> {
    serde_json::from_str::<Value>(raw).ok().and_then(|v| v.as_object().cloned()).unwrap_or_default()
}

// --- liveness -------------------------------------------------------------------

/// `online`, `idle`, `stale`, `offline`, or `unknown` without a heartbeat.
/// `online` exactly when the node is live; a beat further in the future than
/// the skew allowance is `offline`; an older beat takes the agent grading,
/// never `online`.
pub(crate) fn heartbeat_status(beat: Option<Timestamp>, now: Timestamp) -> &'static str {
    let Some(beat) = beat else { return "unknown" };
    let age = now.as_second() - beat.as_second();
    if (-NODE_CLOCK_SKEW_S..=NODE_LIVE_WINDOW_S).contains(&age) {
        return "online";
    }
    let (_, idle, stale) = STATUS_THRESHOLDS;
    if age < 0 {
        "offline"
    } else if age <= idle {
        "idle"
    } else if age <= stale {
        "stale"
    } else {
        "offline"
    }
}

/// How one node reads at `now`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Liveness {
    /// `live`, `stale`, `offline` or `retired`.
    pub status: &'static str,
    /// The finer grading of [`heartbeat_status`].
    pub heartbeat_status: &'static str,
    pub live: bool,
    /// The heartbeat that counts: `None` while the stored one is at or
    /// before the fence set by retire or un-retire.
    pub live_heartbeat: Option<String>,
}

pub(crate) fn liveness(last: Option<&str>, floor: Option<&str>, retired: bool, now: Timestamp) -> Liveness {
    let beat = last.and_then(parse_ts);
    let fenced = matches!((beat, floor.and_then(parse_ts)), (Some(b), Some(f)) if b <= f);
    let effective = if fenced { None } else { beat };
    // A stored beat that does not count reads offline, as routing would.
    let graded =
        if effective.is_none() && last.is_some() { "offline" } else { heartbeat_status(effective, now) };
    let status = match (retired, graded) {
        (true, _) => "retired",
        (false, "online") => "live",
        (false, "idle" | "stale") => "stale",
        (false, _) => "offline",
    };
    Liveness {
        status,
        heartbeat_status: graded,
        live: status == "live",
        live_heartbeat: effective.and(last).map(str::to_string),
    }
}

// --- rows -----------------------------------------------------------------------

fn root_list(facts: &Map<String, Value>) -> Vec<String> {
    facts
        .get("worktree_roots")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|r| r.get("exists") != Some(&json!(false)))
        .filter_map(|r| r.get("path").and_then(Value::as_str).map(str::to_string))
        .collect()
}

fn node_json(r: &Row<'_>, now: Timestamp) -> rusqlite::Result<Value> {
    let last: Option<String> = r.get("last_heartbeat")?;
    let floor: Option<String> = r.get("heartbeat_floor")?;
    let retired_at: Option<String> = r.get("retired_at")?;
    let l = liveness(last.as_deref(), floor.as_deref(), retired_at.is_some(), now);
    let facts = load_facts(&r.get::<_, String>("facts_json")?);
    let fact = |k: &str, empty: Value| facts.get(k).cloned().unwrap_or(empty);
    let mut row = json!({
        "detail": "full",
        "node": r.get::<_, String>("node")?,
        "agent": r.get::<_, String>("agent")?,
        "version": r.get::<_, Option<String>>("version")?,
        "registered_at": r.get::<_, String>("registered_at")?,
        "last_heartbeat": last,
        "live_heartbeat": l.live_heartbeat,
        "status": l.status,
        "heartbeat_status": l.heartbeat_status,
        "live": l.live,
        "os": fact("os", Value::Null),
        "backends": fact("backends", json!([])),
        "harnesses": fact("harnesses", json!({})),
        "worktree_roots": root_list(&facts),
        "repos": fact("repos", json!([])),
        "surfaces": fact("surfaces", json!({})),
        "node_features": fact("node_features", json!([])),
        "native_sessions": fact("native_sessions", json!([])),
        "harness_config": fact("harness_config", Value::Null),
        "vault_sync": fact("vault_sync", Value::Null),
        "code_sha": fact("code_sha", Value::Null),
    });
    if retired_at.is_some() {
        row["retired_at"] = json!(retired_at);
        row["retired_by"] = json!(r.get::<_, Option<String>>("retired_by")?);
        row["retired_reason"] = json!(r.get::<_, Option<String>>("retired_reason")?);
    }
    Ok(row)
}

/// What a viewer who is neither the node's agent nor a lifecycle operator
/// sees: identity, liveness, version and capability names, but no paths,
/// checkouts, harness binaries or session titles.
fn summary(full: &Value) -> Value {
    let harness_names: Vec<&String> =
        full["harnesses"].as_object().map(|m| m.keys().collect()).unwrap_or_default();
    let mut row = json!({ "detail": "summary", "harness_names": harness_names });
    for key in [
        "node",
        "agent",
        "status",
        "heartbeat_status",
        "live",
        "live_heartbeat",
        "version",
        "last_heartbeat",
        "registered_at",
        "backends",
    ] {
        row[key] = full[key].clone();
    }
    row
}

/// Facts the ledger records a registration for: a first registration, or a
/// change in any of these between the stored row and the new one.
fn identity_facts(version: Option<&str>, facts: &Map<String, Value>) -> Map<String, Value> {
    let names = |k: &str| -> Value {
        facts
            .get(k)
            .and_then(Value::as_object)
            .map(|m| json!(m.keys().collect::<Vec<_>>()))
            .unwrap_or(json!([]))
    };
    let repos: Vec<&str> = facts
        .get("repos")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| r.get("realpath").and_then(Value::as_str))
        .collect();
    let mut out = Map::new();
    out.insert("version".into(), json!(version));
    out.insert("backends".into(), facts.get("backends").cloned().unwrap_or(json!([])));
    out.insert("harnesses".into(), names("harnesses"));
    out.insert("worktree_roots".into(), json!(root_list(facts)));
    out.insert("repos".into(), json!(repos));
    out
}

/// Facts a device acceptance vouches for: a registration that changes one
/// voids the node's acceptance.
const ACCEPTANCE_FACTS: [&str; 3] = ["code_sha", "backends", "harnesses"];

/// The acceptance facts that differ between `old` and `new`. `code_sha` may
/// arrive by heartbeat only, so a registration (or heartbeat) without one
/// leaves it unjudged; `backends` and `harnesses` (every field of each
/// harness) change only by registering.
fn moved_acceptance_facts(old: &Map<String, Value>, new: &Map<String, Value>) -> Vec<&'static str> {
    ACCEPTANCE_FACTS
        .into_iter()
        .filter(|k| match *k {
            "code_sha" => new.get(*k).is_some_and(|n| old.get(*k).is_some_and(|o| o != n)),
            _ => old.get(*k) != new.get(*k),
        })
        .collect()
}

fn read_nodes(c: &Connection, now: Timestamp) -> UaResult<Vec<Value>> {
    let mut stmt = c.prepare("SELECT * FROM nodes ORDER BY node")?;
    let rows = stmt.query_map([], |r| node_json(r, now))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// One node as the doctor's fleet row sees it.
#[derive(Debug, Clone)]
pub(crate) struct FleetNode {
    pub node: String,
    /// `live`, `stale` or `offline`.
    pub status: &'static str,
    pub last_heartbeat: Option<String>,
}

/// Every registered node: those in service, and the names of retired ones.
#[derive(Debug, Clone, Default)]
pub(crate) struct Fleet {
    pub active: Vec<FleetNode>,
    pub retired: Vec<String>,
}

pub(crate) fn fleet(c: &Connection, now: Timestamp) -> UaResult<Fleet> {
    let mut stmt =
        c.prepare("SELECT node, last_heartbeat, heartbeat_floor, retired_at FROM nodes ORDER BY node")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut out = Fleet::default();
    for row in rows {
        let (node, last, floor, retired_at) = row?;
        if retired_at.is_some() {
            out.retired.push(node);
        } else {
            let status = liveness(last.as_deref(), floor.as_deref(), false, now).status;
            out.active.push(FleetNode { node, status, last_heartbeat: last });
        }
    }
    Ok(out)
}

// --- arguments ------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterArgs {
    /// Node name: 1-128 of `A-Z a-z 0-9 . _ -`, starting alphanumeric. It
    /// belongs to the calling agent from its first registration on.
    pub node: String,
    /// Host facts, a JSON object of at most 64000 bytes: `os`, `backends`,
    /// `harnesses`, `worktree_roots`, `repos`, `surfaces`, `node_features`,
    /// `native_sessions`, `harness_config`, `vault_sync`, `code_sha`. Values
    /// are bounded; other keys are dropped and named in `dropped_fact_keys`.
    /// `surfaces` maps up to 16 keys of `[a-z0-9_]{1,40}` to lists of at most
    /// 50 short names (the node's profiles, queues or assignees).
    pub facts: Option<Value>,
    /// The node software version, at most 64 characters.
    pub version: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatArgs {
    /// Node name, as registered by the calling agent.
    pub node: String,
    /// Id of the work item the node is running: its lease (and its dispatch
    /// run's) is renewed for another `timeout_s` + 300 seconds.
    pub running: Option<Value>,
    /// Advisory facts: `surfaces`, `harness_config`, `vault_sync`,
    /// `native_sessions` and `code_sha` replace those keys and keep the rest.
    /// Any other key is dropped and named in `dropped_fact_keys`; host facts
    /// such as roots, repos and harnesses change only by registering again.
    pub facts: Option<Value>,
    /// Progress note for the running item, recorded on the ledger (at most
    /// 2000 characters).
    pub progress: Option<Value>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeListArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetireArgs {
    /// Node name.
    pub node: String,
    /// Why, 1-500 characters. Required; recorded on the ledger (and, for a
    /// retirement, on the row).
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReassignArgs {
    /// Node name.
    pub node: String,
    /// The agent label that owns the node from now on.
    pub to_agent: String,
    /// Why, 1-500 characters. Required; recorded on the ledger.
    pub reason: Option<String>,
}

// --- tools ----------------------------------------------------------------------

fn bounded_version(v: Option<String>) -> UaResult<Option<String>> {
    match v.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) if s.chars().count() <= MAX_VERSION => Ok(Some(s.to_string())),
        Some(_) => Err(UaError::invalid(format!("version must be at most {MAX_VERSION} characters"))),
    }
}

async fn node_register(ctx: ToolCtx, a: RegisterArgs) -> UaResult<Value> {
    let agent = node_agent(&ctx.caller)?;
    let name = validate_node_name(&a.node)?;
    let version = bounded_version(a.version)?;
    let (facts, dropped) = match raw_facts(a.facts)? {
        Some(raw) => bound_facts(&raw),
        None => (Map::new(), Vec::new()),
    };
    let cap = i64::from(ctx.hub.cfg().node_max_per_agent);
    ctx.hub
        .db()
        .write_async(move |tx| {
            let existing: Option<(String, Option<String>, Option<String>, String)> = tx
                .query_row(
                    "SELECT agent, retired_at, version, facts_json FROM nodes WHERE node = ?1",
                    [&name],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            if let Some((owner, retired_at, _, _)) = &existing {
                check_owner(owner, retired_at.is_some(), &name, &agent)?;
            } else {
                let held: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM nodes WHERE agent = ?1 AND retired_at IS NULL",
                    [&agent],
                    |r| r.get(0),
                )?;
                if held >= cap {
                    return Err(UaError::denied(
                        "node_limit",
                        format!(
                            "agent {agent:?} already holds {held} node(s) in service, the limit \
                             (node_max_per_agent = {cap}); an operator must retire one first"
                        ),
                    ));
                }
            }
            // Which ledgered facts differ from the stored row (all of them
            // on a first registration).
            let new_identity = identity_facts(version.as_deref(), &facts);
            let changed: Vec<String> = match &existing {
                None => new_identity.keys().cloned().collect(),
                Some((_, _, old_version, old_facts)) => {
                    let old = identity_facts(old_version.as_deref(), &load_facts(old_facts));
                    new_identity.iter().filter(|(k, v)| old.get(*k) != Some(*v)).map(|(k, _)| k.clone()).collect()
                }
            };
            // A device acceptance vouched for the code and harnesses the node
            // had: a registration that changes them ends it.
            if let Some((_, _, _, old_facts)) = &existing {
                let moved = moved_acceptance_facts(&load_facts(old_facts), &facts);
                if !moved.is_empty() {
                    let why = format!("node_changed ({})", moved.join(", "));
                    super::node_queue::acceptance::void_tx(tx, &name, &why, false)?;
                }
            }
            let now = ua_core::time::now();
            let facts_json = Value::Object(facts.clone()).to_string();
            // A registration is a fresh beat, so the fence set by retire or
            // un-retire is no longer needed.
            tx.execute(
                "INSERT INTO nodes (node, agent, facts_json, version, registered_at, last_heartbeat, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5) \
                 ON CONFLICT(node) DO UPDATE SET facts_json = excluded.facts_json, version = excluded.version, \
                 last_heartbeat = excluded.last_heartbeat, heartbeat_floor = NULL, updated_at = excluded.updated_at",
                params![name, agent, facts_json, version, now],
            )?;
            let first = existing.is_none();
            // An identical re-registration (a node restarting) is not news.
            let ledgered = !changed.is_empty();
            if ledgered {
                let mut payload = json!({
                    "kind": "register",
                    "node": name,
                    "agent": agent,
                    "first_registration": first,
                    "changed": changed,
                });
                // Names and counts only: the ledger is read more widely than
                // the node's own facts, so paths stay out of it.
                for (k, v) in &new_identity {
                    payload[k] = match k.as_str() {
                        "worktree_roots" | "repos" => json!(v.as_array().map_or(0, Vec::len)),
                        _ => v.clone(),
                    };
                }
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "agent.node.register", payload).by(agent.clone()))?;
            }
            Ok(json!({
                "node": name,
                "agent": agent,
                "registered": true,
                "first_registration": first,
                "changed": changed,
                "ledgered": ledgered,
                "as_of": now,
                "hub_features": HUB_FEATURES,
                "dropped_fact_keys": dropped,
            }))
        })
        .await
}

async fn node_heartbeat(ctx: ToolCtx, a: HeartbeatArgs) -> UaResult<Value> {
    let agent = node_agent(&ctx.caller)?;
    let name = validate_node_name(&a.node)?;
    let update = raw_facts(a.facts)?;
    let running = match a.running {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s),
        Some(Value::String(_)) => None,
        Some(_) => return Err(UaError::invalid("running must be an item id or null")),
    };
    let progress = a.progress.as_ref().and_then(Value::as_str).map(str::to_string);
    ctx.hub
        .db()
        .write_async(move |tx| {
            let row: Option<(String, Option<String>, String)> = tx
                .query_row("SELECT agent, retired_at, facts_json FROM nodes WHERE node = ?1", [&name], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .optional()?;
            let Some((owner, retired_at, stored)) = row else {
                return Err(UaError::not_found(format!("node {name:?} is not registered")));
            };
            check_owner(&owner, retired_at.is_some(), &name, &agent)?;
            let now = ua_core::time::now();
            let mut dropped = Vec::new();
            if let Some(update) = update.filter(|u| !u.is_empty()) {
                let old = load_facts(&stored);
                let (facts, d) = heartbeat_facts(old.clone(), &update);
                dropped = d;
                let moved = moved_acceptance_facts(&old, &facts);
                if !moved.is_empty() {
                    let why = format!("node_changed ({})", moved.join(", "));
                    super::node_queue::acceptance::void_tx(tx, &name, &why, false)?;
                }
                tx.execute(
                    "UPDATE nodes SET facts_json = ?2 WHERE node = ?1",
                    params![name, Value::Object(facts).to_string()],
                )?;
            }
            // Liveness itself is not ledgered.
            tx.execute(
                "UPDATE nodes SET last_heartbeat = ?2, updated_at = ?2 WHERE node = ?1",
                params![name, now],
            )?;
            let cancel =
                super::node_queue::on_heartbeat(tx, &name, &agent, running.as_deref(), progress.as_deref())?;
            Ok(json!({ "node": name, "as_of": now, "cancel": cancel, "dropped_fact_keys": dropped }))
        })
        .await
}

async fn node_list(ctx: ToolCtx, _a: NodeListArgs) -> UaResult<Value> {
    // Full facts for the node's own agent and for lifecycle operators; a
    // summary for everyone else, including unverified callers.
    let viewer = verified(&ctx.caller).map(str::to_string);
    let operator =
        Authz::new(ctx.hub.cfg()).holds(&ctx.caller, &[Authority::LifecycleOperator], ua_core::DEFAULT_ORG);
    ctx.hub
        .db()
        .read_async(move |c| {
            let now = Timestamp::now();
            let (retired, nodes): (Vec<Value>, Vec<Value>) =
                read_nodes(c, now)?.into_iter().partition(|n| n["status"] == "retired");
            let nodes: Vec<Value> = nodes
                .into_iter()
                .map(|n| {
                    let mine = viewer.as_deref().is_some_and(|v| n["agent"] == v);
                    if operator || mine { n } else { summary(&n) }
                })
                .collect();
            let mut counts = json!({ "live": 0, "stale": 0, "offline": 0 });
            for n in &nodes {
                if let Some(s) = n["status"].as_str() {
                    counts[s] = json!(counts[s].as_i64().unwrap_or(0) + 1);
                }
            }
            let retired_nodes: Vec<Value> = retired
                .iter()
                .map(|n| {
                    json!({
                        "node": n["node"],
                        "agent": n["agent"],
                        "last_heartbeat": n["last_heartbeat"],
                        "retired_at": n["retired_at"],
                        "retired_by": n["retired_by"],
                        "retired_reason": n["retired_reason"],
                    })
                })
                .collect();
            Ok(json!({
                "nodes": nodes,
                "retired_nodes": retired_nodes,
                "counts": counts,
                "as_of": ua_core::time::format_ts(now),
            }))
        })
        .await
}

/// The verified lifecycle operator running `verb`, else a refusal. The
/// node's own agent is not enough.
fn lifecycle_operator(ctx: &ToolCtx, verb: &str) -> UaResult<String> {
    let Some(who) = verified(&ctx.caller) else {
        return Err(UaError::denied(
            "identity_required",
            format!("{verb} a node requires an authenticated identity"),
        ));
    };
    if !Authz::new(ctx.hub.cfg()).holds(&ctx.caller, &[Authority::LifecycleOperator], ua_core::DEFAULT_ORG) {
        return Err(UaError::denied(
            "not_lifecycle_operator",
            format!(
                "{who:?} may not {verb} a node: that is a lifecycle operator action (lifecycle_operators)"
            ),
        ));
    }
    Ok(who.to_string())
}

fn retire_reason(raw: Option<&str>) -> UaResult<String> {
    let text = raw.unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        return Err(UaError::invalid("a reason is required"));
    }
    if text.chars().count() > MAX_RETIRE_REASON {
        return Err(UaError::invalid(format!("reason must be at most {MAX_RETIRE_REASON} characters")));
    }
    Ok(text)
}

/// A conflict while any [`RETIRE_BLOCKERS`] probe reports queued or claimed
/// work for `name`, so no work is stranded by `doing` (retiring, reassigning
/// or forgetting the node).
fn refuse_open_work(tx: &mut WriteTx<'_>, name: &str, doing: &str) -> UaResult<()> {
    let mut open: Vec<String> = Vec::new();
    for probe in RETIRE_BLOCKERS {
        open.extend(probe(tx, name)?);
    }
    if open.is_empty() {
        return Ok(());
    }
    open.truncate(20);
    Err(UaError::conflict(format!(
        "node {name:?} has queued or claimed work ({}); cancel it before {doing} the node",
        open.join(", ")
    )))
}

/// `agent, last_heartbeat, retired_at, retired_by, retired_reason`.
type RetireRow = (String, Option<String>, Option<String>, Option<String>, Option<String>);

fn set_retired(tx: &mut WriteTx<'_>, name: &str, who: &str, reason: &str, retire: bool) -> UaResult<Value> {
    let row: Option<RetireRow> = tx
        .query_row(
            "SELECT agent, last_heartbeat, retired_at, retired_by, retired_reason FROM nodes WHERE node = ?1",
            [name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((agent, last_heartbeat, retired_at, retired_by, retired_reason)) = row else {
        return Err(UaError::not_found(format!("node {name:?} is not registered")));
    };
    if retired_at.is_some() == retire {
        return Ok(json!({
            "node": name,
            "retired": retire,
            "changed": false,
            "retired_at": retired_at,
            "retired_by": retired_by,
            "retired_reason": retired_reason,
        }));
    }
    if retire {
        refuse_open_work(tx, name, "retiring")?;
    }
    let now = ua_core::time::now();
    // Either way the stored beat becomes the fence: it predates the refusal,
    // so only a newer registration or heartbeat makes the node live again.
    if retire {
        tx.execute(
            "UPDATE nodes SET retired_at = ?2, retired_by = ?3, retired_reason = ?4, \
             heartbeat_floor = last_heartbeat, updated_at = ?2 WHERE node = ?1",
            params![name, now, who, reason],
        )?;
    } else {
        tx.execute(
            "UPDATE nodes SET retired_at = NULL, retired_by = NULL, retired_reason = NULL, \
             heartbeat_floor = last_heartbeat, updated_at = ?2 WHERE node = ?1",
            params![name, now],
        )?;
    }
    let kind = if retire { "retire" } else { "unretire" };
    if retire {
        super::node_queue::acceptance::void_tx(tx, name, "node_retired", false)?;
    }
    let event = ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            format!("agent.node.{kind}"),
            json!({
                "kind": kind,
                "node": name,
                "agent": agent,
                "actor": who,
                "reason": reason,
                "last_heartbeat": last_heartbeat,
                "at": now,
            }),
        )
        .by(who.to_string()),
    )?;
    Ok(json!({
        "node": name,
        "retired": retire,
        "changed": true,
        "retired_at": retire.then_some(&now),
        "retired_by": retire.then_some(who),
        "retired_reason": retire.then_some(reason),
        "event_ulid": event.map(|e| e.ulid),
    }))
}

async fn change_retirement(ctx: ToolCtx, a: RetireArgs, retire: bool) -> UaResult<Value> {
    let who = lifecycle_operator(&ctx, if retire { "retire" } else { "un-retire" })?;
    let name = validate_node_name(&a.node)?;
    let reason = retire_reason(a.reason.as_deref())?;
    ctx.hub.db().write_async(move |tx| set_retired(tx, &name, &who, &reason, retire)).await
}

/// `coordination_manage(action="node_retire")`.
pub(crate) async fn node_retire(ctx: ToolCtx, a: RetireArgs) -> UaResult<Value> {
    change_retirement(ctx, a, true).await
}

/// `coordination_manage(action="node_unretire")`.
pub(crate) async fn node_unretire(ctx: ToolCtx, a: RetireArgs) -> UaResult<Value> {
    change_retirement(ctx, a, false).await
}

fn reassign(tx: &mut WriteTx<'_>, name: &str, to: &str, who: &str, reason: &str) -> UaResult<Value> {
    let row: Option<RetireRow> = tx
        .query_row(
            "SELECT agent, last_heartbeat, retired_at, retired_by, retired_reason FROM nodes WHERE node = ?1",
            [name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((from, last_heartbeat, retired_at, _, _)) = row else {
        return Err(UaError::not_found(format!("node {name:?} is not registered")));
    };
    if from == to {
        return Ok(json!({ "node": name, "agent": to, "changed": false }));
    }
    refuse_open_work(tx, name, "reassigning")?;
    let now = ua_core::time::now();
    // The stored beat was the previous owner's: the new owner's node is not
    // live until it registers or beats itself.
    tx.execute(
        "UPDATE nodes SET agent = ?2, heartbeat_floor = last_heartbeat, updated_at = ?3 WHERE node = ?1",
        params![name, to, now],
    )?;
    super::node_queue::acceptance::void_tx(tx, name, "node_reassigned", false)?;
    super::harness_config::close_for_node(tx, name, "node_reassigned", who)?;
    let event = ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            "agent.node.reassign",
            json!({
                "kind": "reassign",
                "node": name,
                "from_agent": from,
                "to_agent": to,
                "actor": who,
                "reason": reason,
                "retired": retired_at.is_some(),
                "last_heartbeat": last_heartbeat,
                "at": now,
            }),
        )
        .by(who.to_string()),
    )?;
    Ok(json!({
        "node": name,
        "agent": to,
        "previous_agent": from,
        "changed": true,
        "retired": retired_at.is_some(),
        "event_ulid": event.map(|e| e.ulid),
    }))
}

fn forget(tx: &mut WriteTx<'_>, name: &str, who: &str, reason: &str) -> UaResult<Value> {
    let row: Option<RetireRow> = tx
        .query_row(
            "SELECT agent, last_heartbeat, retired_at, retired_by, retired_reason FROM nodes WHERE node = ?1",
            [name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((agent, last_heartbeat, retired_at, retired_by, retired_reason)) = row else {
        return Err(UaError::not_found(format!("node {name:?} is not registered")));
    };
    if retired_at.is_none() {
        return Err(UaError::conflict(format!(
            "node {name:?} is in service; retire it (coordination_manage node_retire) before forgetting it"
        )));
    }
    refuse_open_work(tx, name, "forgetting")?;
    super::node_queue::acceptance::void_tx(tx, name, "node_forgotten", true)?;
    super::harness_config::close_for_node(tx, name, "node_forgotten", who)?;
    tx.execute("DELETE FROM nodes WHERE node = ?1", [name])?;
    let now = ua_core::time::now();
    let event = ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            "agent.node.forget",
            json!({
                "kind": "forget",
                "node": name,
                "agent": agent,
                "actor": who,
                "reason": reason,
                "retired_at": retired_at,
                "retired_by": retired_by,
                "retired_reason": retired_reason,
                "last_heartbeat": last_heartbeat,
                "at": now,
            }),
        )
        .by(who.to_string()),
    )?;
    Ok(json!({ "node": name, "agent": agent, "forgotten": true, "event_ulid": event.map(|e| e.ulid) }))
}

/// `coordination_manage(action="node_reassign")`: move a node name to
/// another agent label (for example after a label change).
pub(crate) async fn node_reassign(ctx: ToolCtx, a: ReassignArgs) -> UaResult<Value> {
    let who = lifecycle_operator(&ctx, "reassign")?;
    let name = validate_node_name(&a.node)?;
    let to = validate_label(Some(&a.to_agent), "to_agent")?;
    let reason = retire_reason(a.reason.as_deref())?;
    ctx.hub.db().write_async(move |tx| reassign(tx, &name, &to, &who, &reason)).await
}

/// `coordination_manage(action="node_forget")`: delete a retired node's row
/// so its name can be registered afresh.
pub(crate) async fn node_forget(ctx: ToolCtx, a: RetireArgs) -> UaResult<Value> {
    let who = lifecycle_operator(&ctx, "forget")?;
    let name = validate_node_name(&a.node)?;
    let reason = retire_reason(a.reason.as_deref())?;
    ctx.hub.db().write_async(move |tx| forget(tx, &name, &who, &reason)).await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "node_register",
            "Register (or re-register) a remote node under the calling agent. The owner is the verified agent; a node name another agent registered is refused (node_owned_elsewhere), a retired node is refused (node_retired), and a new name past node_max_per_agent nodes in service is refused (node_limit). Facts are bounded and unknown keys dropped. Ledgered only when first registered or when version, backends, harness names, roots or repos change. Returns {node, agent, registered, first_registration, changed, ledgered, as_of, hub_features, dropped_fact_keys}.",
            node_register,
        )
        .family("nodes"),
    );
    r.add(
        tool(
            "node_heartbeat",
            "Mark the calling agent's node alive and optionally refresh its advisory facts (surfaces, harness_config, vault_sync, native_sessions, code_sha); other fact keys are dropped and reported. Not ledgered. Refused for a node another agent owns, an unregistered node (not_found) or a retired one (node_retired). Returns {node, as_of, cancel, dropped_fact_keys}.",
            node_heartbeat,
        )
        .family("nodes"),
    );
    r.add(
        tool(
            "node_list",
            "List registered nodes with liveness derived at read time: status live (heartbeat within 90s, at most 60s in the future), stale, offline or retired, plus heartbeat_status (online/idle/stale/offline/unknown). Retired nodes are left out of `nodes` and listed in `retired_nodes`. Rows carry full facts (detail=full) for the node's own agent and lifecycle operators, otherwise a summary (detail=summary: liveness, version, backends, harness_names). Returns {nodes, retired_nodes, counts, as_of}.",
            node_list,
        )
        .family("nodes")
        .read_only(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: i64) -> Timestamp {
        Timestamp::from_second(s).unwrap()
    }

    fn ts(s: i64) -> String {
        ua_core::time::format_ts(at(s))
    }

    #[test]
    fn heartbeat_status_follows_the_node_window() {
        let now = at(1_000_000);
        let beat = |age: i64| heartbeat_status(Some(at(1_000_000 - age)), now);
        assert_eq!(heartbeat_status(None, now), "unknown");
        assert_eq!(beat(0), "online");
        assert_eq!(beat(NODE_LIVE_WINDOW_S), "online");
        assert_eq!(beat(NODE_LIVE_WINDOW_S + 1), "idle", "past the node window, never online");
        assert_eq!(beat(900), "idle");
        assert_eq!(beat(901), "stale");
        assert_eq!(beat(86_400), "stale");
        assert_eq!(beat(86_401), "offline");
        assert_eq!(beat(-NODE_CLOCK_SKEW_S), "online", "ordinary skew is live");
        assert_eq!(beat(-NODE_CLOCK_SKEW_S - 1), "offline", "a beat far in the future is not");
    }

    #[test]
    fn a_fenced_beat_reads_offline_until_a_newer_one() {
        let now = at(1_000_000);
        let l = liveness(Some(&ts(999_990)), Some(&ts(999_990)), false, now);
        assert_eq!((l.status, l.heartbeat_status, l.live), ("offline", "offline", false));
        assert_eq!(l.live_heartbeat, None);
        let l = liveness(Some(&ts(999_995)), Some(&ts(999_990)), false, now);
        assert_eq!((l.status, l.live), ("live", true));
        assert_eq!(liveness(Some(&ts(999_995)), None, true, now).status, "retired");
    }

    #[test]
    fn bounded_facts_are_shed_to_fit() {
        // Each session's cwd is stored twice (cwd and cwd_realpath), so a
        // report under the cap can bound to one over it.
        let deep = format!("/srv/work/{}", "d".repeat(1200));
        let sessions: Vec<Value> = (0..50)
            .map(|i| json!({ "harness": "codex", "external_session_id": format!("s{i}"), "cwd_realpath": deep }))
            .collect();
        let raw = json!({ "worktree_roots": [{ "path": "/srv/work", "realpath": "/srv/work" }], "native_sessions": sessions });
        let raw = raw.as_object().unwrap().clone();
        assert!(encoded_len(&raw) <= MAX_FACTS_BYTES);
        let (out, dropped) = bound_facts(&raw);
        assert!(dropped.is_empty());
        assert!(encoded_len(&out) <= MAX_FACTS_BYTES);
        let kept = out["native_sessions"].as_array().unwrap().len();
        assert!(kept > 0 && kept < 50, "{kept}");
        assert_eq!(out["worktree_roots"][0]["path"], "/srv/work", "roots are kept while sessions shed");
    }

    #[test]
    fn node_names_and_paths() {
        assert!(validate_node_name("node-a.example_1").is_ok());
        for bad in ["", "-node", "node a", "node/a", &"n".repeat(129)] {
            assert!(validate_node_name(bad).is_err(), "{bad:?}");
        }
        let roots = vec!["/srv/work".to_string()];
        assert!(path_in_roots("/srv/work", &roots));
        assert!(path_in_roots("/srv/work/repo/./x", &roots));
        assert!(!path_in_roots("/srv/workshop", &roots), "components, not a prefix");
        assert!(!path_in_roots("/srv/work/../etc", &roots));
        assert!(!path_in_roots("srv/work/x", &roots));
    }
}
