//! Session credentials: a short-lived, revocable hub credential for the ACP
//! session a node launches for one claimed item.
//!
//! The node's agent asks for one with `node_session_credential`
//! (`POST /api/node/session_credential`, body `{node, item_id, attempt}`).
//! The value is `uas_` plus 43 base64url characters (32 random bytes). It is
//! returned once and never stored, logged or ledgered: the table keeps its
//! SHA-256 only, and events carry the public `credential_id` (16 hex).
//!
//! Binding comes from rows the hub owns, never from the request: the subject
//! is the item's agent, and the credential is bound to the node, the item
//! and the claim's attempt (and so to the item's task and run). It expires
//! at the claim's lease deadline (`claimed_at + timeout_s + 300`); an idle
//! window of [`IDLE_WINDOW_S`] (never past the expiry) is slid forward by
//! the node's heartbeats for the running item. A second mint for the same
//! item and attempt revokes the first (`superseded`).
//!
//! The HTTP adapter runs [`verify`] on every request; nothing is cached. A
//! verified request runs as the subject under the `acp-session` profile and
//! the grant ([`crate::grant`]): the tools in [`Profile::AcpSession`]'s list
//! that the subject's own profile also exposes, with `task_comment` confined
//! to the item's task.
//!
//! A credential stops working when the item's receipt arrives
//! (`session_end`), the item is cancelled (`cancelled`), its lease lapses
//! (`lease_expired`), its task is closed or deleted (`task_closed`,
//! `task_deleted`, found on the next request), the agent is retired
//! (`agent_retired`), an operator revokes it (`operator`, through
//! `coordination_manage session_credential_revoke`), or its windows lapse
//! (`expired`, `idle_expired`). Turning `session_credentials_enabled` off
//! refuses every outstanding credential at once.
//!
//! Events: `hub.session_credential.minted`, `.revoked` (one per credential)
//! and `.refused` (the failed check, rate-limited per check).

use std::collections::{BTreeSet, HashMap};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{SignedDuration, Timestamp};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::time::{format_ts, parse_ts};
use ua_core::{Profile, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use super::{LEASE_GRACE_S, check_item_id, device_agent, load_item, load_node, owned_node, run_gate};
use crate::families::{governance, nodes};
use crate::grant::SessionGrant;
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, tool};
use ua_org::authz::{Authority, Authz};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "session_credentials.v1",
    sql: "
CREATE TABLE IF NOT EXISTS session_credentials (
    credential_id TEXT PRIMARY KEY,
    token_sha256 TEXT NOT NULL UNIQUE,
    agent_label TEXT NOT NULL,
    node TEXT NOT NULL,
    item_id TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    task_id INTEGER,
    run_id TEXT,
    tools_json TEXT NOT NULL,
    issued_by TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT,
    revoke_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_session_credentials_item ON session_credentials(item_id, attempt);
CREATE INDEX IF NOT EXISTS idx_session_credentials_node ON session_credentials(node);
CREATE INDEX IF NOT EXISTS idx_session_credentials_agent ON session_credentials(agent_label);
",
};

/// Every session credential starts with this.
pub const PREFIX: &str = "uas_";
/// The node feature a node advertises when it can use a session credential;
/// the hub lists it in `hub_features` too.
pub const FEATURE: &str = "acp_session_mcp";
/// The MCP server name a node gives the harness for the hub.
pub const MCP_SERVER_NAME: &str = "unified-agent";
/// Sliding idle window, renewed by the node's heartbeats for the item.
pub const IDLE_WINDOW_S: i64 = 600;

pub const CHANNEL_MINTED: &str = "hub.session_credential.minted";
pub const CHANNEL_REVOKED: &str = "hub.session_credential.revoked";
pub const CHANNEL_REFUSED: &str = "hub.session_credential.refused";

/// A refused-check event is written at most this often per (subject, check).
const REFUSED_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// `last_used_at` is written at most this often per credential.
const LAST_USED_RESOLUTION_S: i64 = 30;
const VALUE_TAIL: usize = 43;

const PUBLIC_COLUMNS: &str = "credential_id, agent_label, node, item_id, attempt, task_id, run_id, tools_json, \
    issued_by, issued_at, idle_expires_at, expires_at, last_used_at, revoked_at, revoke_reason";

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Whether a bearer value is in the session-credential namespace. Routing is
/// by prefix alone, so a malformed `uas_` value never reaches another check.
pub fn is_session_token(token: &str) -> bool {
    token.starts_with(PREFIX)
}

fn well_formed(token: &str) -> bool {
    token.strip_prefix(PREFIX).is_some_and(|t| {
        t.len() == VALUE_TAIL && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

fn valid_credential_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn plus(t: Timestamp, secs: i64) -> Timestamp {
    t.checked_add(SignedDuration::from_secs(secs)).unwrap_or(Timestamp::MAX)
}

/// The `acp-session` list, narrowed by `label`'s own default profile: a
/// credential never reaches a tool its subject could not.
fn ceiling(hub: &Hub, label: &str) -> BTreeSet<String> {
    let own = crate::sessions::default_profile(hub, label);
    crate::builtin_registry_shared()
        .all()
        .map(|t| t.name)
        .filter(|t| Profile::AcpSession.allows_tool(t) && own.allows_tool(t))
        .map(str::to_string)
        .collect()
}

// --- revocation -----------------------------------------------------------------

/// Revoke every active credential matching `clause` (one of this module's
/// constant clauses) in the caller's transaction, with one `.revoked` event
/// each. Returns the ids.
fn revoke_where(
    tx: &mut WriteTx<'_>,
    clause: &str,
    p: &[&dyn rusqlite::ToSql],
    reason: &str,
    actor: Option<&str>,
) -> UaResult<Vec<String>> {
    let ids: Vec<String> = {
        let mut stmt = tx.prepare(&format!(
            "SELECT credential_id FROM session_credentials WHERE revoked_at IS NULL AND ({clause}) ORDER BY issued_at"
        ))?;
        stmt.query_map(p, |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    let ts = ua_core::time::now();
    for id in &ids {
        tx.execute(
            "UPDATE session_credentials SET revoked_at = ?2, revoke_reason = ?3 \
             WHERE credential_id = ?1 AND revoked_at IS NULL",
            params![id, ts, reason],
        )?;
        let mut ev = EventInput::new(
            ua_core::DEFAULT_ORG,
            CHANNEL_REVOKED,
            json!({ "credential_id": id, "reason": reason, "actor": actor }),
        );
        if let Some(a) = actor {
            ev = ev.by(a.to_string());
        }
        ledger::append(tx, ev)?;
    }
    Ok(ids)
}

/// Revoke the credentials of item `item_id` (receipt, cancel, lease expiry).
pub(crate) fn revoke_for_item(
    tx: &mut WriteTx<'_>,
    item_id: &str,
    reason: &str,
    actor: &str,
) -> UaResult<Vec<String>> {
    revoke_where(tx, "item_id = ?1", &[&item_id], reason, Some(actor))
}

/// Revoke the credentials running as `agent` (agent retirement).
pub(crate) fn revoke_for_agent(
    tx: &mut WriteTx<'_>,
    agent: &str,
    reason: &str,
    actor: &str,
) -> UaResult<Vec<String>> {
    revoke_where(tx, "agent_label = ?1 COLLATE NOCASE", &[&agent], reason, Some(actor))
}

/// Slide the idle window of `item_id`'s live credentials forward, in the
/// heartbeat's transaction. Never past the expiry, never reviving a lapsed
/// window.
pub(crate) fn slide_idle(tx: &mut WriteTx<'_>, item_id: &str, node: &str) -> UaResult<()> {
    let now = Timestamp::now();
    let rows: Vec<(String, String, String)> = {
        let mut stmt = tx.prepare(
            "SELECT credential_id, idle_expires_at, expires_at FROM session_credentials \
             WHERE item_id = ?1 AND node = ?2 AND revoked_at IS NULL",
        )?;
        stmt.query_map(params![item_id, node], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?
    };
    for (id, idle, cap) in rows {
        let (Some(idle), Some(cap)) = (parse_ts(&idle), parse_ts(&cap)) else { continue };
        if idle <= now {
            continue;
        }
        let renewed = plus(now, IDLE_WINDOW_S).min(cap);
        if renewed > idle {
            tx.execute(
                "UPDATE session_credentials SET idle_expires_at = ?2 WHERE credential_id = ?1 AND revoked_at IS NULL",
                params![id, format_ts(renewed)],
            )?;
        }
    }
    Ok(())
}

// --- refusal events -------------------------------------------------------------

/// At most this many `.refused` events per check per interval, across
/// subjects: a spray of random values cannot flood the ledger.
const REFUSED_PER_CHECK_CAP: usize = 32;
/// The rate-limit map is pruned of expired entries past this size.
const REFUSED_MAP_PRUNE: usize = 1024;

static REFUSED_LAST: LazyLock<Mutex<HashMap<(String, String), Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether a `.refused` event for (`check`, `subject`) is due: at most one
/// per pair per interval, and at most [`REFUSED_PER_CHECK_CAP`] per check.
fn refusal_due(check: &str, subject: &str) -> bool {
    let mut last = REFUSED_LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.len() > REFUSED_MAP_PRUNE {
        last.retain(|_, t| t.elapsed() < REFUSED_LOG_INTERVAL);
    }
    let key = (check.to_string(), subject.to_string());
    if last.get(&key).is_some_and(|t| t.elapsed() < REFUSED_LOG_INTERVAL) {
        return false;
    }
    let recent = last.iter().filter(|((c, _), t)| c == check && t.elapsed() < REFUSED_LOG_INTERVAL).count();
    if recent >= REFUSED_PER_CHECK_CAP {
        return false;
    }
    last.insert(key, Instant::now());
    true
}

/// What a refusal is rate-limited by: the credential when one was found,
/// else a short prefix of the presented value's SHA-256 (never the value).
fn refusal_subject(credential_id: Option<&str>, token: Option<&str>) -> String {
    match (credential_id, token) {
        (Some(id), _) => format!("cred:{id}"),
        (None, Some(t)) => format!("sha:{}", &digest(t)[..16]),
        (None, None) => "-".into(),
    }
}

/// A rate-limited `.refused` event naming the failed check, never a value.
/// Limited per (credential or presented value, check), so repeated replays
/// of different credentials are each ledgered.
fn record_refused(hub: &Hub, check: &str, credential_id: Option<&str>, subject: &str) {
    if !refusal_due(check, subject) {
        return;
    }
    let mut payload = json!({ "check": check });
    if let Some(id) = credential_id {
        payload["credential_id"] = json!(id);
    }
    let res = hub.db().write(move |tx| {
        ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, CHANNEL_REFUSED, payload))?;
        Ok(())
    });
    if let Err(e) = res {
        tracing::warn!(error = %e, "session credential refusal was not recorded");
    }
}

// --- mint -----------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MintArgs {
    /// Your node's name.
    pub node: String,
    /// The claimed ACP item the session runs (`nd-` + 16 hex).
    pub item_id: String,
    /// The claim's attempt, as `node_claim` returned it.
    pub attempt: Value,
}

fn refuse(code: &str, msg: impl Into<String>) -> UaError {
    UaError::denied(code, msg)
}

fn conflict(code: &str, msg: impl Into<String>) -> UaError {
    UaError::conflict_code(code, msg)
}

fn mint_tx(
    tx: &mut WriteTx<'_>,
    hub: &Hub,
    agent: &str,
    node: &str,
    item_id: &str,
    attempt: i64,
) -> UaResult<Value> {
    // Ownership: another label's node, or a retired node, is a binding failure.
    let row = owned_node(tx, node, agent).map_err(|e| match e {
        UaError::NotFound(m) => conflict("node_binding", m),
        UaError::Denied { reason, .. } => refuse("node_binding", reason),
        other => other,
    })?;
    let node = row.node.clone();
    if !row.has_feature(FEATURE) {
        return Err(conflict("node_feature_missing", format!("node {node:?} did not advertise {FEATURE}")));
    }
    let Some(item) = load_item(tx, item_id)?.filter(|i| i.node == node) else {
        return Err(conflict("item_not_found", format!("item {item_id} is not queued for node {node:?}")));
    };
    if !item.is_acp() {
        return Err(conflict("not_acp", "session credentials are issued for ACP items only"));
    }
    if item.status != "claimed" {
        return Err(conflict("item_not_claimed", format!("item {item_id} is {}, not claimed", item.status)));
    }
    if item.attempts != attempt {
        return Err(conflict("stale_attempt", format!("attempt {attempt} is not the item's current claim")));
    }
    let now = Timestamp::now();
    let lease = item.lease_expires_at.as_deref().and_then(parse_ts);
    let claimed = item.claimed_at.as_deref().and_then(parse_ts);
    let (Some(lease), Some(claimed)) = (lease, claimed) else {
        return Err(conflict("lease_expired", "the item's lease has expired"));
    };
    if lease <= now {
        return Err(conflict("lease_expired", "the item's lease has expired"));
    }
    if item.cancel_requested || run_gate(tx, &item)?.is_some() {
        return Err(conflict("cancel_requested", "the item is being cancelled"));
    }
    // The claim's lease deadline; heartbeats never move it.
    let expires = plus(claimed, item.timeout_s + LEASE_GRACE_S);
    if expires <= now {
        return Err(conflict("lease_expired", "the item's lease has expired"));
    }
    let subject = item.agent.clone();
    // The session runs as the item's agent, which must be the node's owner:
    // verify() would refuse any other subject on every request (node_stale).
    if subject != row.agent {
        return Err(refuse(
            "node_binding",
            format!(
                "item {item_id} runs as {subject:?}, not as node {node:?}'s agent; no credential is minted"
            ),
        ));
    }
    if governance::is_retired(tx, &subject)? {
        return Err(refuse(
            "agent_retired",
            format!("agent {subject:?} is retired; no session credential is minted for it"),
        ));
    }
    if hub.cfg().revoked_agents.iter().any(|r| r.eq_ignore_ascii_case(&subject)) {
        return Err(refuse("label_refused", "the session's agent label is revoked"));
    }
    if hub.cfg().is_human(&subject) {
        return Err(refuse("human_subject", "a session credential is never minted for a human identity"));
    }
    // A runner path: the item's task is read in the task row's own
    // organization (the enqueuer's, `insert_item`).
    if let Some(task_id) = item.task_id {
        let org = crate::families::tasks::task_org(tx, task_id)?.unwrap_or_default();
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM tasks WHERE org_id = ?1 AND id = ?2",
                rusqlite::params![org, task_id],
                |r| r.get(0),
            )
            .optional()?;
        if status.as_deref().is_none_or(|s| matches!(s, "done" | "cancelled")) {
            return Err(conflict("task_closed", "the item's task is closed or missing"));
        }
    }
    let tools: Vec<String> = ceiling(hub, &subject).into_iter().collect();
    let idle = plus(now, IDLE_WINDOW_S).min(expires);

    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let value = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
    let mut idb = [0u8; 8];
    rand::rng().fill_bytes(&mut idb);
    let credential_id = hex::encode(idb);
    if !well_formed(&value) {
        return Err(UaError::internal("credential generation failed"));
    }

    // At most one active credential per (item, attempt).
    let superseded =
        revoke_where(tx, "item_id = ?1 AND attempt = ?2", &[&item_id, &attempt], "superseded", Some(agent))?;
    let issued = ua_core::time::now();
    tx.execute(
        "INSERT INTO session_credentials (credential_id, token_sha256, agent_label, node, item_id, attempt, task_id, \
         run_id, tools_json, issued_by, issued_at, idle_expires_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            credential_id,
            digest(&value),
            subject,
            node,
            item_id,
            attempt,
            item.task_id,
            item.run_id,
            json!(tools).to_string(),
            agent,
            issued,
            format_ts(idle),
            format_ts(expires),
        ],
    )?;
    ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            CHANNEL_MINTED,
            json!({
                "credential_id": credential_id,
                "item_id": item_id,
                "attempt": attempt,
                "node": node,
                "task_id": item.task_id,
                "run_id": item.run_id,
                "agent_label": subject,
                "tools": tools,
                "idle_expires_at": format_ts(idle),
                "expires_at": format_ts(expires),
                "superseded": superseded,
            }),
        )
        .by(agent.to_string()),
    )?;
    Ok(json!({
        "credential": value,
        "credential_id": credential_id,
        "expires_at": format_ts(expires),
        "idle_expires_at": format_ts(idle),
        "tools": tools,
        "mcp_server_name": MCP_SERVER_NAME,
    }))
}

async fn node_session_credential(ctx: ToolCtx, a: MintArgs) -> UaResult<Value> {
    if !ctx.hub.cfg().session_credentials_enabled {
        return Err(refuse(
            "disabled",
            "session credentials are off on this hub (session_credentials_enabled)",
        ));
    }
    // A session credential never mints another one.
    if crate::grant::current().is_some() {
        return Err(refuse("node_binding", "a session credential cannot mint credentials"));
    }
    let agent = device_agent(&ctx.caller)?;
    let node = nodes::validate_node_name(&a.node)?;
    let item_id = check_item_id(&a.item_id)?;
    let attempt = match &a.attempt {
        Value::Number(n) if n.as_i64().is_some_and(|v| v >= 1) => n.as_i64().unwrap_or(0),
        _ => return Err(UaError::invalid("attempt must be a positive integer")),
    };
    let hub = ctx.hub.clone();
    let subject = format!("item:{item_id}");
    let out = ctx.hub.db().write_async(move |tx| mint_tx(tx, &hub, &agent, &node, &item_id, attempt)).await;
    if let Err(e) = &out
        && let Some(code) = e.reason_code()
    {
        let (hub, check) = (ctx.hub.clone(), format!("mint:{code}"));
        let _ = tokio::task::spawn_blocking(move || record_refused(&hub, &check, None, &subject)).await;
    }
    out
}

// --- per-request verification ---------------------------------------------------

/// A credential the hub let in: who it runs as, and its grant.
#[derive(Debug, Clone)]
pub struct Verified {
    pub subject: String,
    pub grant: SessionGrant,
}

/// Why a presented credential was refused: a short check name, never secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub check: &'static str,
}

/// What the read half of [`verify`] decided.
enum Decision {
    Refuse(&'static str, Option<String>),
    Lapse(&'static str, String),
    Admit { row: CredRow, touch: bool },
}

struct CredRow {
    credential_id: String,
    agent_label: String,
    item_id: String,
    task_id: Option<i64>,
    tools: Vec<String>,
}

fn decide(c: &Connection, hub: &Hub, token: &str, now: Timestamp) -> UaResult<Decision> {
    type Raw = (
        String,
        String,
        String,
        String,
        i64,
        Option<i64>,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
    );
    let raw: Option<Raw> = c
        .query_row(
            "SELECT credential_id, agent_label, node, item_id, attempt, task_id, tools_json, idle_expires_at, \
             expires_at, last_used_at, revoked_at FROM session_credentials WHERE token_sha256 = ?1",
            [digest(token)],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            },
        )
        .optional()?;
    let Some((id, agent, node, item_id, attempt, task_id, tools, idle, expires, last_used, revoked)) = raw
    else {
        return Ok(Decision::Refuse("unknown_or_revoked", None));
    };
    if revoked.is_some() {
        return Ok(Decision::Refuse("unknown_or_revoked", Some(id)));
    }
    if parse_ts(&expires).is_none_or(|e| now >= e) {
        return Ok(Decision::Lapse("expired", id));
    }
    if parse_ts(&idle).is_none_or(|i| now >= i) {
        return Ok(Decision::Lapse("idle_expired", id));
    }
    let item = load_item(c, &item_id)?;
    let Some(item) = item.filter(|i| i.status == "claimed" && i.node == node && i.attempts == attempt) else {
        return Ok(Decision::Refuse("item_not_live", Some(id)));
    };
    if item.cancel_requested || run_gate(c, &item)?.is_some() {
        return Ok(Decision::Refuse("cancel_requested", Some(id)));
    }
    // The bound task, read live: closed by any path, it ends access.
    if let Some(t) = task_id {
        let org = crate::families::tasks::task_org(c, t)?.unwrap_or_default();
        let status: Option<String> = c
            .query_row(
                "SELECT status FROM tasks WHERE org_id = ?1 AND id = ?2",
                rusqlite::params![org, t],
                |r| r.get(0),
            )
            .optional()?;
        match status.as_deref() {
            None => return Ok(Decision::Lapse("task_deleted", id)),
            Some("done" | "cancelled") => return Ok(Decision::Lapse("task_closed", id)),
            _ => {}
        }
    }
    let node_row = load_node(c, &node)?;
    if node_row.as_ref().is_none_or(|n| n.agent != agent || n.retired || !n.liveness().live) {
        return Ok(Decision::Refuse("node_stale", Some(id)));
    }
    if governance::is_retired(c, &agent)? {
        return Ok(Decision::Lapse("agent_retired", id));
    }
    if hub.cfg().revoked_agents.iter().any(|r| r.eq_ignore_ascii_case(&agent)) || hub.cfg().is_human(&agent) {
        return Ok(Decision::Refuse("label_revoked", Some(id)));
    }
    let touch =
        last_used.as_deref().and_then(parse_ts).is_none_or(|t| (now - t).as_secs() >= LAST_USED_RESOLUTION_S);
    let tools: Vec<String> = serde_json::from_str::<Vec<String>>(&tools).unwrap_or_default();
    Ok(Decision::Admit {
        row: CredRow { credential_id: id, agent_label: agent, item_id, task_id, tools },
        touch,
    })
}

/// Run every per-request check on a presented `uas_` value and return its
/// subject and grant, or the failed check. Reads the database on every call;
/// a lapsed window or a closed task is written as a revocation.
pub fn verify(hub: &Hub, token: &str) -> Result<Verified, Refused> {
    let refused = |check: &'static str, id: Option<&str>| {
        record_refused(hub, check, id, &refusal_subject(id, Some(token)));
        Err(Refused { check })
    };
    if !hub.cfg().session_credentials_enabled {
        return refused("flag_off", None);
    }
    if !well_formed(token) {
        return refused("unknown", None);
    }
    let now = Timestamp::now();
    let decision = match hub.db().read(|c| decide(c, hub, token, now)) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "session credential check failed");
            return Err(Refused { check: "internal" });
        }
    };
    match decision {
        Decision::Refuse(check, id) => refused(check, id.as_deref()),
        Decision::Lapse(reason, id) => {
            let cid = id.clone();
            let res = hub.db().write(move |tx| {
                revoke_where(tx, "credential_id = ?1", &[&cid], reason, None)?;
                Ok(())
            });
            if let Err(e) = res {
                tracing::warn!(error = %e, "a lapsed session credential was not revoked");
            }
            refused(reason, Some(&id))
        }
        Decision::Admit { row, touch } => {
            if touch {
                let id = row.credential_id.clone();
                let ts = format_ts(now);
                let _ = hub.db().write(move |tx| {
                    tx.execute(
                        "UPDATE session_credentials SET last_used_at = ?2 WHERE credential_id = ?1",
                        params![id, ts],
                    )?;
                    Ok(())
                });
            }
            let ceiling = ceiling(hub, &row.agent_label);
            let tools = row.tools.into_iter().filter(|t| ceiling.contains(t)).collect();
            Ok(Verified {
                subject: row.agent_label,
                grant: SessionGrant {
                    tools,
                    credential_id: row.credential_id,
                    item_id: row.item_id,
                    task_id: row.task_id,
                },
            })
        }
    }
}

// --- operator revoke ------------------------------------------------------------

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeArgs {
    /// One credential, by its public id (16 hex).
    pub credential_id: Option<String>,
    /// Every credential of one node item.
    pub item_id: Option<String>,
    /// Every credential minted on one node.
    pub node: Option<String>,
}

/// `coordination_manage(action="session_credential_revoke")`: an operator
/// revokes by exactly one of `credential_id`, `item_id` or `node`. Returns
/// the revoked ids and their metadata, never a value.
pub(crate) async fn session_credential_revoke(ctx: ToolCtx, a: RevokeArgs) -> UaResult<Value> {
    let who = super::verified_caller(&ctx.caller, "revoking session credentials")?;
    if !Authz::new(ctx.hub.cfg()).holds(&ctx.caller, &[Authority::Operator], ua_core::DEFAULT_ORG) {
        return Err(UaError::denied(
            "not_operator",
            "revoking session credentials is for an operator (a verified human)",
        ));
    }
    let chosen =
        [a.credential_id.is_some(), a.item_id.is_some(), a.node.is_some()].iter().filter(|b| **b).count();
    if chosen != 1 {
        return Err(UaError::invalid("pass exactly one of credential_id, item_id or node"));
    }
    let (clause, key) = if let Some(id) = a.credential_id {
        let id = id.trim().to_string();
        if !valid_credential_id(&id) {
            return Err(UaError::invalid("credential_id must be 16 hex characters"));
        }
        ("credential_id = ?1", id)
    } else if let Some(item) = a.item_id {
        ("item_id = ?1", check_item_id(&item)?)
    } else {
        ("node = ?1", nodes::validate_node_name(a.node.as_deref().unwrap_or(""))?)
    };
    ctx.hub
        .db()
        .write_async(move |tx| {
            let ids = revoke_where(tx, clause, &[&key], "operator", Some(&who))?;
            let creds = metadata(tx, &ids)?;
            Ok(json!({ "revoked": ids, "count": ids.len(), "credentials": creds }))
        })
        .await
}

/// The public metadata of credentials, in the given order.
fn metadata(c: &Connection, ids: &[String]) -> UaResult<Vec<Value>> {
    let now = Timestamp::now();
    let mut out = Vec::new();
    for id in ids {
        let row = c
            .query_row(
                &format!("SELECT {PUBLIC_COLUMNS} FROM session_credentials WHERE credential_id = ?1"),
                [id],
                |r| {
                    let tools: String = r.get(7)?;
                    let idle: String = r.get(10)?;
                    let expires: String = r.get(11)?;
                    let revoked: Option<String> = r.get(13)?;
                    let lapsed = [idle.as_str(), expires.as_str()]
                        .iter()
                        .any(|t| parse_ts(t).is_none_or(|t| t <= now));
                    let state = if revoked.is_some() {
                        "revoked"
                    } else if lapsed {
                        "expired"
                    } else {
                        "active"
                    };
                    Ok(json!({
                        "credential_id": r.get::<_, String>(0)?,
                        "agent_label": r.get::<_, String>(1)?,
                        "node": r.get::<_, String>(2)?,
                        "item_id": r.get::<_, String>(3)?,
                        "attempt": r.get::<_, i64>(4)?,
                        "task_id": r.get::<_, Option<i64>>(5)?,
                        "run_id": r.get::<_, Option<String>>(6)?,
                        "tools": serde_json::from_str::<Value>(&tools).unwrap_or(json!([])),
                        "issued_by": r.get::<_, String>(8)?,
                        "issued_at": r.get::<_, String>(9)?,
                        "idle_expires_at": idle,
                        "expires_at": expires,
                        "last_used_at": r.get::<_, Option<String>>(12)?,
                        "revoked_at": revoked,
                        "revoke_reason": r.get::<_, Option<String>>(14)?,
                        "state": state,
                    }))
                },
            )
            .optional()?;
        out.extend(row);
    }
    Ok(out)
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "node_session_credential",
            "Device plane: mint a short-lived hub credential (uas_...) for the ACP session your node runs for one \
             claimed item ({node, item_id, attempt}). The value is returned once. It is bound to the item's agent, \
             node, item and attempt, expires at the claim's lease deadline, idles out after 600 s without a \
             heartbeat for the item, and reaches /mcp and /api/tools with a small read/report tool set. Off unless \
             session_credentials_enabled. A second mint for the same attempt revokes the first.",
            node_session_credential,
        )
        .family("nodes"),
    );
}
