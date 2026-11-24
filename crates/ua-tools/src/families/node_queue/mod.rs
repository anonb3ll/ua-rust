//! The remote-node work queue: items queued for a registered node, claimed by
//! that node's agent, run there, and settled by a receipt.
//!
//! Tools:
//! - `node_dispatch` queues one item (always a one-time human approval, bound
//!   to the node, backend, working directory, prompt, model, timeout and,
//!   for a supervised command, its argv);
//! - the device plane, called by the node under its agent's token:
//!   `node_claim`, `node_receipt`, `node_events`, `node_followups` and
//!   `node_permission`; `node_heartbeat` (in [`super::nodes`]) renews the
//!   running item's lease and relays cancels;
//! - `node_items` lists items, and `node_followup` sends a follow-up into a
//!   live ACP session (an agent's needs a one-time `node_followup` approval);
//! - `coordination_manage` actions `node_item_cancel`, `node_item_restart`,
//!   `node_command_start`, `node_command_status` and `node_command_adopt`.
//!
//! An item is `queued`, then `claimed` (each claim adds one to `attempts`,
//! the attempt fence, and sets a lease of `timeout_s` + [`LEASE_GRACE_S`]),
//! then ends `finished`, `failed`, `killed` or `cancelled`. The first receipt
//! wins (`receipt_json` is the idempotency gate). A receipt must name the
//! attempt it reports (an integer `attempt`; one without it is refused), and
//! one for an earlier attempt is refused. A supervised command must also echo
//! the per-claim fence token. Its free text is redacted before it is stored.
//!
//! Work for a node that is not live waits up to `node_queue_wait_s`, then
//! fails `waiting_expired_node_offline`. A claimed item whose lease lapses
//! fails `lease_expired_outcome_unknown`: the hub cannot tell whether it ran,
//! so it is not restartable until reconciled.
//!
//! A dispatch run routed to a node (`dispatch_task` with `node`) is linked to
//! one item by `evidence_ref = "node:<node>:<item>"`. Only that item moves or
//! closes the run; the dispatch reaper leaves such runs to this queue.
//!
//! A claimed ACP item's session can get its own short-lived hub credential
//! ([`credentials`], `node_session_credential`), and a node can pass a
//! harmless device acceptance run before real work (`acceptance`,
//! `coordination_manage` `node_acceptance_*`).
//!
//! Every change is ledgered on `agent.node` in the same transaction.

pub(crate) mod acceptance;
mod claim;
pub(crate) mod command;
pub mod credentials;
mod receipt;
mod relay;
mod tenant_keys;

use rusqlite::{Connection, OptionalExtension, Row, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::{ActorKind, Caller, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use super::agents::verified;
use super::{governance, nodes};
use crate::approvals::{self, GateOutcome};
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, tool};
use ua_org::authz::{Authority, Authz};

pub(crate) use acceptance::{
    node_acceptance_attest, node_acceptance_evaluate, node_acceptance_start, node_acceptance_status,
};
pub(crate) use claim::on_heartbeat;
pub(crate) use command::{node_command_adopt, node_command_start, node_command_status};
pub(crate) use credentials::{revoke_for_agent, session_credential_revoke};
pub(crate) use receipt::cancel_for_run;
pub use tenant_keys::{DISPATCH_ORG_SCOPE, DISPATCH_TENANT_PART, ORG_SCOPE, TENANT_KEYS, TENANT_PART};

pub const CHANNEL: &str = "agent.node";

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "node_queue.v1",
    sql: "
CREATE TABLE IF NOT EXISTS node_dispatch (
    id TEXT PRIMARY KEY,
    node TEXT NOT NULL,
    agent TEXT NOT NULL,
    backend TEXT NOT NULL,
    prompt TEXT NOT NULL,
    cwd TEXT NOT NULL,
    cwd_realpath TEXT,
    model TEXT,
    permission_mode TEXT,
    settings_source TEXT,
    timeout_s INTEGER NOT NULL,
    run_id TEXT,
    task_id INTEGER,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','claimed','finished','failed','killed','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    claimed_at TEXT,
    lease_expires_at TEXT,
    completed_at TEXT,
    receipt_json TEXT,
    session_id TEXT,
    launch_key TEXT,
    wait_reason TEXT,
    wait_last_heartbeat TEXT,
    wait_expires_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_node_dispatch_node_status ON node_dispatch(node, status, created_at);
CREATE INDEX IF NOT EXISTS idx_node_dispatch_run ON node_dispatch(run_id) WHERE run_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_node_dispatch_launch_key ON node_dispatch(launch_key)
    WHERE launch_key IS NOT NULL;

-- Durable claim operations: a node that lost the answer to a claim asks
-- again under the same id and gets the same item (or the same no).
CREATE TABLE IF NOT EXISTS node_claim_ops (
    node TEXT NOT NULL,
    op_id TEXT NOT NULL,
    identity TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','bound','no_claim')),
    reason TEXT,
    item_id TEXT,
    attempt INTEGER,
    snapshot_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    fence_expires_at INTEGER NOT NULL,
    PRIMARY KEY (node, op_id),
    CHECK ((state = 'bound') = (item_id IS NOT NULL AND attempt IS NOT NULL AND snapshot_json IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_node_claim_ops_binding ON node_claim_ops(item_id, attempt)
    WHERE item_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_node_claim_ops_fence ON node_claim_ops(fence_expires_at);

-- Supervised commands: the argv, who owns the result, and the fence of the
-- claim that may report it.
CREATE TABLE IF NOT EXISTS node_command (
    item_id TEXT PRIMARY KEY NOT NULL,
    argv_json TEXT NOT NULL,
    owner_agent TEXT NOT NULL,
    owner_session TEXT,
    fence_attempt INTEGER,
    fence_token TEXT,
    exit_code INTEGER,
    log_path TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
-- One owner notice per (item, attempt, outcome), sent after the receipt
-- commits and retried by the sweep until it is delivered.
CREATE TABLE IF NOT EXISTS node_command_notice (
    item_id TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    terminal TEXT NOT NULL,
    owner_agent TEXT NOT NULL,
    body TEXT NOT NULL,
    task_id INTEGER,
    created_at TEXT NOT NULL,
    sent_at TEXT,
    message_id TEXT,
    last_error TEXT,
    PRIMARY KEY (item_id, attempt, terminal)
);

-- Follow-ups into a live ACP session: queued by an operator or the item's
-- requester, polled by the node, acknowledged, then delivered or dropped.
CREATE TABLE IF NOT EXISTS node_followups (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('queue','steer')),
    body TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','claimed','delivered','dropped')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    claimed_at TEXT,
    delivered_at TEXT,
    turn_id TEXT,
    path TEXT,
    reason TEXT,
    operator_authored INTEGER NOT NULL DEFAULT 0,
    approval TEXT NOT NULL DEFAULT 'gate_passed',
    updated_at TEXT NOT NULL,
    UNIQUE (item_id, idempotency_key),
    UNIQUE (item_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_node_followups_item_status ON node_followups(item_id, status, seq);
",
};

pub fn schema_parts() -> Vec<SchemaPart> {
    vec![SCHEMA, credentials::SCHEMA, acceptance::SCHEMA]
}

// --- limits ---------------------------------------------------------------------

pub const DEFAULT_TIMEOUT_S: i64 = 3600;
pub const MAX_TIMEOUT_S: i64 = 21_600;
/// A claim's lease is the item's timeout plus this grace.
pub const LEASE_GRACE_S: i64 = 300;
/// Bounds of `node_queue_wait_s`.
pub const WAIT_MIN_S: u64 = 60;
pub const WAIT_MAX_S: u64 = 604_800;

const MAX_PROMPT_CHARS: usize = 200_000;
const MAX_PATH: usize = 4096;
const MAX_SHORT: usize = 200;
const MAX_ARGV: usize = 64;
const PREVIEW_CHARS: usize = 80;

/// Backends a node may run. `acceptance` is the hub's no-model self-test
/// and `command` a supervised argv (queued through `node_command_start`).
pub const NODE_BACKENDS: [&str; 16] = [
    "codex",
    "agy",
    "pi",
    "claude",
    "cursor",
    "copilot",
    "devin",
    "agy-interactive",
    "acp:gemini",
    "acp:codex",
    "acp:claude",
    "acp:copilot",
    "acp:cursor",
    "acp:opencode",
    "acceptance",
    "command",
];
pub const PERMISSION_MODES: [&str; 3] = ["supervised", "auto-accept-edits", "full-access"];
pub const TERMINAL: [&str; 4] = ["finished", "failed", "killed", "cancelled"];

pub(crate) const LEASE_EXPIRED: &str = "lease_expired_outcome_unknown";
pub(crate) const WAIT_EXPIRED: &str = "waiting_expired_node_offline";

// --- small helpers --------------------------------------------------------------

pub(crate) fn now() -> String {
    ua_core::time::now()
}

pub(crate) fn after(secs: i64) -> String {
    let t = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap_or(jiff::Timestamp::MAX);
    ua_core::time::format_ts(t)
}

/// Whether timestamp `a` is strictly before `b` (both hub-written).
pub(crate) fn before(a: &str, b: &str) -> bool {
    match (ua_core::time::parse_ts(a), ua_core::time::parse_ts(b)) {
        (Some(x), Some(y)) => x < y,
        _ => a < b,
    }
}

pub(crate) fn new_item_id() -> String {
    format!("nd-{}", &uuid::Uuid::new_v4().simple().to_string()[..16])
}

pub(crate) fn valid_item_id(id: &str) -> bool {
    id.len() == 19 && id.starts_with("nd-") && id[3..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn check_item_id(id: &str) -> UaResult<String> {
    let id = id.trim();
    if valid_item_id(id) { Ok(id.to_string()) } else { Err(UaError::invalid("item_id is malformed")) }
}

pub(crate) fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

pub(crate) fn evidence_ref(node: &str, item: &str) -> String {
    format!("node:{node}:{item}")
}

/// Append an `agent.node` event about a row of organization `org`.
pub(crate) fn record(
    tx: &mut WriteTx<'_>,
    org: &str,
    kind: &str,
    mut payload: Value,
    by: &str,
) -> UaResult<Option<String>> {
    payload["kind"] = json!(kind);
    emit(tx, org, CHANNEL, payload, by, None)
}

/// Keys an event about another organization's node, item, follow-up or run
/// keeps in the default organization's ledger: hub-generated ids, counts,
/// and states and codes the hub chooses from a fixed set. Node names, hosts,
/// agents, actors, paths, prompts, commands, reasons, notes and outputs are
/// dropped.
const ORG_EVENT_KEYS: [&str; 21] = [
    "kind",
    "item_id",
    "run_id",
    "task_id",
    "status",
    "state",
    "run_state",
    "attempt",
    "attempts",
    "fence",
    "retry_count",
    "backend",
    "seq",
    "followup_id",
    "credential_id",
    "terminal",
    "timestamp",
    "termination_outcome",
    "proposals",
    "changed",
    "executable",
];

/// An event payload as the default organization's ledger may hold it: the
/// payload itself for the default organization, else only
/// [`ORG_EVENT_KEYS`].
pub(crate) fn ledger_payload(org: &str, payload: Value) -> Value {
    if org == ua_core::DEFAULT_ORG {
        return payload;
    }
    match payload {
        Value::Object(m) => {
            Value::Object(m.into_iter().filter(|(k, _)| ORG_EVENT_KEYS.contains(&k.as_str())).collect())
        }
        _ => Value::Null,
    }
}

/// Append a node or dispatch event about a row of organization `org`.
///
/// ORG-EVENT-DEFAULT: the ledger row stays in the default organization until
/// `org_guard` admits another (the task family's `emit` rule). So another
/// organization's event keeps only [`ORG_EVENT_KEYS`] (no node name, host,
/// agent, path, prompt, command or output) and its originator is the neutral
/// `system`, never the acting agent. `agent.node` and
/// `agent.dispatch.transition` are ordinary visible channels
/// (`VISIBLE_EVENT` restricts neither), which is why the payload is reduced
/// here rather than hidden on read.
pub(crate) fn emit(
    tx: &mut WriteTx<'_>,
    org: &str,
    channel: &str,
    payload: Value,
    by: &str,
    dedupe: Option<String>,
) -> UaResult<Option<String>> {
    let default = org == ua_core::DEFAULT_ORG;
    let by = if default { by } else { "system" };
    let mut ev =
        EventInput::new(ua_core::DEFAULT_ORG, channel, ledger_payload(org, payload)).by(by.to_string());
    if let Some(d) = dedupe {
        // A dedupe key can name a node or a node-chosen turn id: another
        // organization's is stored only as its digest (still unique, since
        // every one names a hub-generated item id).
        ev =
            ev.dedupe(if default { d } else { format!("org:{}", hex::encode(Sha256::digest(d.as_bytes()))) });
    }
    Ok(ledger::append(tx, ev)?.map(|e| e.ulid))
}

/// Refuse an organization `orgs` does not hold, or holds as suspended,
/// before anything is read for a write or written. The `org_exists`
/// triggers fire only on insert and do not read the status, so an update
/// (a heartbeat, a cancel, a receipt) would otherwise pass.
pub(crate) fn require_org(c: &Connection, org: &str) -> UaResult<()> {
    let status: Option<String> =
        c.query_row("SELECT status FROM orgs WHERE id = ?1", [org], |r| r.get(0)).optional()?;
    match status.as_deref() {
        Some("active") => Ok(()),
        None => Err(UaError::denied(
            "unknown_organization",
            format!("unknown organization {org:?}; no node, node work or dispatch run was changed"),
        )),
        Some(_) => Err(UaError::denied(
            "organization_suspended",
            format!("organization {org:?} is suspended; no node, node work or dispatch run was changed"),
        )),
    }
}

/// The verified agent a device-plane call acts for (the node's owner).
pub(crate) fn device_agent(caller: &Caller) -> UaResult<String> {
    match caller.kind {
        ActorKind::Agent => Ok(caller.label.clone()),
        ActorKind::Human => Err(UaError::denied(
            "agent_identity_required",
            "the node device plane runs under an authenticated agent identity, not a human one",
        )),
        ActorKind::System | ActorKind::Anonymous => {
            Err(UaError::Unauthenticated("a node needs an authenticated agent identity".into()))
        }
    }
}

/// A verified caller of any kind, else a refusal.
pub(crate) fn verified_caller(caller: &Caller, verb: &str) -> UaResult<String> {
    verified(caller).map(str::to_string).ok_or_else(|| {
        UaError::denied("identity_required", format!("{verb} requires an authenticated identity"))
    })
}

// --- node rows ------------------------------------------------------------------

/// A registered node as the queue needs it.
pub(crate) struct NodeRow {
    /// The organization that registered the node.
    pub org_id: String,
    pub node: String,
    pub agent: String,
    pub facts: Map<String, Value>,
    pub last_heartbeat: Option<String>,
    pub heartbeat_floor: Option<String>,
    pub retired: bool,
}

impl NodeRow {
    pub fn liveness(&self) -> nodes::Liveness {
        nodes::liveness(
            self.last_heartbeat.as_deref(),
            self.heartbeat_floor.as_deref(),
            self.retired,
            jiff::Timestamp::now(),
        )
    }

    /// The node's advertised backends, or `None` when it reports no list.
    pub fn backends(&self) -> Option<Vec<String>> {
        self.facts
            .get("backends")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
    }

    pub fn features(&self) -> Vec<String> {
        self.facts
            .get("node_features")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()
    }

    pub fn has_feature(&self, f: &str) -> bool {
        self.features().iter().any(|x| x == f)
    }
}

/// The node `node` of organization `org`. Another organization's node
/// answers exactly like a missing one.
pub(crate) fn load_node(c: &Connection, org: &str, node: &str) -> UaResult<Option<NodeRow>> {
    Ok(c.query_row(
        "SELECT node, agent, facts_json, last_heartbeat, heartbeat_floor, retired_at, org_id FROM nodes \
         WHERE node = ?1 AND org_id = ?2",
        params![node, org],
        |r| {
            let facts: String = r.get(2)?;
            Ok(NodeRow {
                org_id: r.get(6)?,
                node: r.get(0)?,
                agent: r.get(1)?,
                facts: serde_json::from_str::<Value>(&facts)
                    .ok()
                    .and_then(|v| v.as_object().cloned())
                    .unwrap_or_default(),
                last_heartbeat: r.get(3)?,
                heartbeat_floor: r.get(4)?,
                retired: r.get::<_, Option<String>>(5)?.is_some(),
            })
        },
    )
    .optional()?)
}

/// The node `name` of organization `org`, owned by `agent` and in service:
/// the device plane's gate. Another label's node is refused before
/// retirement is revealed; another organization's answers as unregistered,
/// so a node token of one organization never reaches another's node.
pub(crate) fn owned_node(c: &Connection, org: &str, name: &str, agent: &str) -> UaResult<NodeRow> {
    let name = nodes::validate_node_name(name)?;
    let Some(row) = load_node(c, org, &name)? else {
        return Err(UaError::not_found(format!("node {name:?} is not registered")));
    };
    nodes::check_owner(&row.agent, row.retired, &name, agent)?;
    Ok(row)
}

// --- items ----------------------------------------------------------------------

/// One `node_dispatch` row.
#[derive(Debug, Clone)]
pub(crate) struct Item {
    pub id: String,
    /// The organization of the caller who queued the item (its node's).
    pub org_id: String,
    pub node: String,
    pub agent: String,
    pub backend: String,
    pub prompt: String,
    pub cwd: String,
    pub cwd_realpath: Option<String>,
    pub model: Option<String>,
    pub permission_mode: Option<String>,
    pub settings_source: Option<String>,
    pub timeout_s: i64,
    pub run_id: Option<String>,
    pub task_id: Option<i64>,
    pub status: String,
    pub attempts: i64,
    pub cancel_requested: bool,
    pub created_by: String,
    pub created_at: String,
    pub claimed_at: Option<String>,
    pub lease_expires_at: Option<String>,
    pub completed_at: Option<String>,
    pub receipt_json: Option<String>,
    pub session_id: Option<String>,
    pub wait_reason: Option<String>,
    pub wait_last_heartbeat: Option<String>,
    pub wait_expires_at: Option<String>,
    pub updated_at: String,
}

pub(crate) const ITEM_COLS: &str = "id, node, agent, backend, prompt, cwd, cwd_realpath, model, permission_mode, \
    settings_source, timeout_s, run_id, task_id, status, attempts, cancel_requested, created_by, created_at, \
    claimed_at, lease_expires_at, completed_at, receipt_json, session_id, wait_reason, wait_last_heartbeat, \
    wait_expires_at, updated_at, org_id";

pub(crate) fn item_from_row(r: &Row<'_>) -> rusqlite::Result<Item> {
    Ok(Item {
        id: r.get(0)?,
        node: r.get(1)?,
        agent: r.get(2)?,
        backend: r.get(3)?,
        prompt: r.get(4)?,
        cwd: r.get(5)?,
        cwd_realpath: r.get(6)?,
        model: r.get(7)?,
        permission_mode: r.get(8)?,
        settings_source: r.get(9)?,
        timeout_s: r.get(10)?,
        run_id: r.get(11)?,
        task_id: r.get(12)?,
        status: r.get(13)?,
        attempts: r.get(14)?,
        cancel_requested: r.get::<_, i64>(15)? != 0,
        created_by: r.get(16)?,
        created_at: r.get(17)?,
        claimed_at: r.get(18)?,
        lease_expires_at: r.get(19)?,
        completed_at: r.get(20)?,
        receipt_json: r.get(21)?,
        session_id: r.get(22)?,
        wait_reason: r.get(23)?,
        wait_last_heartbeat: r.get(24)?,
        wait_expires_at: r.get(25)?,
        updated_at: r.get(26)?,
        org_id: r.get(27)?,
    })
}

/// The item `id` of organization `org`. Another organization's item answers
/// exactly like a missing one.
pub(crate) fn load_item(c: &Connection, org: &str, id: &str) -> UaResult<Option<Item>> {
    Ok(c.query_row(
        &format!("SELECT {ITEM_COLS} FROM node_dispatch WHERE id = ?1 AND org_id = ?2"),
        params![id, org],
        item_from_row,
    )
    .optional()?)
}

pub(crate) fn items_where(c: &Connection, filter: &str, p: impl rusqlite::Params) -> UaResult<Vec<Item>> {
    let mut stmt = c.prepare(&format!("SELECT {ITEM_COLS} FROM node_dispatch WHERE {filter}"))?;
    let rows = stmt.query_map(p, item_from_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

impl Item {
    pub fn is_terminal(&self) -> bool {
        TERMINAL.contains(&self.status.as_str())
    }

    pub fn receipt(&self) -> Option<Value> {
        self.receipt_json.as_deref().and_then(|s| serde_json::from_str(s).ok())
    }

    /// A hub-written failure whose real outcome is unknown.
    pub fn outcome_unknown(&self) -> bool {
        self.receipt()
            .is_some_and(|r| r["hub_generated"] == json!(true) && r["reason"] == json!(LEASE_EXPIRED))
    }

    pub fn is_acp(&self) -> bool {
        self.backend.starts_with("acp:")
    }

    pub fn waiting(&self) -> Option<Value> {
        let reason = self.wait_reason.as_ref()?;
        let expires = self.wait_expires_at.clone().unwrap_or_default();
        let active = self.status == "queued" && !before(&expires, &now());
        Some(json!({
            "reason": reason,
            "last_heartbeat": self.wait_last_heartbeat,
            "expires_at": expires,
            "since": self.created_at,
            "active": active,
        }))
    }

    /// The listing view: no prompt or receipt body.
    pub fn public(&self) -> Value {
        let preview = if self.prompt.chars().count() > PREVIEW_CHARS {
            format!("{}…", clip(&self.prompt, PREVIEW_CHARS - 3))
        } else {
            self.prompt.clone()
        };
        let outcome_unknown = self.outcome_unknown();
        let receipt = self.receipt();
        json!({
            "item_id": self.id,
            "node": self.node,
            "agent": self.agent,
            "backend": self.backend,
            "cwd": self.cwd,
            "cwd_realpath": self.cwd_realpath,
            "model": self.model,
            "permission_mode": self.permission_mode,
            "settings_source": self.settings_source,
            "timeout_s": self.timeout_s,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "status": self.status,
            "attempts": self.attempts,
            "cancel_requested": self.cancel_requested,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "claimed_at": self.claimed_at,
            "lease_expires_at": self.lease_expires_at,
            "completed_at": self.completed_at,
            "session_id": self.session_id,
            "updated_at": self.updated_at,
            "evidence_ref": evidence_ref(&self.node, &self.id),
            "prompt_preview": preview,
            "outcome": receipt.as_ref().map(|r| json!({
                "status": r.get("status"),
                "reason": r.get("reason"),
                "exit_code": r.get("exit_code"),
                "hub_generated": r.get("hub_generated").cloned().unwrap_or(json!(false)),
            })),
            "outcome_unknown": outcome_unknown,
            "restartable": self.is_terminal() && !outcome_unknown,
            "waiting": self.waiting(),
        })
    }
}

/// Every queued or claimed item of `node`: the open-work probe that keeps a
/// node from being retired, reassigned or forgotten while it holds work.
pub(crate) fn open_work(c: &Connection, org: &str, node: &str) -> UaResult<Vec<String>> {
    let mut stmt = c.prepare(
        "SELECT id FROM node_dispatch WHERE org_id = ?1 AND node = ?2 AND status IN ('queued','claimed') \
         ORDER BY created_at, rowid LIMIT 20",
    )?;
    let ids = stmt.query_map([org, node], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
    Ok(ids)
}

// --- linked dispatch runs -------------------------------------------------------

/// A run-linked item may run only while its run is live and not being
/// cancelled. A run id with no run row does not gate.
pub(crate) fn run_gate(c: &Connection, item: &Item) -> UaResult<Option<&'static str>> {
    let Some(run_id) = &item.run_id else { return Ok(None) };
    let row: Option<(String, Option<String>)> = c
        .query_row(
            "SELECT state, termination_outcome FROM dispatch_runs WHERE run_id = ?1 AND org_id = ?2",
            params![run_id, item.org_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(match row {
        None => None,
        Some((_, Some(_))) => Some("run_cancelling"),
        Some((state, None)) if !matches!(state.as_str(), "claimed" | "launched" | "running") => {
            Some("run_not_live")
        }
        Some(_) => None,
    })
}

/// Whether `item` is the run's current item: the one its evidence names.
pub(crate) fn run_bound(c: &Connection, item: &Item) -> UaResult<bool> {
    let Some(run_id) = &item.run_id else { return Ok(false) };
    let ev: Option<Option<String>> = c
        .query_row(
            "SELECT evidence_ref FROM dispatch_runs WHERE run_id = ?1 AND org_id = ?2",
            params![run_id, item.org_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(ev.flatten().as_deref() == Some(evidence_ref(&item.node, &item.id).as_str()))
}

/// Close the item's linked run after the item ended. Refusals are reported,
/// never raised: the queue row stays authoritative.
pub(crate) fn close_linked_run(
    tx: &mut WriteTx<'_>,
    item: &Item,
    status: &str,
    reason: Option<&str>,
    actor: &str,
    node_confirmed: bool,
) -> UaResult<Option<Value>> {
    let Some(run_id) = item.run_id.clone() else { return Ok(None) };
    if !run_bound(tx, item)? {
        return Ok(Some(json!({ "ok": false, "reason": "run_rebound", "run_id": run_id })));
    }
    let org = item.org_id.as_str();
    let Some(run) = super::dispatch::load_run(tx, org, &run_id)? else {
        return Ok(Some(json!({ "ok": false, "reason": "unknown_run", "run_id": run_id })));
    };
    // A cancel whose intent was recorded but never finalized (the cancelling
    // call was interrupted) is finalized now: confirmed when the node
    // reported or never claimed the item, unknown when a lease lapsed.
    if run.termination_outcome.as_deref() == Some("requested")
        && matches!(run.state.as_str(), "claimed" | "launched" | "running")
    {
        let confirmed = node_confirmed || item.attempts == 0;
        let out = super::dispatch::finalize_cancellation(
            tx,
            org,
            &run_id,
            actor,
            "node_queue",
            &format!("node item {status}: {}", reason.unwrap_or(status)),
            if node_confirmed {
                "node_receipt"
            } else if confirmed {
                "already_gone"
            } else {
                "lease_expired"
            },
            if confirmed { "confirmed" } else { "unknown" },
        )?;
        return Ok(Some(out));
    }
    // A cancel the hub asked for is confirmed by the node's own receipt.
    if run.state == "cancelled" || run.termination_outcome.is_some() {
        if node_confirmed && matches!(run.termination_outcome.as_deref(), Some("requested" | "unknown")) {
            let out = super::dispatch::finalize_cancellation(
                tx,
                org,
                &run_id,
                actor,
                "node_receipt",
                &format!("node_receipt:{status}"),
                "node_receipt",
                "confirmed",
            )?;
            return Ok(Some(out));
        }
        return Ok(Some(
            json!({ "ok": true, "reason": "already_terminal", "run_id": run_id, "state": run.state }),
        ));
    }
    if super::dispatch::states::is_terminal(&run.state) {
        return Ok(Some(
            json!({ "ok": true, "reason": "already_terminal", "run_id": run_id, "state": run.state }),
        ));
    }
    if !matches!(run.state.as_str(), "claimed" | "launched" | "running") {
        return Ok(Some(
            json!({ "ok": false, "reason": "run_not_live", "run_id": run_id, "state": run.state }),
        ));
    }
    let finished = status == "finished";
    let out = super::dispatch::record_outcome(
        tx,
        super::dispatch::Outcome {
            org,
            run_id: &run_id,
            fence: None,
            state: if finished { "finished" } else { "failed" },
            actor,
            source: "node",
            evidence: Some(evidence_ref(&item.node, &item.id)),
            failure_reason: if finished { None } else { Some(reason.unwrap_or(status).to_string()) },
            failure_class: if finished {
                None
            } else if status == "killed" {
                Some("killed".into())
            } else {
                Some("error".into())
            },
            usage: None,
            quota_signal: None,
        },
    )?;
    Ok(Some(out))
}

/// Move a claimed item's linked run to `running` with the item's lease.
pub(crate) fn run_running(tx: &mut WriteTx<'_>, item: &Item, lease: &str) -> UaResult<()> {
    let Some(run_id) = &item.run_id else { return Ok(()) };
    if !run_bound(tx, item)? {
        return Ok(());
    }
    let Some(run) = super::dispatch::load_run(tx, &item.org_id, run_id)? else { return Ok(()) };
    if run.termination_outcome.is_some() {
        return Ok(());
    }
    match run.state.as_str() {
        "claimed" | "launched" => {
            let edge = super::dispatch::Edge::to("running")
                .set("lease_expires_at", lease.to_string())
                .set("started_at", now());
            if super::dispatch::transition(tx, &run, edge)?.is_ok() {
                super::dispatch::record_transition(
                    tx,
                    &item.org_id,
                    run_id,
                    "running",
                    &item.agent,
                    json!({ "source": "node_claim", "item_id": item.id, "node": item.node }),
                )?;
            }
        }
        "running" => renew_run(tx, item, lease)?,
        _ => {}
    }
    Ok(())
}

/// Renew a linked live run's lease; no state change.
pub(crate) fn renew_run(tx: &WriteTx<'_>, item: &Item, lease: &str) -> UaResult<()> {
    let Some(run_id) = &item.run_id else { return Ok(()) };
    if !run_bound(tx, item)? {
        return Ok(());
    }
    tx.execute(
        "UPDATE dispatch_runs SET lease_expires_at = ?2, updated_at = ?3 WHERE run_id = ?1 AND org_id = ?4 \
         AND state IN ('claimed','launched','running') AND termination_outcome IS NULL",
        params![run_id, lease, now(), item.org_id],
    )?;
    Ok(())
}

// --- validation -----------------------------------------------------------------

/// A validated, normalized request to queue one item.
#[derive(Debug, Clone)]
pub(crate) struct NewItem {
    pub node: String,
    pub backend: String,
    pub prompt: String,
    pub cwd: String,
    pub cwd_realpath: Option<String>,
    pub model: Option<String>,
    pub permission_mode: Option<String>,
    pub timeout_s: i64,
    pub task_id: Option<i64>,
    pub run_id: Option<String>,
    pub command: Option<command::NewCommand>,
    pub launch_key: Option<String>,
}

fn short(field: &str, v: Option<String>) -> UaResult<Option<String>> {
    match v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) if s.chars().count() <= MAX_SHORT => Ok(Some(s)),
        Some(_) => Err(UaError::invalid(format!("{field} must be at most {MAX_SHORT} characters"))),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_new(
    node: &str,
    backend: &str,
    prompt: &str,
    cwd: &str,
    cwd_realpath: Option<String>,
    model: Option<String>,
    permission_mode: Option<String>,
    timeout_s: Option<i64>,
    task_id: Option<i64>,
    launch_key: Option<String>,
) -> UaResult<NewItem> {
    let node = nodes::validate_node_name(node)?;
    let backend = backend.trim().to_ascii_lowercase();
    if !NODE_BACKENDS.contains(&backend.as_str()) {
        return Err(UaError::invalid(format!("backend must be one of {}", NODE_BACKENDS.join(", "))));
    }
    if prompt.trim().is_empty() {
        return Err(UaError::invalid("prompt must not be empty"));
    }
    if prompt.chars().count() > MAX_PROMPT_CHARS {
        return Err(UaError::invalid(format!("prompt must be at most {MAX_PROMPT_CHARS} characters")));
    }
    let cwd = cwd.trim().to_string();
    if cwd.is_empty() || cwd.chars().count() > MAX_PATH || cwd.contains('\0') {
        return Err(UaError::invalid(format!("cwd must be 1-{MAX_PATH} characters")));
    }
    let cwd_realpath = match cwd_realpath.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        None => None,
        Some(p) if p.starts_with('/') && p.chars().count() <= MAX_PATH && !p.contains('\0') => Some(p),
        Some(_) => return Err(UaError::invalid("cwd_realpath must be an absolute path")),
    };
    let acp = backend.starts_with("acp:");
    let permission_mode = match permission_mode.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(_) if !acp => {
            return Err(UaError::invalid("permission_mode applies only to acp:* backends"));
        }
        Some(m) if PERMISSION_MODES.contains(&m.as_str()) => Some(m),
        Some(_) => {
            return Err(UaError::invalid(format!(
                "permission_mode must be one of {}",
                PERMISSION_MODES.join(", ")
            )));
        }
        None if acp => Some("supervised".to_string()),
        None => None,
    };
    let timeout_s = timeout_s.unwrap_or(DEFAULT_TIMEOUT_S);
    if !(1..=MAX_TIMEOUT_S).contains(&timeout_s) {
        return Err(UaError::invalid(format!("timeout_s must be 1-{MAX_TIMEOUT_S}")));
    }
    let launch_key = match launch_key.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        None => None,
        Some(k)
            if (8..=128).contains(&k.len())
                && k.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-')) =>
        {
            Some(k)
        }
        Some(_) => return Err(UaError::invalid("launch_key must be 8-128 of [A-Za-z0-9_.:-]")),
    };
    Ok(NewItem {
        node,
        backend,
        prompt: prompt.to_string(),
        cwd,
        cwd_realpath,
        model: short("model", model)?,
        permission_mode,
        timeout_s,
        task_id,
        run_id: None,
        command: None,
        launch_key,
    })
}

/// The settings provenance recorded on the item.
fn settings_source(n: &NewItem) -> String {
    match &n.permission_mode {
        Some(m) if m != "supervised" => "explicit_session".into(),
        _ => "supervised_default".into(),
    }
}

/// The node `n.node` can take this item now: registered, in service,
/// advertising the backend (when it reports a list), with the features the
/// item needs, and past device acceptance when `node_require_acceptance` is on.
///
/// The node must be `org`'s: another organization's node answers exactly
/// like an unregistered one, so work is never queued across organizations.
pub(crate) fn accepting_node(
    c: &Connection,
    cfg: &ua_core::Config,
    org: &str,
    n: &NewItem,
) -> UaResult<NodeRow> {
    let Some(row) = load_node(c, org, &n.node)? else {
        return Err(UaError::not_found(format!("node {:?} is not registered", n.node)));
    };
    if row.retired {
        return Err(UaError::conflict_code(
            nodes::RETIRED_CODE,
            format!("node {:?} is retired and takes no work until an operator un-retires it", n.node),
        ));
    }
    if let Some(list) = row.backends()
        && !list.iter().any(|b| b == &n.backend)
    {
        return Err(UaError::conflict_code(
            "backend_unavailable",
            format!("node {:?} does not advertise backend {:?}", n.node, n.backend),
        ));
    }
    if n.cwd_realpath.is_some() && !row.has_feature("cwd_realpath") {
        return Err(UaError::conflict_code(
            "node_feature_missing",
            format!("node {:?} does not support cwd_realpath; update the node", n.node),
        ));
    }
    if n.backend.starts_with("acp:")
        && !row.has_feature("session_settings")
        && n.permission_mode.as_deref() != Some("supervised")
    {
        return Err(UaError::conflict_code(
            "node_feature_missing",
            format!("node {:?} does not support ACP session settings; only supervised mode", n.node),
        ));
    }
    acceptance::require_accepted(c, cfg, &row, &n.backend)?;
    Ok(row)
}

/// What a `node_dispatch` approval binds: everything that decides what runs.
pub(crate) fn gate_payload(n: &NewItem, caller: &str) -> Value {
    let mut p = json!({
        "node": n.node,
        "backend": n.backend,
        "cwd": n.cwd,
        "prompt": n.prompt,
        "model": n.model,
        "permission_mode": n.permission_mode,
        "timeout_s": n.timeout_s,
        "task_id": n.task_id,
        "run_id": n.run_id,
        "action": "dispatch",
        "agent": caller,
    });
    if let Some(r) = &n.cwd_realpath {
        p["cwd_realpath"] = json!(r);
    }
    if let Some(c) = &n.command {
        p["command"] = json!(c.argv);
    }
    p
}

/// Insert a validated item (the caller has gated it). Returns the enqueue
/// result. A wait is recorded when the node is not live.
///
/// `org` is the enqueuer's organization, and the item's: the node must be
/// in it, and a bound task is looked up in it, so an item's task is always
/// one the enqueuer can see, and the runner paths read that task by its
/// hub-global id afterwards.
pub(crate) fn insert_item(
    tx: &mut WriteTx<'_>,
    hub: &Hub,
    org: &str,
    n: &NewItem,
    node: &NodeRow,
    created_by: &str,
) -> UaResult<Value> {
    require_org(tx, org)?;
    if node.org_id != org {
        return Err(UaError::not_found(format!("node {:?} is not registered", n.node)));
    }
    // The one claim gate, again at the enqueue itself (every path queues here).
    governance::check_claim(tx, org, Some(&node.agent), n.task_id, false)?;
    acceptance::require_accepted(tx, hub.cfg(), node, &n.backend)?;
    if let Some(t) = n.task_id {
        let exists: Option<String> = tx
            .query_row("SELECT status FROM tasks WHERE org_id = ?1 AND id = ?2", params![org, t], |r| {
                r.get(0)
            })
            .optional()?;
        match exists.as_deref() {
            None => return Err(UaError::not_found(format!("task {t} does not exist"))),
            Some("done" | "cancelled") => {
                return Err(UaError::conflict(format!("task {t} is closed; reopen it before queuing work")));
            }
            _ => {}
        }
        // Node work bound to a proposal-spawned task (node_dispatch, a
        // command, node-routed dispatch) fails closed on a drifted contract.
        governance::task_contract(tx, org, t)?;
    }
    let id = new_item_id();
    let ts = now();
    let live = node.liveness();
    let (wait_reason, wait_expires) = if live.live {
        (None, None)
    } else {
        let reason = if node.last_heartbeat.is_none() { "node_never_heartbeat" } else { "node_offline" };
        let wait = hub.cfg().node_queue_wait_s.clamp(WAIT_MIN_S, WAIT_MAX_S) as i64;
        (Some(reason), Some(after(wait)))
    };
    tx.execute(
        "INSERT INTO node_dispatch (id, node, agent, backend, prompt, cwd, cwd_realpath, model, permission_mode, \
         settings_source, timeout_s, run_id, task_id, status, created_by, created_at, launch_key, wait_reason, \
         wait_last_heartbeat, wait_expires_at, updated_at, org_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'queued', ?14, ?15, ?16, ?17, ?18, ?19, ?15, \
         ?20)",
        params![
            id,
            n.node,
            node.agent,
            n.backend,
            n.prompt,
            n.cwd,
            n.cwd_realpath,
            n.model,
            n.permission_mode,
            settings_source(n),
            n.timeout_s,
            n.run_id,
            n.task_id,
            created_by,
            ts,
            n.launch_key,
            wait_reason,
            live.live_heartbeat.clone().or(node.last_heartbeat.clone()),
            wait_expires,
            org,
        ],
    )?;
    if let Some(c) = &n.command {
        command::insert(tx, org, &id, c, &ts)?;
    }
    let mut ev = json!({
        "node": n.node,
        "item_id": id,
        "backend": n.backend,
        "task_id": n.task_id,
        "run_id": n.run_id,
        "created_by": created_by,
    });
    let mut out = json!({ "item_id": id, "node": n.node, "status": "queued", "created_at": ts });
    if let Some(reason) = wait_reason {
        let waiting = json!({
            "reason": reason,
            "last_heartbeat": node.last_heartbeat,
            "expires_at": wait_expires,
            "since": ts,
            "active": true,
        });
        ev["waiting"] = json!({ "reason": reason, "expires_at": wait_expires });
        out["waiting"] = waiting;
    }
    record(tx, org, "enqueue", ev, created_by)?;
    Ok(out)
}

/// A retry under a used `launch_key`: the item it queued, when the same
/// caller asks for the same thing. Another caller's key, or the same key
/// with other arguments, is a conflict that reveals nothing about the item.
/// Launch keys are unique per organization (`node_queue.v2.tenant_keys`),
/// so only `org`'s items are read: another organization's use of the same
/// key is invisible and the key answers like a fresh one.
fn replay(c: &Connection, org: &str, key: &str, who: &str, n: &NewItem) -> UaResult<Option<Value>> {
    let Some(item) = items_where(c, "org_id = ?1 AND launch_key = ?2", params![org, key])?.into_iter().next()
    else {
        return Ok(None);
    };
    let cmd = command::load(c, org, &item.id)?.map(|c| c.argv);
    let same = item.created_by == who
        && item.node == n.node
        && item.backend == n.backend
        && item.prompt == n.prompt
        && item.cwd == n.cwd
        && item.cwd_realpath == n.cwd_realpath
        && item.model == n.model
        && item.permission_mode == n.permission_mode
        && item.timeout_s == n.timeout_s
        && item.task_id == n.task_id
        && cmd == n.command.as_ref().map(|c| c.argv.clone());
    if !same {
        return Err(UaError::conflict_code(
            "launch_key_reused",
            "launch_key was already used for another request",
        ));
    }
    Ok(Some(json!({
        "item_id": item.id,
        "node": item.node,
        "status": item.status,
        "created_at": item.created_at,
        "replayed": true,
    })))
}

/// Gate `n` behind a one-time human approval and queue it, in one write
/// transaction. `ApprovalRequired` while the approval is pending.
pub(crate) async fn request_dispatch(hub: &Hub, caller: &Caller, n: NewItem) -> UaResult<Value> {
    let who = verified_caller(caller, "queuing node work")?;
    if let Err(refusal) = crate::policy::check_prod_action(hub.cfg(), caller, "node_dispatch") {
        return Err(refusal.error);
    }
    let (hub2, caller) = (hub.clone(), caller.clone());
    let out = hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &caller.org_id)?;
            if let Some(k) = &n.launch_key
                && let Some(prev) = replay(tx, &caller.org_id, k, &who, &n)?
            {
                return Ok(Ok(prev));
            }
            let node = accepting_node(tx, hub2.cfg(), &caller.org_id, &n)?;
            // Before the approval gate, so stopped, held or drifted work never
            // consumes one.
            governance::check_claim(tx, &caller.org_id, Some(&node.agent), n.task_id, false)?;
            if let Some(t) = n.task_id {
                governance::task_contract(tx, &caller.org_id, t)?;
            }
            match approvals::gate(tx, hub2.cfg(), &caller, "node_dispatch", &gate_payload(&n, &who))? {
                GateOutcome::Pass { .. } => {}
                GateOutcome::Pending { approval_id } => return Ok(Err(Some(approval_id))),
                GateOutcome::Denied { approval_id, reason } => {
                    return Err(UaError::denied(
                        "approval_denied",
                        format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                    ));
                }
            }
            insert_item(tx, &hub2, &caller.org_id, &n, &node, &who).map(Ok)
        })
        .await?;
    match out {
        Ok(v) => Ok(v),
        Err(Some(approval_id)) => {
            Err(UaError::ApprovalRequired { tool: "node_dispatch".into(), approval_id })
        }
        Err(None) => Err(UaError::internal("unreachable")),
    }
}

// --- cancel and restart ---------------------------------------------------------

/// Request cancellation of an item. A queued item ends `cancelled` at once;
/// a claimed one is flagged, and the node stops it on its next heartbeat and
/// reports a receipt. Returns `{item_id, status, cancel_requested}`.
///
/// `org` is the item's organization: the caller's, or for a hub path the
/// organization of the row it acts on.
pub(crate) fn cancel_item(
    tx: &mut WriteTx<'_>,
    org: &str,
    id: &str,
    actor: &str,
    reason: &str,
) -> UaResult<Value> {
    let Some(item) = load_item(tx, org, id)? else {
        return Err(UaError::not_found(format!("node item {id} does not exist")));
    };
    if item.is_terminal() {
        return Ok(
            json!({ "item_id": id, "status": item.status, "cancel_requested": item.cancel_requested, "changed": false }),
        );
    }
    let ts = now();
    if item.status == "queued" {
        tx.execute(
            "UPDATE node_dispatch SET status = 'cancelled', cancel_requested = 1, completed_at = ?2, updated_at = ?2 \
             WHERE id = ?1 AND org_id = ?3 AND status = 'queued'",
            params![id, ts, org],
        )?;
        record(
            tx,
            org,
            "cancelled",
            json!({ "node": item.node, "item_id": id, "actor": actor, "reason": reason }),
            actor,
        )?;
        relay::drop_open_followups(tx, org, id, "item_cancelled")?;
        credentials::revoke_for_item(tx, org, id, "cancelled", actor)?;
        let run = close_linked_cancel(tx, &item, actor)?;
        return Ok(
            json!({ "item_id": id, "status": "cancelled", "cancel_requested": true, "changed": true, "run_outcome": run }),
        );
    }
    if !item.cancel_requested {
        tx.execute(
            "UPDATE node_dispatch SET cancel_requested = 1, updated_at = ?2 WHERE id = ?1 AND org_id = ?3",
            params![id, ts, org],
        )?;
        record(
            tx,
            org,
            "cancel_requested",
            json!({ "node": item.node, "item_id": id, "actor": actor, "reason": reason }),
            actor,
        )?;
    }
    credentials::revoke_for_item(tx, org, id, "cancelled", actor)?;
    Ok(
        json!({ "item_id": id, "status": item.status, "cancel_requested": true, "changed": !item.cancel_requested }),
    )
}

/// A queued (never claimed) item's run is cancelled with confirmed cessation:
/// nothing ran.
fn close_linked_cancel(tx: &mut WriteTx<'_>, item: &Item, actor: &str) -> UaResult<Option<Value>> {
    if item.run_id.is_none() || !run_bound(tx, item)? {
        return Ok(None);
    }
    let run_id = item.run_id.clone().unwrap_or_default();
    let Some(run) = super::dispatch::load_run(tx, &item.org_id, &run_id)? else { return Ok(None) };
    if super::dispatch::states::is_terminal(&run.state) && run.state != "cancelled" {
        return Ok(None);
    }
    Ok(Some(super::dispatch::finalize_cancellation(
        tx,
        &item.org_id,
        &run_id,
        actor,
        "node_queue",
        "cancelled before the node claimed it",
        "already_gone",
        "confirmed",
    )?))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ItemArgs {
    /// The node work item (`nd-` + 16 hex).
    pub item_id: String,
    /// Why (recorded on the ledger), at most 300 characters.
    pub reason: Option<String>,
}

/// Who may control an item: whoever queued it, the node's agent, the
/// command's owner, or an operator.
fn may_control(c: &Connection, hub: &Hub, caller: &Caller, who: &str, item: &Item) -> UaResult<bool> {
    if Authz::new(hub.cfg()).holds(
        caller,
        &[Authority::Operator, Authority::LifecycleOperator],
        ua_core::DEFAULT_ORG,
    ) || item.created_by == who
        || item.agent == who
    {
        return Ok(true);
    }
    let owner: Option<String> = c
        .query_row(
            "SELECT owner_agent FROM node_command WHERE item_id = ?1 AND org_id = ?2",
            params![item.id, item.org_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(owner.as_deref() == Some(who))
}

/// `coordination_manage(action="node_item_cancel")`.
pub(crate) async fn node_item_cancel(ctx: ToolCtx, a: ItemArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "cancelling node work")?;
    let id = check_item_id(&a.item_id)?;
    let reason = clip(a.reason.as_deref().unwrap_or("cancelled").trim(), 300);
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &caller.org_id)?;
            let Some(item) = load_item(tx, &caller.org_id, &id)? else {
                return Err(UaError::not_found(format!("node item {id} does not exist")));
            };
            if !may_control(tx, &hub, &caller, &who, &item)? {
                return Err(UaError::denied(
                    "not_item_owner",
                    format!(
                        "{who:?} may not cancel {id}: only its requester, the node's agent or an operator"
                    ),
                ));
            }
            cancel_item(tx, &caller.org_id, &id, &who, &reason)
        })
        .await
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconcileArgs {
    /// An item the hub failed when its lease lapsed (`lease_expired_outcome_unknown`).
    pub item_id: String,
    /// What really happened on the node: finished, failed or killed.
    pub status: String,
    /// How you know, 1-500 characters (a log, the node's spool, a commit).
    pub note: String,
}

/// `coordination_manage(action="node_item_reconcile")`: record the real
/// outcome of an item whose lease lapsed, so it can be restarted. The
/// node's agent or an operator; the hub's failure is kept as `prior`.
pub(crate) async fn node_item_reconcile(ctx: ToolCtx, a: ReconcileArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "reconciling node work")?;
    let id = check_item_id(&a.item_id)?;
    let status = a.status.trim().to_string();
    if !receipt::RECEIPT_STATUSES.contains(&status.as_str()) {
        return Err(UaError::invalid("status must be finished, failed or killed"));
    }
    let note = a.note.split_whitespace().collect::<Vec<_>>().join(" ");
    if note.is_empty() || note.chars().count() > 500 {
        return Err(UaError::invalid("note must be 1-500 characters"));
    }
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &caller.org_id)?;
            let org = caller.org_id.clone();
            let Some(item) = load_item(tx, &org, &id)? else {
                return Err(UaError::not_found(format!("node item {id} does not exist")));
            };
            if !(item.agent == who
                || Authz::new(hub.cfg()).holds(
                    &caller,
                    &[Authority::Operator, Authority::LifecycleOperator],
                    ua_core::DEFAULT_ORG,
                ))
            {
                return Err(UaError::denied(
                    "not_item_owner",
                    format!("only the node's agent {:?} or an operator reconciles {id}", item.agent),
                ));
            }
            if !item.outcome_unknown() {
                return Err(UaError::conflict(format!(
                    "node item {id} has a known outcome; nothing to reconcile"
                )));
            }
            let ts = now();
            let receipt = json!({
                "status": status,
                "reason": "reconciled",
                "note": note,
                "reconciled": true,
                "reconciled_by": who,
                "recorded_at": ts,
                "hub_generated": false,
                "prior": item.receipt(),
            });
            tx.execute(
                "UPDATE node_dispatch SET status = ?2, receipt_json = ?3, updated_at = ?4 WHERE id = ?1 AND org_id = ?5",
                params![id, status, receipt.to_string(), ts, org],
            )?;
            record(
                tx,
                &org,
                "reconciled",
                json!({ "node": item.node, "item_id": id, "status": status, "actor": who, "note": note }),
                &who,
            )?;
            Ok(json!({ "item_id": id, "status": status, "reconciled": true, "restartable": true }))
        })
        .await
}

/// `coordination_manage(action="node_item_restart")`: queue a fresh item
/// with the stored fields of a terminal one, behind a new approval.
pub(crate) async fn node_item_restart(ctx: ToolCtx, a: ItemArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "restarting node work")?;
    let id = check_item_id(&a.item_id)?;
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let (item, cmd) = ctx
        .hub
        .db()
        .read_async(move |c| {
            let Some(item) = load_item(c, &caller.org_id, &id)? else {
                return Err(UaError::not_found(format!("node item {id} does not exist")));
            };
            if !may_control(c, &hub, &caller, &who, &item)? {
                return Err(UaError::denied(
                    "not_item_owner",
                    format!(
                        "{who:?} may not restart {id}: only its requester, the node's agent or an operator"
                    ),
                ));
            }
            let cmd = command::load(c, &item.org_id, &id)?;
            Ok((item, cmd))
        })
        .await?;
    if !item.is_terminal() {
        return Err(UaError::conflict(format!(
            "node item {} is {}; only a finished item restarts",
            item.id, item.status
        )));
    }
    if item.outcome_unknown() {
        return Err(UaError::conflict(format!(
            "node item {} lost its lease and its outcome is unknown; reconcile the node outcome before restarting",
            item.id
        )));
    }
    if item.run_id.is_some() {
        return Err(UaError::conflict(format!(
            "node item {} belongs to dispatch run {}; resume or re-dispatch the run instead",
            item.id,
            item.run_id.clone().unwrap_or_default()
        )));
    }
    let mut n = validate_new(
        &item.node,
        &item.backend,
        &item.prompt,
        &item.cwd,
        item.cwd_realpath.clone(),
        item.model.clone(),
        item.permission_mode.clone(),
        Some(item.timeout_s),
        item.task_id,
        None,
    )?;
    if let Some(c) = cmd {
        n.command = Some(command::NewCommand {
            argv: c.argv,
            owner_agent: c.owner_agent,
            owner_session: c.owner_session,
        });
    }
    let mut out = request_dispatch(&ctx.hub, &ctx.caller, n).await?;
    out["restarted_from"] = json!(item.id);
    Ok(out)
}

// --- the sweep ------------------------------------------------------------------

/// Expire waits, fail lapsed leases and retry undelivered command notices,
/// for `node`'s items or every node's. Run by every claim for its node, and by
/// `ua serve` every `node_wait_sweep_s` seconds for all nodes.
///
/// A hub job with no caller: it spans every organization, and each item is
/// settled, ledgered and has its run closed in the item's own organization.
pub fn sweep(hub: &Hub, node: Option<&str>) -> UaResult<Value> {
    let owned = node.map(str::to_string);
    let out = hub.db().write(move |tx| sweep_tx(tx, owned.as_deref(), "node-queue-sweep"))?;
    let scope = node.map_or(command::NoticeScope::All, command::NoticeScope::Node);
    let notices = command::deliver_pending(hub, scope)?;
    let mut out = out;
    out["notices_delivered"] = json!(notices);
    Ok(out)
}

pub(crate) fn sweep_tx(tx: &mut WriteTx<'_>, node: Option<&str>, actor: &str) -> UaResult<Value> {
    let ts = now();
    let scope = if node.is_some() { " AND node = ?2" } else { " AND ?2 IS NULL" };
    // Waits that ran out.
    let waits = items_where(
        tx,
        &format!(
            "status = 'queued' AND wait_reason IS NOT NULL AND wait_expires_at IS NOT NULL \
             AND wait_expires_at < ?1{scope} ORDER BY created_at LIMIT 200"
        ),
        params![ts, node],
    )?;
    let mut expired = Vec::new();
    for item in waits {
        if !item.wait_expires_at.as_deref().is_some_and(|e| before(e, &ts)) {
            continue;
        }
        let receipt = json!({ "status": "failed", "reason": WAIT_EXPIRED, "hub_generated": true });
        let n = tx.execute(
            "UPDATE node_dispatch SET status = 'failed', receipt_json = ?2, completed_at = ?3, updated_at = ?3 \
             WHERE id = ?1 AND org_id = ?4 AND status = 'queued'",
            params![item.id, receipt.to_string(), ts, item.org_id],
        )?;
        if n == 1 {
            record(
                tx,
                &item.org_id,
                "wait_expired",
                json!({ "node": item.node, "item_id": item.id, "reason": item.wait_reason }),
                actor,
            )?;
            relay::drop_open_followups(tx, &item.org_id, &item.id, "session_ended_before_delivery")?;
            close_linked_run(tx, &item, "failed", Some(WAIT_EXPIRED), actor, false)?;
            expired.push(item.id);
        }
    }
    // Claims whose lease lapsed: the outcome is unknown.
    let lapsed = items_where(
        tx,
        &format!(
            "status = 'claimed' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?1{scope} LIMIT 200"
        ),
        params![ts, node],
    )?;
    let mut failed = Vec::new();
    for item in lapsed {
        if !item.lease_expires_at.as_deref().is_some_and(|e| before(e, &ts)) {
            continue;
        }
        let receipt = json!({ "status": "failed", "reason": LEASE_EXPIRED, "hub_generated": true });
        let n = tx.execute(
            "UPDATE node_dispatch SET status = 'failed', receipt_json = ?2, completed_at = ?3, updated_at = ?3 \
             WHERE id = ?1 AND org_id = ?4 AND status = 'claimed' AND receipt_json IS NULL",
            params![item.id, receipt.to_string(), ts, item.org_id],
        )?;
        if n == 1 {
            record(
                tx,
                &item.org_id,
                "lease_expired",
                json!({ "node": item.node, "item_id": item.id, "attempt": item.attempts }),
                actor,
            )?;
            relay::drop_open_followups(tx, &item.org_id, &item.id, "delivery_unconfirmed")?;
            credentials::revoke_for_item(tx, &item.org_id, &item.id, "lease_expired", actor)?;
            close_linked_run(tx, &item, "failed", Some(LEASE_EXPIRED), actor, false)?;
            failed.push(item.id);
        }
    }
    claim::cleanup_ops(tx, node)?;
    Ok(json!({ "waits_expired": expired, "leases_failed": failed }))
}

/// Run [`sweep`] every `node_wait_sweep_s` seconds (0: never), until `ct` is
/// cancelled; a sweep in progress finishes first.
pub fn spawn_sweeper(
    hub: &Hub,
    ct: tokio_util::sync::CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let every = hub.cfg().node_wait_sweep_s;
    if every == 0 {
        return None;
    }
    let hub = hub.clone();
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(every));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = ct.cancelled() => return,
                _ = tick.tick() => {}
            }
            let h = hub.clone();
            match tokio::task::spawn_blocking(move || sweep(&h, None)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "node queue sweep failed"),
                Err(e) => tracing::warn!(error = %e, "node queue sweep panicked"),
            }
        }
    }))
}

// --- tools ----------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DispatchArgs {
    /// Registered node to run on.
    pub node: String,
    /// What to run: one of the node backends (`codex`, `claude`, `acp:claude`, ...).
    pub backend: String,
    /// The prompt, 1-200000 characters.
    pub prompt: String,
    /// Working directory on the node; the node refuses one outside its worktree roots.
    pub cwd: String,
    /// The directory's resolved path as the node reported it; the node refuses
    /// the item if the path resolves elsewhere by then.
    pub cwd_realpath: Option<String>,
    /// Model for the backend, at most 200 characters.
    pub model: Option<String>,
    /// ACP only: `supervised` (default), `auto-accept-edits` or `full-access`.
    pub permission_mode: Option<String>,
    /// Wall-clock limit on the node, 1-21600 seconds (default 3600).
    pub timeout_s: Option<i64>,
    /// Task the work is for (must exist and be open).
    pub task_id: Option<i64>,
    /// Client key (8-128 of `[A-Za-z0-9_.:-]`): a retry with the same key
    /// returns the item it queued.
    pub launch_key: Option<String>,
}

async fn node_dispatch(ctx: ToolCtx, a: DispatchArgs) -> UaResult<Value> {
    let n = validate_new(
        &a.node,
        &a.backend,
        &a.prompt,
        &a.cwd,
        a.cwd_realpath,
        a.model,
        a.permission_mode,
        a.timeout_s,
        a.task_id,
        a.launch_key,
    )?;
    if n.backend == "command" {
        return Err(UaError::invalid(
            "supervised commands are queued with coordination_manage node_command_start",
        ));
    }
    if n.backend == "acceptance" {
        return Err(UaError::invalid("the acceptance backend runs only the hub's own device acceptance"));
    }
    request_dispatch(&ctx.hub, &ctx.caller, n).await
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ItemsArgs {
    /// Only this node's items.
    pub node: Option<String>,
    /// Only items in this status (queued, claimed, finished, failed, killed, cancelled), or `open`.
    pub status: Option<String>,
    /// Only items for this task.
    pub task_id: Option<i64>,
    /// One item, with its prompt and full receipt.
    pub item_id: Option<String>,
    /// Rows, newest first (default 25, max 200).
    pub limit: Option<i64>,
}

async fn node_items(ctx: ToolCtx, a: ItemsArgs) -> UaResult<Value> {
    let who = verified(&ctx.caller).map(str::to_string);
    let maintainer = who.is_some()
        && Authz::new(ctx.hub.cfg()).holds(
            &ctx.caller,
            &[Authority::Operator, Authority::LifecycleOperator],
            ua_core::DEFAULT_ORG,
        );
    let limit = a.limit.unwrap_or(25).clamp(1, 200);
    if let Some(s) = &a.status
        && s != "open"
        && !["queued", "claimed", "finished", "failed", "killed", "cancelled"].contains(&s.as_str())
    {
        return Err(UaError::invalid("status must be an item status or `open`"));
    }
    let item_id = a.item_id.as_deref().map(check_item_id).transpose()?;
    // Only the caller's organization's items, whoever asks.
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            // An item is visible to an operator, its requester, the node's
            // agent and a command's owner.
            let visible = |item: &Item| -> UaResult<bool> {
                if maintainer {
                    return Ok(true);
                }
                let Some(w) = who.as_deref() else { return Ok(false) };
                if item.created_by == w || item.agent == w {
                    return Ok(true);
                }
                let owner: Option<String> = c
                    .query_row(
                        "SELECT owner_agent FROM node_command WHERE item_id = ?1 AND org_id = ?2",
                        params![item.id, item.org_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                Ok(owner.as_deref() == Some(w))
            };
            if let Some(id) = item_id {
                let Some(item) = load_item(c, &org, &id)?.filter(|i| visible(i).unwrap_or(false)) else {
                    return Err(UaError::not_found(format!("no node item {id} visible to you")));
                };
                let mut v = item.public();
                v["prompt"] = json!(item.prompt);
                v["receipt"] = item.receipt().unwrap_or(Value::Null);
                v["followups"] = relay::followups_of(c, &org, &item.id)?;
                if let Some(cmd) = command::load(c, &org, &item.id)? {
                    v["command"] = cmd.public();
                }
                return Ok(json!({ "item": v }));
            }
            let mut binds: Vec<rusqlite::types::Value> = vec![org.clone().into()];
            let mut clauses = vec!["org_id = ?1".to_string()];
            if !maintainer {
                let Some(w) = who.clone() else { return Ok(json!({ "items": [], "count": 0 })) };
                binds.push(w.into());
                let i = binds.len();
                clauses.push(format!(
                    "(created_by = ?{i} OR agent = ?{i} OR EXISTS (SELECT 1 FROM node_command c \
                     WHERE c.item_id = node_dispatch.id AND c.org_id = node_dispatch.org_id \
                     AND c.owner_agent = ?{i}))"
                ));
            }
            if let Some(n) = &a.node {
                binds.push(nodes::validate_node_name(n)?.into());
                clauses.push(format!("node = ?{}", binds.len()));
            }
            match a.status.as_deref() {
                Some("open") => clauses.push("status IN ('queued','claimed')".into()),
                Some(s) => {
                    binds.push(s.to_string().into());
                    clauses.push(format!("status = ?{}", binds.len()));
                }
                None => {}
            }
            if let Some(t) = a.task_id {
                binds.push(t.into());
                clauses.push(format!("task_id = ?{}", binds.len()));
            }
            let filter =
                format!("{} ORDER BY created_at DESC, rowid DESC LIMIT {limit}", clauses.join(" AND "));
            let out: Vec<Value> = items_where(c, &filter, rusqlite::params_from_iter(binds))?
                .iter()
                .map(Item::public)
                .collect();
            Ok(json!({ "items": out, "count": out.len() }))
        })
        .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "node_dispatch",
            "Queue work for a registered remote node: a backend (codex, claude, acp:claude, ...), a prompt and a \
             working directory on the node. Always needs a one-time human approval bound to the node, backend, \
             cwd, prompt, model, permission mode, timeout and task; the identical retry after approval queues it. \
             Work for a node that is not live waits up to node_queue_wait_s, then fails. Returns {item_id, node, \
             status, created_at, waiting?}.",
            node_dispatch,
        )
        .gates_in_handler()
        .family("nodes"),
    );
    r.add(
        tool(
            "node_items",
            "List remote-node work items, newest first: status, attempts, outcome, waiting state and a prompt \
             preview (with item_id: one item with its prompt, receipt, follow-ups and command). Visible to the \
             requester, the node's agent, a command's owner and operators.",
            node_items,
        )
        .read_only()
        .family("nodes"),
    );
    claim::register(r);
    credentials::register(r);
    receipt::register(r);
    relay::register(r);
}
