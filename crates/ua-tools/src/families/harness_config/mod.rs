//! Hub-served harness config bundles: one versioned bundle of rules text,
//! skills and MCP server lists that each node renders into per-harness files
//! (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, codex TOML, opencode JSON).
//!
//! Tools:
//! - `harness_config_publish` (an operator): validate a bundle and make it the
//!   active one. Always a one-time human approval, bound to the version and
//!   the SHA-256 of the canonical bundle; a version is published once.
//! - `harness_config_status` (read-only): the active bundle and recent
//!   proposals.
//! - `node_config` (the device plane, behind `GET|POST /api/node/config`):
//!   `get` the bundle for the caller's node with every surface rendered and
//!   the apply grants it holds; `report` drift, which parks one
//!   `harness_config_apply` approval per surface bound to {node, surface,
//!   path, bundle_version, desired_hash}; `applied` after the node wrote a
//!   surface, which consumes that approved pass.
//!
//! The node never writes a surface without a consumed pass (proposal mode).
//! A drift report must name the active version (else `409`), carries at most
//! [`render::MAX_PROPOSALS_PER_REPORT`] proposals, and each `desired_hash`
//! must equal the hub's own render of that surface (else `409`), so a node
//! cannot have arbitrary content approved.
//!
//! The bundle a node is served is the active bundle plus the registry skills
//! resolved for the node's agent ([`super::skill_registry`]), appended after
//! the bundle's own skills (a bundle skill of the same name wins). Rendering
//! is byte-compatible with the Python hub ([`render`]), so Python nodes
//! compare hashes unchanged.
//!
//! Publish, report and applied are ledgered on `agent.harness_config` in the
//! same transaction as the change.

pub mod render;

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{Caller, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use self::render::{
    Bundle, MAX_BUNDLE_BYTES, MAX_PROPOSALS_PER_REPORT, MAX_SKILLS, Skill, clip_diff, content_hash,
    diff_from_empty, py_strip, render_all, render_surface, valid_surface,
};
use super::node_queue::{device_agent, is_operator, owned_node, verified_caller};
use super::skill_registry;
use crate::approvals::{self, GateOutcome, RequestState};
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "harness_config.v1",
    sql: "
CREATE TABLE IF NOT EXISTS harness_config_bundles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL UNIQUE,
    published_at TEXT NOT NULL,
    published_by TEXT NOT NULL,
    bundle_json TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    org_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_harness_config_bundles_active ON harness_config_bundles(active);
CREATE TABLE IF NOT EXISTS harness_config_proposals (
    id TEXT PRIMARY KEY,
    node TEXT NOT NULL,
    surface TEXT NOT NULL,
    path TEXT NOT NULL,
    bundle_version TEXT NOT NULL,
    desired_hash TEXT NOT NULL,
    observed_hash TEXT,
    diff_text TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    approval_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT,
    org_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_harness_config_proposals_node
    ON harness_config_proposals(node, status, created_at);
CREATE TABLE IF NOT EXISTS harness_config_drift (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node TEXT NOT NULL,
    surface TEXT NOT NULL,
    path TEXT NOT NULL,
    bundle_version TEXT NOT NULL,
    observed_hash TEXT,
    desired_hash TEXT NOT NULL,
    reported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_harness_config_drift_node ON harness_config_drift(node, reported_at);
",
};

pub const CHANNEL: &str = "agent.harness_config";
/// The approval each surface write needs.
pub const APPLY_TOOL: &str = "harness_config_apply";
pub const PUBLISH_TOOL: &str = "harness_config_publish";
/// The node's default harness-config root, reported when
/// `harness_config_root_hint` is unset.
pub const DEFAULT_ROOT_HINT: &str = "~/.unified_agent/harness-config";

const MAX_DESCRIPTION: usize = 1024;

fn record(tx: &mut WriteTx<'_>, kind: &str, mut payload: Value, by: &str) -> UaResult<()> {
    payload["kind"] = json!(kind);
    ledger::append(tx, EventInput::new(CHANNEL, payload).by(by.to_string()))?;
    Ok(())
}

// --- the active bundle ------------------------------------------------------------

struct Active {
    version: String,
    published_at: String,
    published_by: String,
    bundle: Bundle,
}

fn active(c: &Connection) -> UaResult<Option<Active>> {
    let row: Option<(String, String, String, String)> = c
        .query_row(
            "SELECT version, published_at, published_by, bundle_json FROM harness_config_bundles \
             WHERE active = 1 ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((version, published_at, published_by, json)) = row else { return Ok(None) };
    // A stored bundle that no longer parses is treated as no bundle, as the
    // Python hub does.
    let Ok(bundle) = serde_json::from_str::<Bundle>(&json) else { return Ok(None) };
    Ok(Some(Active { version, published_at, published_by, bundle }))
}

/// The bundle a node of `agent` is served: the active bundle plus the
/// registry skills resolved for the agent (and its default profile), and a
/// note per resolved skill saying whether it was included.
fn effective(c: &Connection, hub: &Hub, agent: &str, bundle: &Bundle) -> UaResult<(Bundle, Vec<Value>)> {
    let profile = crate::sessions::default_profile(hub, agent);
    let resolved = skill_registry::resolve(c, agent, Some(profile.as_str()))?;
    let mut out = bundle.clone();
    let mut notes = Vec::new();
    for s in resolved {
        let mut note = json!({ "name": s.name, "version": s.version, "hash": s.hash, "via": s.via });
        let skipped = if out.skills.iter().any(|k| k.name == s.name) {
            Some("bundle_defines")
        } else if out.skills.len() >= MAX_SKILLS {
            Some("skill_limit")
        } else {
            let description = skill_registry::frontmatter(&s.content)
                .and_then(|m| m.get("description").and_then(Value::as_str).map(|d| py_strip(d).to_string()))
                .map(|d| d.chars().take(MAX_DESCRIPTION).collect())
                .unwrap_or_default();
            out.skills.push(Skill { name: s.name.clone(), description, body: s.content.clone() });
            if out.to_json().len() > MAX_BUNDLE_BYTES {
                out.skills.pop();
                Some("size_limit")
            } else {
                None
            }
        };
        note["included"] = json!(skipped.is_none());
        if let Some(reason) = skipped {
            note["reason"] = json!(reason);
        }
        notes.push(note);
    }
    Ok((out, notes))
}

/// What a `harness_config_apply` approval binds.
fn canonical(node: &str, surface: &str, path: &str, version: &str, desired_hash: &str) -> Value {
    json!({
        "node": node,
        "surface": surface,
        "path": path,
        "bundle_version": version,
        "desired_hash": desired_hash,
    })
}

/// Surfaces with an approved, unconsumed apply pass for this node whose
/// desired content is still the current render. Read-only: no approval is
/// asked for or consumed.
fn apply_grants(
    c: &Connection,
    hub: &Hub,
    agent: &str,
    node: &str,
    version: &str,
    current: &std::collections::BTreeMap<String, render::Rendered>,
) -> UaResult<Vec<Value>> {
    let mut stmt = c.prepare(
        "SELECT id, surface, path, desired_hash, approval_id FROM harness_config_proposals \
         WHERE node = ?1 AND bundle_version = ?2 AND status IN ('pending', 'approved') ORDER BY created_at, id",
    )?;
    let rows: Vec<(String, String, String, String, Option<i64>)> = stmt
        .query_map(params![node, version], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
        .collect::<Result<_, _>>()?;
    let mut grants = Vec::new();
    for (id, surface, path, hash, approval_id) in rows {
        if current.get(&surface).is_none_or(|r| r.hash != hash) {
            continue;
        }
        let payload = canonical(node, &surface, &path, version, &hash);
        if let Some(RequestState::Approved { approval_id: pass }) =
            approvals::peek(c, hub.cfg(), agent, APPLY_TOOL, &payload)?
        {
            grants.push(json!({
                "proposal_id": id,
                "surface": surface,
                "path": path,
                "desired_hash": hash,
                "approval_id": approval_id.unwrap_or(pass),
                "bundle_version": version,
            }));
        }
    }
    Ok(grants)
}

fn new_proposal_id() -> String {
    format!("hc-{}", &uuid::Uuid::new_v4().simple().to_string()[..16])
}

fn sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A bounded, stripped string field of a proposal (the Python `_bounded_str`).
fn field(raw: &Map<String, Value>, key: &str, limit: usize) -> UaResult<Option<String>> {
    match raw.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let t = py_strip(s);
            if t.is_empty() {
                Ok(None)
            } else if t.chars().count() > limit {
                Err(UaError::invalid(format!("string exceeds {limit} characters")))
            } else {
                Ok(Some(t.to_string()))
            }
        }
        Some(_) => Err(UaError::invalid("expected a string")),
    }
}

// --- node_config ------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeConfigArgs {
    /// The calling agent's node.
    pub node: String,
    /// `get` (default), `report` or `applied`.
    #[serde(default)]
    pub action: Option<String>,
    /// `report`: up to 32 drift proposals, each {surface, path, desired_hash,
    /// observed_hash?, diff?}.
    #[serde(default)]
    pub proposals: Option<Value>,
    /// `report`: the bundle version the node rendered; must be the active one.
    #[serde(default)]
    pub bundle_version: Option<String>,
    /// `applied`: the surface the node wrote.
    #[serde(default)]
    pub surface: Option<String>,
    /// `applied`: SHA-256 of the content written.
    #[serde(default)]
    pub desired_hash: Option<String>,
}

fn no_bundle() -> Value {
    json!({ "bundle": null, "version": null, "rendered": {}, "apply_grants": [], "proposal_mode": true })
}

fn get_payload(c: &Connection, hub: &Hub, agent: &str, node: &str) -> UaResult<Value> {
    let row = owned_node(c, node, agent)?;
    let Some(active) = active(c)? else { return Ok(no_bundle()) };
    let (bundle, assigned) = effective(c, hub, agent, &active.bundle)?;
    let rendered = render_all(&bundle)?;
    let grants = apply_grants(c, hub, agent, &row.node, &active.version, &rendered)?;
    let mut full = Map::new();
    let mut surfaces = Map::new();
    for (s, r) in &rendered {
        full.insert(
            s.clone(),
            json!({ "path": r.path, "hash": r.hash, "kind": r.kind, "content": r.content }),
        );
        surfaces.insert(s.clone(), json!({ "path": r.path, "hash": r.hash, "kind": r.kind }));
    }
    let hint = hub.cfg().harness_config_root_hint.clone().unwrap_or_else(|| DEFAULT_ROOT_HINT.into());
    Ok(json!({
        "version": active.version,
        "published_at": active.published_at,
        "published_by": active.published_by,
        "bundle": bundle.to_value(),
        "rendered": full,
        "surfaces": surfaces,
        "apply_grants": grants,
        "proposal_mode": true,
        "config_root_hint": hint,
        "assigned_skills": assigned,
    }))
}

fn report(tx: &mut WriteTx<'_>, hub: &Hub, caller: &Caller, a: &NodeConfigArgs) -> UaResult<Value> {
    let agent = caller.label.as_str();
    let node = owned_node(tx, &a.node, agent)?.node;
    let Some(active) = active(tx)? else {
        return Err(UaError::not_found("no active harness config bundle"));
    };
    let version = active.version.clone();
    if let Some(v) = a.bundle_version.as_deref().filter(|v| !v.is_empty())
        && v != version
    {
        return Err(UaError::conflict_code(
            "bundle_version_mismatch",
            format!("report targets {v:?} but active bundle is {version:?}"),
        ));
    }
    let Some(Value::Array(proposals)) = &a.proposals else {
        return Err(UaError::invalid("proposals must be a list"));
    };
    if proposals.len() > MAX_PROPOSALS_PER_REPORT {
        return Err(UaError::invalid(format!("at most {MAX_PROPOSALS_PER_REPORT} proposals per report")));
    }
    let (bundle, _) = effective(tx, hub, agent, &active.bundle)?;
    let now = ua_core::time::now();
    let mut accepted = Vec::new();
    for raw in proposals {
        let Some(raw) = raw.as_object() else {
            return Err(UaError::invalid("each proposal must be an object"));
        };
        let Some(surface) = field(raw, "surface", 32)?.filter(|s| valid_surface(s)) else {
            return Err(UaError::invalid("proposal.surface is invalid"));
        };
        let Some(path) = field(raw, "path", 256)?.filter(|p| !p.split('/').any(|s| s == "..")) else {
            return Err(UaError::invalid("proposal.path is invalid"));
        };
        let Some(desired_hash) = field(raw, "desired_hash", 64)?.filter(|h| sha256_hex(h)) else {
            return Err(UaError::invalid("proposal.desired_hash must be sha256 hex"));
        };
        // Recompute from the hub's own bundle so a node cannot invent content.
        let desired = render_surface(&bundle, &surface)?;
        if content_hash(&desired) != desired_hash {
            return Err(UaError::conflict_code(
                "desired_hash_mismatch",
                format!("desired_hash for {surface:?} does not match active bundle render"),
            ));
        }
        let observed_hash = field(raw, "observed_hash", 64)?;
        let diff = match raw.get("diff").and_then(Value::as_str) {
            Some(d) if !d.is_empty() => clip_diff(d.to_string()),
            _ => diff_from_empty(&path, &desired),
        };
        let payload = canonical(&node, &surface, &path, &version, &desired_hash);
        let state = approvals::request(tx, hub.cfg(), caller, APPLY_TOOL, &payload)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM harness_config_proposals WHERE node = ?1 AND surface = ?2 AND bundle_version = ?3 \
                 AND desired_hash = ?4 AND path = ?5 AND status IN ('pending', 'approved') ORDER BY created_at DESC \
                 LIMIT 1",
                params![node, surface, version, desired_hash, path],
                |r| r.get(0),
            )
            .optional()?;
        let proposal_id = match existing {
            Some(id) => {
                tx.execute(
                    "UPDATE harness_config_proposals SET observed_hash = ?2, diff_text = ?3, approval_id = ?4, \
                     updated_at = ?5 WHERE id = ?1",
                    params![id, observed_hash, diff, state.approval_id(), now],
                )?;
                id
            }
            None => {
                let id = new_proposal_id();
                tx.execute(
                    "INSERT INTO harness_config_proposals (id, node, surface, path, bundle_version, desired_hash, \
                     observed_hash, diff_text, status, approval_id, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10, ?10)",
                    params![id, node, surface, path, version, desired_hash, observed_hash, diff, state.approval_id(), now],
                )?;
                id
            }
        };
        tx.execute(
            "INSERT INTO harness_config_drift (node, surface, path, bundle_version, observed_hash, desired_hash, \
             reported_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![node, surface, path, version, observed_hash, desired_hash, now],
        )?;
        accepted.push(json!({
            "proposal_id": proposal_id,
            "surface": surface,
            "path": path,
            "approval_id": state.approval_id(),
            "status": state.status(),
            "inbox": null,
        }));
    }
    let summary: Vec<Value> = accepted
        .iter()
        .map(|p| json!({ "proposal_id": p["proposal_id"], "surface": p["surface"], "approval_id": p["approval_id"], "status": p["status"] }))
        .collect();
    record(
        tx,
        "harness_config_report",
        json!({ "node": node, "bundle_version": version, "proposals": summary }),
        agent,
    )?;
    let rendered = render_all(&bundle)?;
    let grants = apply_grants(tx, hub, agent, &node, &version, &rendered)?;
    Ok(json!({ "ok": true, "bundle_version": version, "proposals": accepted, "apply_grants": grants }))
}

/// `applied`: consume the surface's approved pass and mark its proposal
/// applied. `Ok(Err(id))` when the approval is still pending (committed so
/// the pending request stands).
fn applied(
    tx: &mut WriteTx<'_>,
    hub: &Hub,
    caller: &Caller,
    a: &NodeConfigArgs,
) -> UaResult<Result<Value, i64>> {
    let agent = caller.label.as_str();
    let surface = a.surface.as_deref().map(py_strip).unwrap_or_default().to_string();
    if !valid_surface(&surface) {
        return Err(UaError::invalid("surface is invalid"));
    }
    let hash = a.desired_hash.as_deref().map(py_strip).unwrap_or_default().to_string();
    if !sha256_hex(&hash) {
        return Err(UaError::invalid("desired_hash must be sha256 hex"));
    }
    let node = owned_node(tx, &a.node, agent)?.node;
    let Some(active) = active(tx)? else {
        return Err(UaError::not_found("no active harness config bundle"));
    };
    let version = active.version.clone();
    let (bundle, _) = effective(tx, hub, agent, &active.bundle)?;
    if content_hash(&render_surface(&bundle, &surface)?) != hash {
        return Err(UaError::conflict_code(
            "desired_hash_mismatch",
            "desired_hash does not match active bundle",
        ));
    }
    let proposal: Option<(String, String)> = tx
        .query_row(
            "SELECT id, path FROM harness_config_proposals WHERE node = ?1 AND surface = ?2 AND bundle_version = ?3 \
             AND desired_hash = ?4 AND status IN ('pending', 'approved') ORDER BY created_at DESC, id DESC LIMIT 1",
            params![node, surface, version, hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((proposal_id, path)) = proposal else {
        return Err(UaError::not_found("no matching pending/approved proposal"));
    };
    let payload = canonical(&node, &surface, &path, &version, &hash);
    let approval_id = match approvals::gate(tx, hub.cfg(), caller, APPLY_TOOL, &payload)? {
        GateOutcome::Pass { approval_id } => approval_id,
        GateOutcome::Pending { approval_id } => return Ok(Err(approval_id)),
        GateOutcome::Denied { approval_id, reason } => {
            return Err(UaError::denied(
                "approval_denied",
                format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
            ));
        }
    };
    let now = ua_core::time::now();
    tx.execute(
        "UPDATE harness_config_proposals SET status = 'applied', approval_id = ?2, updated_at = ?3, \
         resolved_at = ?3, resolved_by = ?4 WHERE id = ?1",
        params![proposal_id, approval_id, now, agent],
    )?;
    record(
        tx,
        "harness_config_applied",
        json!({
            "node": node,
            "surface": surface,
            "path": path,
            "proposal_id": proposal_id,
            "approval_id": approval_id,
            "bundle_version": version,
            "desired_hash": hash,
        }),
        agent,
    )?;
    Ok(Ok(json!({
        "ok": true,
        "proposal_id": proposal_id,
        "surface": surface,
        "bundle_version": version,
        "approval_id": approval_id,
    })))
}

async fn node_config(ctx: ToolCtx, a: NodeConfigArgs) -> UaResult<Value> {
    device_agent(&ctx.caller)?;
    let action = a.action.clone().unwrap_or_else(|| "get".into());
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    match action.as_str() {
        "get" => ctx.hub.db().read_async(move |c| get_payload(c, &hub, &caller.label, &a.node)).await,
        "report" => ctx.hub.db().write_async(move |tx| report(tx, &hub, &caller, &a)).await,
        "applied" => match ctx.hub.db().write_async(move |tx| applied(tx, &hub, &caller, &a)).await? {
            Ok(v) => Ok(v),
            Err(approval_id) => Err(UaError::ApprovalRequired { tool: APPLY_TOOL.into(), approval_id }),
        },
        _ => Err(UaError::invalid("action must be 'get', 'report', or 'applied'")),
    }
}

// --- publish and status -----------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishArgs {
    /// The bundle: {version, rules?: {surface: text}, skills?: [{name,
    /// description?, body?}], mcp_servers?: [{name, url, auth?: oauth|oauth2|none,
    /// transport?}], surfaces?: {surface: {path, kind?}}}.
    pub bundle: Value,
}

/// What a publish approval binds: the version and the SHA-256 of the
/// canonical bundle, with a summary for the approver.
fn publish_payload(b: &Bundle) -> Value {
    json!({
        "version": b.version,
        "bundle_sha256": b.sha256(),
        "surfaces": b.surfaces().into_iter().map(|(n, s)| json!({ "surface": n, "path": s.path, "kind": s.kind })).collect::<Vec<_>>(),
        "rules": b.rules.keys().collect::<Vec<_>>(),
        "skills": b.skills.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
        "mcp_servers": b.mcp_servers.iter().map(|s| json!({ "name": s.name, "url": s.url, "auth": s.auth })).collect::<Vec<_>>(),
    })
}

async fn publish(ctx: ToolCtx, a: PublishArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "publishing a harness config bundle")?;
    if !is_operator(&ctx.hub, &ctx.caller, &who) {
        return Err(UaError::denied(
            "operator_required",
            "publishing a harness config bundle is an operator action (a human or a lifecycle operator)",
        ));
    }
    let bundle = render::normalize(&a.bundle)?;
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let taken: Option<i64> = tx
                .query_row("SELECT id FROM harness_config_bundles WHERE version = ?1", [&bundle.version], |r| r.get(0))
                .optional()?;
            if taken.is_some() {
                return Err(UaError::conflict_code(
                    "version_published",
                    format!("version {:?} already published", bundle.version),
                ));
            }
            match approvals::gate(tx, hub.cfg(), &caller, PUBLISH_TOOL, &publish_payload(&bundle))? {
                GateOutcome::Pass { .. } => {}
                GateOutcome::Pending { approval_id } => return Ok(Err(approval_id)),
                GateOutcome::Denied { approval_id, reason } => {
                    return Err(UaError::denied(
                        "approval_denied",
                        format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                    ));
                }
            }
            let now = ua_core::time::now();
            tx.execute("UPDATE harness_config_bundles SET active = 0 WHERE active = 1", [])?;
            tx.execute(
                "INSERT INTO harness_config_bundles (version, published_at, published_by, bundle_json, active) \
                 VALUES (?1, ?2, ?3, ?4, 1)",
                params![bundle.version, now, who, bundle.to_json()],
            )?;
            let bundle_id = tx.last_insert_rowid();
            let surfaces: Vec<String> = bundle.surfaces().into_keys().collect();
            record(
                tx,
                "harness_config_publish",
                json!({
                    "version": bundle.version,
                    "bundle_id": bundle_id,
                    "bundle_sha256": bundle.sha256(),
                    "surfaces": surfaces,
                }),
                &who,
            )?;
            Ok(Ok(json!({
                "ok": true,
                "version": bundle.version,
                "bundle_id": bundle_id,
                "published_at": now,
                "published_by": who,
                "surfaces": surfaces,
                "mcp_servers": bundle.mcp_servers.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
                "skills": bundle.skills.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
            })))
        })
        .await?;
    out.map_err(|approval_id| UaError::ApprovalRequired { tool: PUBLISH_TOOL.into(), approval_id })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusArgs {}

async fn status(ctx: ToolCtx, _a: StatusArgs) -> UaResult<Value> {
    verified_caller(&ctx.caller, "reading the harness config status")?;
    ctx.hub
        .db()
        .read_async(|c| {
            let active = active(c)?.map(|a| {
                json!({
                    "version": a.version,
                    "published_at": a.published_at,
                    "published_by": a.published_by,
                    "bundle": a.bundle.to_value(),
                })
            });
            let pending: i64 = c.query_row(
                "SELECT COUNT(*) FROM harness_config_proposals WHERE status = 'pending'",
                [],
                |r| r.get(0),
            )?;
            let mut stmt = c.prepare(
                "SELECT id, node, surface, path, bundle_version, status, created_at, approval_id \
                 FROM harness_config_proposals ORDER BY created_at DESC, id DESC LIMIT 25",
            )?;
            let recent = stmt
                .query_map([], |r| {
                    Ok(json!({
                        "id": r.get::<_, String>(0)?,
                        "node": r.get::<_, String>(1)?,
                        "surface": r.get::<_, String>(2)?,
                        "path": r.get::<_, String>(3)?,
                        "bundle_version": r.get::<_, String>(4)?,
                        "status": r.get::<_, String>(5)?,
                        "created_at": r.get::<_, String>(6)?,
                        "approval_id": r.get::<_, Option<i64>>(7)?,
                    }))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({
                "active": active,
                "pending_proposals": pending,
                "recent_proposals": recent,
                "apply_tool": APPLY_TOOL,
                "proposal_mode": true,
            }))
        })
        .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "harness_config_publish",
            "Publish a harness config bundle (operators only): rules text per surface, skills and MCP servers \
             (OAuth or none; bearer/token auth and embedded secrets are refused), rendered by each node into \
             CLAUDE.md, AGENTS.md, .cursorrules, codex and opencode config. Always needs a one-time human \
             approval bound to the version and the bundle's SHA-256; a version is published once (conflict \
             otherwise). Makes it the active bundle. Returns {ok, version, bundle_id, published_at, \
             published_by, surfaces, mcp_servers, skills}.",
            publish,
        )
        .always_gated()
        .gates_in_handler()
        .family("nodes"),
    );
    r.add(
        tool(
            "harness_config_status",
            "The active harness config bundle, the count of pending drift proposals and the 25 most recent \
             proposals. Read-only.",
            status,
        )
        .read_only()
        .family("nodes"),
    );
    r.add(
        tool(
            "node_config",
            "Device plane for the calling agent's node (POST /api/node/config). action get: the active bundle \
             (plus registry skills assigned to the agent) with every surface rendered and hashed, and the apply \
             grants the node holds. action report {bundle_version, proposals}: drift, at most 32 surfaces; each \
             desired_hash must equal the hub's render, and each parks one harness_config_apply approval bound to \
             {node, surface, path, bundle_version, desired_hash}. action applied {surface, desired_hash}: after the \
             node wrote a surface, consumes that approved pass.",
            node_config,
        )
        .family("nodes"),
    );
}
