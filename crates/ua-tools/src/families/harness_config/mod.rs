//! Hub-served harness config bundles: one versioned bundle of rules text,
//! skills and MCP server lists that each node renders into per-harness files
//! (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, codex TOML, opencode JSON).
//!
//! Tools:
//! - `harness_config_publish` (an operator): validate a bundle and make it the
//!   active one. Always a one-time human approval whose payload shows every
//!   item in full (rules text, skill bodies, servers, surfaces) with its hash,
//!   bound to the version and the SHA-256 of the canonical bundle; a version
//!   is published once.
//! - `harness_config_status` (read-only): the active bundle and recent
//!   proposals (the caller's own nodes', or every node's for an operator).
//! - `node_config` (the device plane, behind `GET|POST /api/node/config`):
//!   `get` the bundle for the caller's node with every surface rendered and
//!   the apply grants it holds; `report` drift, which parks one
//!   `harness_config_apply` approval per surface bound to {node, surface,
//!   path, bundle_version, desired_hash} and the content last applied there
//!   (by hash), with the hub's full diff from it shown beside the approval
//!   but not bound by it; `applied` after the node wrote a surface, which
//!   consumes that approved pass.
//!
//! The node never writes a surface without a consumed pass (proposal mode).
//! A drift report must name the active version (else `400` when missing,
//! `409` when another), must use the hub's rendered path for each surface
//! (the node never chooses where a file goes), carries at most
//! [`render::MAX_PROPOSALS_PER_REPORT`] proposals, and each `desired_hash`
//! must equal the hub's own render of that surface (else `409`), so a node
//! cannot have arbitrary content approved. Reports are rate-limited per node
//! ([`MAX_REPORTS_PER_WINDOW`]); an identical re-report adds no drift row and
//! no ledger event. Diffs are computed outside the write transaction, which
//! re-checks that nothing they depend on moved. A proposal whose approval is
//! denied, revoked or expired leaves the pending state; reassigning or
//! forgetting a node closes its open proposals, and the applied history is
//! keyed by (node, agent).
//!
//! Every bundle passes the Python hub's validation ([`render::normalize`])
//! and the hub's own policy ([`policy`]): no TOML injection into the codex
//! surface, clean MCP URLs, no hidden text or permission front matter,
//! allowlisted surface kinds and paths, capped rendered sizes. The active
//! bundle is re-validated on every read, so an imported or older bundle that
//! fails is refused (`unsafe_bundle`), not served.
//!
//! The bundle a node is served is the active bundle plus the registry skills
//! resolved for the node's agent ([`super::skill_registry`]), appended after
//! the bundle's own skills (a bundle skill of the same name wins; one that
//! fails the policy is left out with a note). Rendering is byte-compatible
//! with the Python hub ([`render`]), so Python nodes compare hashes
//! unchanged.
//!
//! Publish, report, applied and closing are ledgered on
//! `agent.harness_config` in the same transaction as the change.
//!
//! Every bundle, proposal, drift row and report window belongs to one
//! organization (`org_id`, [`TENANT_KEYS`] and [`TENANT_PART`]). Every read
//! and write is scoped to the caller's organization: each organization has
//! its own versions and its own active bundle, a node is served its caller's
//! organization's bundle, and another organization's bundle or proposal
//! answers exactly as a missing one. Publish and apply approvals bind
//! `org_id`, so an approval is never consumed across organizations. A write
//! by a caller whose organization `orgs` does not hold is refused before
//! anything changes.

pub mod policy;
pub mod render;
mod tenant_keys;
pub(crate) use tenant_keys::upgrade_expired_approvals;

pub use tenant_keys::{TENANT_KEYS, TENANT_PART};

use std::collections::BTreeMap;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{ActorKind, Caller, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use self::render::{
    Bundle, MAX_BUNDLE_BYTES, MAX_PROPOSALS_PER_REPORT, MAX_SKILLS, Rendered, Skill, content_hash, py_strip,
    render_all, render_surface, valid_surface,
};
use super::node_queue::{device_agent, owned_node, verified_caller};
use super::skill_registry;
use crate::approvals::{self, GateOutcome, RequestState};
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, tool};
use ua_org::authz::{Authority, Authz};

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
-- One drift proposal per (node, agent, surface, version, desired content).
-- diff_text is the hub's own change summary, never the node's diff.
CREATE TABLE IF NOT EXISTS harness_config_proposals (
    id TEXT PRIMARY KEY,
    node TEXT NOT NULL,
    agent TEXT,
    surface TEXT NOT NULL,
    path TEXT NOT NULL,
    bundle_version TEXT NOT NULL,
    desired_hash TEXT NOT NULL,
    observed_hash TEXT,
    diff_text TEXT,
    desired_text TEXT,
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
-- Drift reports per node in the current rate-limit window.
CREATE TABLE IF NOT EXISTS harness_config_report_window (
    node TEXT PRIMARY KEY,
    window_start TEXT NOT NULL,
    reports INTEGER NOT NULL
);
",
};

/// The diff shown with an apply approval ([`approval_display`]): the base it
/// was computed from (`diff_base`, the SHA-256 of the text last applied, or
/// `none`) and a lookup by approval. Apply approvals in the payload shape
/// that bound the diff itself, pending or approved but unused, are expired:
/// they could stop matching on their own, and a node's next report parks a
/// new one.
pub const SCHEMA_V2: SchemaPart = SchemaPart {
    name: "harness_config.v2",
    sql: "
ALTER TABLE harness_config_proposals ADD COLUMN diff_base TEXT;
CREATE INDEX IF NOT EXISTS idx_harness_config_proposals_approval
    ON harness_config_proposals(approval_id);
UPDATE approvals
   SET status = 'expired',
       reason = COALESCE(reason, 'superseded: the harness_config_apply payload changed shape'),
       updated_at = strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now')
 WHERE tool = 'harness_config_apply'
   AND status IN ('pending', 'approved')
   AND json_valid(payload)
   AND json_type(payload, '$.change_summary.diff') IS NOT NULL;
",
};

pub const CHANNEL: &str = "agent.harness_config";
/// The approval each surface write needs.
pub const APPLY_TOOL: &str = "harness_config_apply";
pub const PUBLISH_TOOL: &str = "harness_config_publish";
/// The node's default harness-config root, reported when
/// `harness_config_root_hint` is unset.
pub const DEFAULT_ROOT_HINT: &str = "~/.unified_agent/harness-config";
/// Drift reports one node may send per [`REPORT_WINDOW_S`].
pub const MAX_REPORTS_PER_WINDOW: i64 = 12;
pub const REPORT_WINDOW_S: i64 = 600;
/// How long one change-summary diff may take to compute.
const DIFF_TIMEOUT: Duration = Duration::from_millis(500);

const MAX_DESCRIPTION: usize = 1024;

fn record(tx: &mut WriteTx<'_>, kind: &str, mut payload: Value, by: &str) -> UaResult<()> {
    payload["kind"] = json!(kind);
    // ORG-EVENT-DEFAULT: use the row's organization once callers can resolve
    // to other organizations and org_guard allows it.
    ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, CHANNEL, payload).by(by.to_string()))?;
    Ok(())
}

/// Refuse an organization `orgs` does not hold. Runs before a write's plan
/// and again first in its write transaction: the `org_exists` triggers only
/// see inserts, so an update alone would otherwise pass.
fn require_org(c: &Connection, org: &str) -> UaResult<()> {
    let known = c.query_row("SELECT 1 FROM orgs WHERE id = ?1", [org], |_| Ok(())).optional()?.is_some();
    if !known {
        return Err(UaError::denied(
            "unknown_organization",
            format!("unknown organization {org:?}; the harness config was not changed"),
        ));
    }
    Ok(())
}

fn state_changed() -> UaError {
    UaError::conflict_code(
        "state_changed",
        "the active bundle or this node's applied state changed; report again",
    )
}

// --- the active bundle ------------------------------------------------------------

struct Active {
    version: String,
    published_at: String,
    published_by: String,
    bundle: Bundle,
}

/// The active bundle of `org`, re-validated: a stored bundle (an imported
/// one, or one from an older hub) that fails today's checks is refused, not
/// served.
fn active(c: &Connection, org: &str) -> UaResult<Option<Active>> {
    let row: Option<(String, String, String, String)> = c
        .query_row(
            "SELECT version, published_at, published_by, bundle_json FROM harness_config_bundles \
             WHERE org_id = ?1 AND active = 1 ORDER BY id DESC LIMIT 1",
            [org],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((version, published_at, published_by, json)) = row else { return Ok(None) };
    let unsafe_bundle = |why: String| {
        UaError::conflict_code(
            "unsafe_bundle",
            format!("the active bundle {version:?} fails the hub's checks ({why}); publish a new version"),
        )
    };
    let raw: Value =
        serde_json::from_str(&json).map_err(|e| unsafe_bundle(format!("it does not parse: {e}")))?;
    let bundle = policy::validate(&raw).map_err(|e| unsafe_bundle(e.to_string()))?;
    Ok(Some(Active { version, published_at, published_by, bundle }))
}

/// The bundle a node of `agent` is served: the active bundle plus the
/// registry skills of `org` resolved for the agent (and its default profile), and a
/// note per resolved skill saying whether it was included. A registry skill
/// that fails the bundle policy (a description that cannot go into TOML,
/// hidden text, permission front matter) is left out and the note says why.
fn effective(
    c: &Connection,
    hub: &Hub,
    org: &str,
    agent: &str,
    bundle: &Bundle,
) -> UaResult<(Bundle, Vec<Value>)> {
    let profile = crate::sessions::default_profile(hub, org, agent);
    let resolved = skill_registry::resolve(c, org, agent, Some(profile.as_str()))?;
    let mut out = bundle.clone();
    let mut notes = Vec::new();
    for s in resolved {
        let mut note = json!({ "name": s.name, "version": s.version, "hash": s.hash, "via": s.via });
        let description: String = skill_registry::frontmatter(&s.content)
            .and_then(|m| m.get("description").and_then(Value::as_str).map(|d| py_strip(d).to_string()))
            .map(|d| d.chars().take(MAX_DESCRIPTION).collect())
            .unwrap_or_default();
        let mut findings = policy::skill_findings(&description, &s.content);
        if let Some(why) = policy::description_refusal(&description) {
            findings.insert(0, format!("description {why}"));
        }
        let skipped = if out.skills.iter().any(|k| k.name == s.name) {
            Some("bundle_defines")
        } else if out.skills.len() >= MAX_SKILLS {
            Some("skill_limit")
        } else if !findings.is_empty() {
            note["findings"] = json!(findings);
            Some("unsafe_skill")
        } else {
            out.skills.push(Skill { name: s.name.clone(), description, body: s.content.clone() });
            if out.to_json().len() > MAX_BUNDLE_BYTES || policy::check_rendered(&out).is_err() {
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

/// The path the hub renders `surface` to: its declared path, else the
/// default surface's.
fn surface_path(bundle: &Bundle, surface: &str) -> Option<String> {
    bundle.surfaces().get(surface).map(|s| s.path.clone()).or_else(|| {
        render::DEFAULT_SURFACES.iter().find(|(n, _, _)| *n == surface).map(|(_, p, _)| p.to_string())
    })
}

// --- apply approvals --------------------------------------------------------------

/// The proposal last applied to this node's surface for this agent: id,
/// version, hash and content. History is keyed by (node, agent), so a node
/// reassigned to another agent starts from nothing.
type LastApplied = Option<(String, String, String, Option<String>)>;

fn last_applied(c: &Connection, org: &str, node: &str, agent: &str, surface: &str) -> UaResult<LastApplied> {
    Ok(c.query_row(
        "SELECT id, bundle_version, desired_hash, desired_text FROM harness_config_proposals \
         WHERE org_id = ?1 AND node = ?2 AND agent = ?3 AND surface = ?4 AND status = 'applied' \
         ORDER BY resolved_at DESC, rowid DESC LIMIT 1",
        params![org, node, agent, surface],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .optional()?)
}

/// What a change is computed from: the content last applied to this
/// surface of this node under the same agent (`base: last_applied`), or
/// nothing (`base: none`). Deterministic: the approval binds these values,
/// never the diff, whose output depends on how long it was allowed to run.
fn change_base(last: &LastApplied) -> Value {
    let (base, from_version, from_hash, from_text) = match last {
        None => ("none", None, None, None),
        Some((_, v, h, Some(text))) => ("last_applied", Some(v), Some(h), Some(content_hash(text))),
        Some((_, v, h, None)) => ("last_applied_text_unknown", Some(v), Some(h), None),
    };
    json!({
        "base": base,
        "from_bundle_version": from_version,
        "from_hash": from_hash,
        "from_text_sha256": from_text,
    })
}

/// The unified diff of what changes on the node if `desired` is applied,
/// computed by the hub from the content last applied there (never from
/// anything the node sent). Display only: it is stored on the proposal and
/// shown with the approval ([`approval_display`]), but not bound by it. The
/// diff is never truncated: surfaces are capped instead
/// ([`policy::MAX_SURFACE_BYTES`]), so the approver sees the whole change.
/// Past the time limit `similar` returns a correct but less minimal diff.
fn change_diff(hub: &Hub, last: &LastApplied, path: &str, desired: &str) -> String {
    let old = match last {
        Some((_, _, _, Some(text))) => text.as_str(),
        _ => "",
    };
    let timeout = hub.cfg().harness_config_diff_timeout_ms.map_or(DIFF_TIMEOUT, Duration::from_millis);
    let diff = similar::TextDiff::configure().timeout(timeout).diff_lines(old, desired);
    diff.unified_diff().context_radius(3).header(&format!("a/{path}"), &format!("b/{path}")).to_string()
}

/// The base a change diff is computed from, as stored beside it: the
/// SHA-256 of the text last applied, or `none` (the diff is from nothing).
/// Equals `change_summary.from_text_sha256` of the approval, `none` for null.
fn diff_base(last: &LastApplied) -> String {
    match last {
        Some((_, _, _, Some(text))) => content_hash(text),
        _ => "none".into(),
    }
}

/// Lines added and removed in a unified diff (hunk bodies only).
fn diff_counts(diff: &str) -> (usize, usize) {
    let (mut added, mut removed, mut in_hunk) = (0, 0, false);
    for line in diff.lines() {
        if line.starts_with("@@") {
            in_hunk = true;
        } else if in_hunk && line.starts_with('+') {
            added += 1;
        } else if in_hunk && line.starts_with('-') {
            removed += 1;
        }
    }
    (added, removed)
}

/// What a `harness_config_apply` approval binds: the organization, node,
/// surface, path, version, the desired content's hash and the base it
/// replaces (with the SHA-256 of the last applied text). Every value is
/// deterministic, so the payload recomputed when the pass is checked equals
/// the one approved. The diff the approver reads is display only
/// ([`approval_display`]).
fn canonical(
    org: &str,
    node: &str,
    surface: &str,
    path: &str,
    version: &str,
    desired: &str,
    last: &LastApplied,
) -> Value {
    json!({
        "org_id": org,
        "node": node,
        "surface": surface,
        "path": path,
        "bundle_version": version,
        "desired_hash": content_hash(desired),
        "change_summary": change_base(last),
    })
}

/// What the approver of a `harness_config_apply` approval is shown beside
/// its payload: the hub's full diff, kept on the proposal row, with lines
/// added and removed. Not part of what the approval binds. A diff computed
/// from another base than the one `payload` binds
/// (`change_summary.from_text_sha256`) is never shown in its place. Only
/// proposals of the organization the payload binds are read, and only when
/// that is the approval's own organization (`approval_org`).
pub(crate) fn approval_display(
    c: &Connection,
    approval_org: &str,
    approval_id: i64,
    payload: &Value,
) -> UaResult<Option<Value>> {
    let bound = payload["change_summary"]["from_text_sha256"].as_str().unwrap_or("none").to_string();
    // A payload without `org_id` predates organization keys (and
    // `harness_config.v3.tenant_keys` expired every open one): its proposals
    // were moved to the default organization.
    let org = payload["org_id"].as_str().unwrap_or(ua_core::DEFAULT_ORG);
    if org != approval_org {
        return Ok(None);
    }
    let mut stmt = c.prepare(
        "SELECT id, diff_text, diff_base FROM harness_config_proposals WHERE org_id = ?1 AND approval_id = ?2 \
         ORDER BY updated_at DESC, rowid DESC",
    )?;
    let rows: Vec<(String, Option<String>, Option<String>)> = stmt
        .query_map(params![org, approval_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let Some(first) = rows.first().map(|r| r.0.clone()) else { return Ok(None) };
    Ok(Some(match rows.into_iter().find(|r| r.2.as_deref() == Some(bound.as_str())) {
        Some((proposal_id, diff, _)) => {
            let diff = diff.unwrap_or_default();
            let (added, removed) = diff_counts(&diff);
            json!({ "proposal_id": proposal_id, "lines_added": added, "lines_removed": removed, "diff": diff })
        }
        None => json!({
            "proposal_id": first,
            "diff": null,
            "note": "the stored diff was computed from another base than this approval binds; the node's next \
                     report shows the current one",
        }),
    }))
}

/// Surfaces with an approved, unconsumed apply pass for this node whose
/// desired content is still the current render. Read-only: no approval is
/// asked for or consumed.
fn apply_grants(
    c: &Connection,
    hub: &Hub,
    org: &str,
    agent: &str,
    node: &str,
    version: &str,
    current: &BTreeMap<String, Rendered>,
) -> UaResult<Vec<Value>> {
    let mut stmt = c.prepare(
        "SELECT id, surface, path, desired_hash FROM harness_config_proposals \
         WHERE org_id = ?1 AND node = ?2 AND agent = ?3 AND bundle_version = ?4 AND status = 'pending' \
         ORDER BY created_at, id",
    )?;
    let rows: Vec<(String, String, String, String)> = stmt
        .query_map(params![org, node, agent, version], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    let mut grants = Vec::new();
    for (id, surface, path, hash) in rows {
        let Some(r) = current.get(&surface).filter(|r| r.hash == hash && r.path == path) else { continue };
        let last = last_applied(c, org, node, agent, &surface)?;
        let payload = canonical(org, node, &surface, &path, version, &r.content, &last);
        if let Some(RequestState::Approved { approval_id }) =
            approvals::peek(c, hub.cfg(), org, agent, APPLY_TOOL, &payload)?
        {
            grants.push(json!({
                "proposal_id": id,
                "surface": surface,
                "path": path,
                "desired_hash": hash,
                "approval_id": approval_id,
                "bundle_version": version,
            }));
        }
    }
    Ok(grants)
}

/// Move this node's pending proposals whose approval was denied, revoked or
/// has expired out of the pending state. Returns how many moved.
fn settle(tx: &mut WriteTx<'_>, hub: &Hub, org: &str, node: &str, agent: &str, by: &str) -> UaResult<usize> {
    let mut stmt = tx.prepare(
        "SELECT p.id, a.status, a.resolved_at FROM harness_config_proposals p \
         JOIN approvals a ON a.org_id = p.org_id AND a.id = p.approval_id \
         WHERE p.org_id = ?1 AND p.node = ?2 AND p.agent = ?3 AND p.status = 'pending'",
    )?;
    let rows: Vec<(String, String, Option<String>)> = stmt
        .query_map(params![org, node, agent], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    drop(stmt);
    let now = ua_core::time::now();
    let mut moved = 0;
    for (id, status, resolved_at) in rows {
        let to = match status.as_str() {
            "denied" => "denied",
            "revoked" | "expired" => "expired",
            "approved" if approvals::pass_expired(hub.cfg(), resolved_at.as_deref()) => "expired",
            _ => continue,
        };
        moved += tx.execute(
            "UPDATE harness_config_proposals SET status = ?3, updated_at = ?4, resolved_at = ?4, resolved_by = ?5 \
             WHERE org_id = ?1 AND id = ?2",
            params![org, id, to, now, by],
        )?;
    }
    Ok(moved)
}

/// Close a node's open proposals when it is reassigned or forgotten, so its
/// pending approvals never apply under another owner.
///
/// `org` is the node's organization (`nodes.org_id`): a node belongs to the
/// organization that registered it, and its proposals were made by its
/// agent's calls in that organization, so only that organization's are
/// closed. (Before nodes carried `org_id` this spanned every organization.)
pub(crate) fn close_for_node(
    tx: &mut WriteTx<'_>,
    org: &str,
    node: &str,
    reason: &str,
    by: &str,
) -> UaResult<()> {
    let now = ua_core::time::now();
    let n = tx.execute(
        "UPDATE harness_config_proposals SET status = 'closed', updated_at = ?2, resolved_at = ?2, \
         resolved_by = ?3 WHERE org_id = ?4 AND node = ?1 AND status = 'pending'",
        params![node, now, by, org],
    )?;
    if n > 0 {
        // ORG-EVENT-DEFAULT: another organization's node name stays out of
        // the default ledger.
        let node_ref = super::plans::ledger_text(org, node);
        let by = if org == ua_core::DEFAULT_ORG { by } else { "system" };
        record(
            tx,
            "harness_config_closed",
            json!({ "node": node_ref, "reason": reason, "proposals": n }),
            by,
        )?;
    }
    Ok(())
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

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeConfigArgs {
    /// The calling agent's node.
    pub node: String,
    /// `get` (default), `report` or `applied`.
    #[serde(default)]
    pub action: Option<String>,
    /// `report`: up to 32 drift proposals, each {surface, path, desired_hash,
    /// observed_hash?, diff?}. `diff` is accepted for compatibility and
    /// ignored: the hub computes its own.
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

fn get_payload(c: &Connection, hub: &Hub, org: &str, agent: &str, node: &str) -> UaResult<Value> {
    let row = owned_node(c, org, node, agent)?;
    let Some(active) = active(c, org)? else { return Ok(no_bundle()) };
    let (bundle, assigned) = effective(c, hub, org, agent, &active.bundle)?;
    let rendered = render_all(&bundle)?;
    let grants = apply_grants(c, hub, org, agent, &row.node, &active.version, &rendered)?;
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

/// One validated drift proposal, with its approval payload computed outside
/// the write transaction.
struct Planned {
    surface: String,
    path: String,
    desired_hash: String,
    desired: String,
    observed_hash: Option<String>,
    payload: Value,
    /// The hub's diff for the approver (display only, not in `payload`).
    diff: String,
    /// What `diff` was computed from ([`diff_base`]).
    diff_base: String,
    /// The last applied proposal the change summary was computed from.
    base: Option<String>,
}

struct ReportPlan {
    node: String,
    version: String,
    items: Vec<Planned>,
}

/// Validate a report and compute every approval payload (diffs included)
/// on a read connection.
fn plan_report(
    c: &Connection,
    hub: &Hub,
    org: &str,
    agent: &str,
    a: &NodeConfigArgs,
) -> UaResult<ReportPlan> {
    require_org(c, org)?;
    let node = owned_node(c, org, &a.node, agent)?.node;
    let Some(active) = active(c, org)? else {
        return Err(UaError::not_found("no active harness config bundle"));
    };
    let version = active.version.clone();
    let Some(v) = a.bundle_version.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
        return Err(UaError::invalid("bundle_version is required: the version the node rendered"));
    };
    if v != version {
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
    let (bundle, _) = effective(c, hub, org, agent, &active.bundle)?;
    let mut items = Vec::new();
    for raw in proposals {
        let Some(raw) = raw.as_object() else {
            return Err(UaError::invalid("each proposal must be an object"));
        };
        let Some(surface) = field(raw, "surface", 32)?.filter(|s| valid_surface(s)) else {
            return Err(UaError::invalid("proposal.surface is invalid"));
        };
        let Some(path) = field(raw, "path", 256)? else {
            return Err(UaError::invalid("proposal.path is invalid"));
        };
        let Some(desired_hash) = field(raw, "desired_hash", 64)?.filter(|h| sha256_hex(h)) else {
            return Err(UaError::invalid("proposal.desired_hash must be sha256 hex"));
        };
        // The file is written where the hub renders it, never a path the
        // node chose.
        let hub_path = surface_path(&bundle, &surface)
            .ok_or_else(|| UaError::invalid(format!("unknown surface {surface:?}")))?;
        if path != hub_path {
            return Err(UaError::invalid(format!(
                "proposal.path for {surface:?} must be the hub's rendered path {hub_path:?}"
            )));
        }
        // Recompute from the hub's own bundle so a node cannot invent content.
        let desired = render_surface(&bundle, &surface)?;
        if content_hash(&desired) != desired_hash {
            return Err(UaError::conflict_code(
                "desired_hash_mismatch",
                format!("desired_hash for {surface:?} does not match active bundle render"),
            ));
        }
        let observed_hash = field(raw, "observed_hash", 64)?;
        let last = last_applied(c, org, &node, agent, &surface)?;
        let payload = canonical(org, &node, &surface, &path, &version, &desired, &last);
        let diff = change_diff(hub, &last, &path, &desired);
        items.push(Planned {
            surface,
            path,
            desired_hash,
            desired,
            observed_hash,
            payload,
            diff,
            diff_base: diff_base(&last),
            base: last.map(|l| l.0),
        });
    }
    Ok(ReportPlan { node, version, items })
}

/// Count this report against the node's window in `org`; refuse past the
/// limit.
fn rate_limit(tx: &mut WriteTx<'_>, org: &str, node: &str) -> UaResult<()> {
    let now = ua_core::time::now();
    let row: Option<(String, i64)> = tx
        .query_row(
            "SELECT window_start, reports FROM harness_config_report_window WHERE org_id = ?1 AND node = ?2",
            [org, node],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let fresh = match &row {
        None => true,
        Some((start, _)) => match (ua_core::time::parse_ts(start), ua_core::time::parse_ts(&now)) {
            (Some(s), Some(n)) => (n.as_second() - s.as_second()) >= REPORT_WINDOW_S,
            _ => true,
        },
    };
    if fresh {
        tx.execute(
            "INSERT INTO harness_config_report_window (org_id, node, window_start, reports) \
             VALUES (?1, ?2, ?3, 1) \
             ON CONFLICT(org_id, node) DO UPDATE SET window_start = excluded.window_start, reports = 1",
            params![org, node, now],
        )?;
        return Ok(());
    }
    let count = row.map(|r| r.1).unwrap_or_default();
    if count >= MAX_REPORTS_PER_WINDOW {
        return Err(UaError::conflict_code(
            "report_rate_limited",
            format!(
                "at most {MAX_REPORTS_PER_WINDOW} drift reports per node every {REPORT_WINDOW_S} seconds"
            ),
        ));
    }
    tx.execute(
        "UPDATE harness_config_report_window SET reports = reports + 1 WHERE org_id = ?1 AND node = ?2",
        [org, node],
    )?;
    Ok(())
}

fn commit_report(tx: &mut WriteTx<'_>, hub: &Hub, caller: &Caller, plan: ReportPlan) -> UaResult<Value> {
    let agent = caller.label.as_str();
    let org = caller.org_id.as_str();
    require_org(tx, org)?;
    let node = owned_node(tx, org, &plan.node, agent)?.node;
    if active(tx, org)?.map(|a| a.version).as_deref() != Some(plan.version.as_str()) {
        return Err(state_changed());
    }
    for item in &plan.items {
        if last_applied(tx, org, &node, agent, &item.surface)?.map(|l| l.0) != item.base {
            return Err(state_changed());
        }
    }
    rate_limit(tx, org, &node)?;
    let mut changed = settle(tx, hub, org, &node, agent, agent)? > 0;
    let version = plan.version;
    let now = ua_core::time::now();
    let mut accepted = Vec::new();
    for item in plan.items {
        let state = approvals::request(tx, hub.cfg(), caller, APPLY_TOOL, &item.payload)?;
        // id, observed_hash, approval_id, diff_base
        type Existing = (String, Option<String>, Option<i64>, Option<String>);
        let existing: Option<Existing> = tx
            .query_row(
                "SELECT id, observed_hash, approval_id, diff_base FROM harness_config_proposals WHERE org_id = ?1 \
                 AND node = ?2 AND agent = ?3 AND surface = ?4 AND bundle_version = ?5 AND desired_hash = ?6 \
                 AND path = ?7 AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
                params![org, node, agent, item.surface, version, item.desired_hash, item.path],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let proposal_id = match existing {
            Some((id, observed, approval, stored_base)) => {
                if observed != item.observed_hash
                    || approval != Some(state.approval_id())
                    || stored_base.as_deref() != Some(item.diff_base.as_str())
                {
                    // The diff shown always comes from the base the
                    // approval binds.
                    tx.execute(
                        "UPDATE harness_config_proposals SET observed_hash = ?3, approval_id = ?4, updated_at = ?5, \
                         diff_text = ?6, diff_base = ?7 WHERE org_id = ?1 AND id = ?2",
                        params![org, id, item.observed_hash, state.approval_id(), now, item.diff, item.diff_base],
                    )?;
                    changed = true;
                }
                id
            }
            None => {
                let id = new_proposal_id();
                tx.execute(
                    "INSERT INTO harness_config_proposals (org_id, id, node, agent, surface, path, bundle_version, \
                     desired_hash, observed_hash, diff_text, desired_text, status, approval_id, created_at, \
                     updated_at, diff_base) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', ?12, \
                     ?13, ?13, ?14)",
                    params![
                        org,
                        id,
                        node,
                        agent,
                        item.surface,
                        item.path,
                        version,
                        item.desired_hash,
                        item.observed_hash,
                        item.diff,
                        item.desired,
                        state.approval_id(),
                        now,
                        item.diff_base
                    ],
                )?;
                changed = true;
                id
            }
        };
        if let RequestState::Denied { .. } = state {
            tx.execute(
                "UPDATE harness_config_proposals SET status = 'denied', resolved_at = ?3, resolved_by = ?4, \
                 updated_at = ?3 WHERE org_id = ?1 AND id = ?2 AND status = 'pending'",
                params![org, proposal_id, now, agent],
            )?;
        }
        // One drift row per distinct observation, not per report.
        let last_drift: Option<(String, Option<String>, String)> = tx
            .query_row(
                "SELECT bundle_version, observed_hash, desired_hash FROM harness_config_drift \
                 WHERE org_id = ?1 AND node = ?2 AND surface = ?3 ORDER BY id DESC LIMIT 1",
                params![org, node, item.surface],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if last_drift != Some((version.clone(), item.observed_hash.clone(), item.desired_hash.clone())) {
            tx.execute(
                "INSERT INTO harness_config_drift (org_id, node, surface, path, bundle_version, observed_hash, \
                 desired_hash, reported_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![org, node, item.surface, item.path, version, item.observed_hash, item.desired_hash, now],
            )?;
            changed = true;
        }
        accepted.push(json!({
            "proposal_id": proposal_id,
            "surface": item.surface,
            "path": item.path,
            "approval_id": state.approval_id(),
            "status": state.status(),
            "inbox": null,
        }));
    }
    if changed {
        let summary: Vec<Value> = accepted
            .iter()
            .map(|p| {
                json!({
                    "proposal_id": p["proposal_id"],
                    "surface": p["surface"],
                    "approval_id": p["approval_id"],
                    "status": p["status"],
                })
            })
            .collect();
        record(
            tx,
            "harness_config_report",
            json!({ "node": node, "bundle_version": version, "proposals": summary }),
            agent,
        )?;
    }
    Ok(json!({ "ok": true, "bundle_version": version, "proposals": accepted }))
}

/// The grants a node holds now, for a report's answer.
fn grants_now(c: &Connection, hub: &Hub, org: &str, agent: &str, node: &str) -> UaResult<Vec<Value>> {
    let Some(active) = active(c, org)? else { return Ok(Vec::new()) };
    let (bundle, _) = effective(c, hub, org, agent, &active.bundle)?;
    apply_grants(c, hub, org, agent, node, &active.version, &render_all(&bundle)?)
}

/// An `applied` call, validated and with its approval payload computed.
struct AppliedPlan {
    node: String,
    version: String,
    surface: String,
    hash: String,
    proposal_id: String,
    path: String,
    payload: Value,
    /// The diff from the current base, shown with a new approval if the
    /// call parks one, and that base ([`diff_base`]).
    diff: String,
    diff_base: String,
    base: Option<String>,
}

fn plan_applied(
    c: &Connection,
    hub: &Hub,
    org: &str,
    agent: &str,
    a: &NodeConfigArgs,
) -> UaResult<AppliedPlan> {
    let surface = a.surface.as_deref().map(py_strip).unwrap_or_default().to_string();
    if !valid_surface(&surface) {
        return Err(UaError::invalid("surface is invalid"));
    }
    let hash = a.desired_hash.as_deref().map(py_strip).unwrap_or_default().to_string();
    if !sha256_hex(&hash) {
        return Err(UaError::invalid("desired_hash must be sha256 hex"));
    }
    require_org(c, org)?;
    let node = owned_node(c, org, &a.node, agent)?.node;
    let Some(active) = active(c, org)? else {
        return Err(UaError::not_found("no active harness config bundle"));
    };
    let version = active.version.clone();
    let (bundle, _) = effective(c, hub, org, agent, &active.bundle)?;
    let desired = render_surface(&bundle, &surface)?;
    if content_hash(&desired) != hash {
        return Err(UaError::conflict_code(
            "desired_hash_mismatch",
            "desired_hash does not match active bundle",
        ));
    }
    let proposal: Option<(String, String)> = c
        .query_row(
            "SELECT id, path FROM harness_config_proposals WHERE org_id = ?1 AND node = ?2 AND agent = ?3 \
             AND surface = ?4 AND bundle_version = ?5 AND desired_hash = ?6 AND status = 'pending' \
             ORDER BY created_at DESC, id DESC LIMIT 1",
            params![org, node, agent, surface, version, hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((proposal_id, path)) = proposal else {
        return Err(UaError::not_found("no matching pending proposal"));
    };
    if surface_path(&bundle, &surface).as_deref() != Some(path.as_str()) {
        return Err(UaError::conflict_code(
            "path_mismatch",
            "the proposal's path is not the hub's rendered path",
        ));
    }
    let last = last_applied(c, org, &node, agent, &surface)?;
    let payload = canonical(org, &node, &surface, &path, &version, &desired, &last);
    let diff = change_diff(hub, &last, &path, &desired);
    Ok(AppliedPlan {
        node,
        version,
        surface,
        hash,
        proposal_id,
        path,
        payload,
        diff,
        diff_base: diff_base(&last),
        base: last.map(|l| l.0),
    })
}

/// Why an `applied` call did not apply, committed with its bookkeeping.
enum NotApplied {
    Pending(i64),
    Denied(i64, Option<String>),
}

fn commit_applied(
    tx: &mut WriteTx<'_>,
    hub: &Hub,
    caller: &Caller,
    p: AppliedPlan,
) -> UaResult<Result<Value, NotApplied>> {
    let agent = caller.label.as_str();
    let org = caller.org_id.as_str();
    require_org(tx, org)?;
    owned_node(tx, org, &p.node, agent)?;
    if active(tx, org)?.map(|a| a.version).as_deref() != Some(p.version.as_str())
        || last_applied(tx, org, &p.node, agent, &p.surface)?.map(|l| l.0) != p.base
    {
        return Err(state_changed());
    }
    settle(tx, hub, org, &p.node, agent, agent)?;
    let status: Option<String> = tx
        .query_row(
            "SELECT status FROM harness_config_proposals WHERE org_id = ?1 AND id = ?2",
            [org, p.proposal_id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    if status.as_deref() != Some("pending") {
        return Err(UaError::not_found("no matching pending proposal"));
    }
    let now = ua_core::time::now();
    let approval_id = match approvals::gate(tx, hub.cfg(), caller, APPLY_TOOL, &p.payload)? {
        GateOutcome::Pass { approval_id } => approval_id,
        GateOutcome::Pending { approval_id } => {
            // The approval parked now binds the current base: show its diff.
            tx.execute(
                "UPDATE harness_config_proposals SET approval_id = ?3, diff_text = ?4, diff_base = ?5, \
                 updated_at = ?6 WHERE org_id = ?1 AND id = ?2",
                params![org, p.proposal_id, approval_id, p.diff, p.diff_base, now],
            )?;
            return Ok(Err(NotApplied::Pending(approval_id)));
        }
        GateOutcome::Denied { approval_id, reason } => {
            tx.execute(
                "UPDATE harness_config_proposals SET status = 'denied', resolved_at = ?3, resolved_by = ?4, \
                 updated_at = ?3 WHERE org_id = ?1 AND id = ?2",
                params![org, p.proposal_id, now, agent],
            )?;
            return Ok(Err(NotApplied::Denied(approval_id, reason)));
        }
    };
    tx.execute(
        "UPDATE harness_config_proposals SET status = 'applied', approval_id = ?3, updated_at = ?4, \
         resolved_at = ?4, resolved_by = ?5 WHERE org_id = ?1 AND id = ?2",
        params![org, p.proposal_id, approval_id, now, agent],
    )?;
    record(
        tx,
        "harness_config_applied",
        json!({
            "node": p.node,
            "surface": p.surface,
            "path": p.path,
            "proposal_id": p.proposal_id,
            "approval_id": approval_id,
            "bundle_version": p.version,
            "desired_hash": p.hash,
        }),
        agent,
    )?;
    Ok(Ok(json!({
        "ok": true,
        "proposal_id": p.proposal_id,
        "surface": p.surface,
        "bundle_version": p.version,
        "approval_id": approval_id,
    })))
}

async fn node_config(ctx: ToolCtx, a: NodeConfigArgs) -> UaResult<Value> {
    device_agent(&ctx.caller)?;
    let action = crate::routes::action_of("node_config", a.action.as_deref())?;
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let agent = caller.label.clone();
    // The bundle, the registry skills and the proposals of a node are its
    // caller's organization's.
    let org = caller.org_id.clone();
    let db = ctx.hub.db();
    match action {
        "get" => db.read_async(move |c| get_payload(c, &hub, &org, &agent, &a.node)).await,
        "report" => {
            let (h, o, ag) = (hub.clone(), org.clone(), agent.clone());
            let plan = db.read_async(move |c| plan_report(c, &h, &o, &ag, &a)).await?;
            let node = plan.node.clone();
            let h = hub.clone();
            let mut out = db.write_async(move |tx| commit_report(tx, &h, &caller, plan)).await?;
            out["apply_grants"] =
                json!(db.read_async(move |c| grants_now(c, &hub, &org, &agent, &node)).await?);
            Ok(out)
        }
        "applied" => {
            let (h, o, ag) = (hub.clone(), org.clone(), agent.clone());
            let plan = db.read_async(move |c| plan_applied(c, &h, &o, &ag, &a)).await?;
            match db.write_async(move |tx| commit_applied(tx, &hub, &caller, plan)).await? {
                Ok(v) => Ok(v),
                Err(NotApplied::Pending(approval_id)) => {
                    Err(UaError::ApprovalRequired { tool: APPLY_TOOL.into(), approval_id })
                }
                Err(NotApplied::Denied(approval_id, reason)) => Err(UaError::denied(
                    "approval_denied",
                    format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                )),
            }
        }
        other => Err(crate::routes::unhandled("node_config", other)),
    }
}

// --- publish and status -----------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishArgs {
    /// The bundle: {version, rules?: {surface: text}, skills?: [{name,
    /// description?, body?}], mcp_servers?: [{name, url, auth?: oauth|oauth2|none,
    /// transport?}], surfaces?: {surface: {path, kind?: rules|mcp}}}.
    pub bundle: Value,
}

/// What a publish approval binds and shows: the organization, the version,
/// the SHA-256 of the canonical bundle, and every item in full with its own
/// hash, so the approver sees exactly what nodes will be served.
fn publish_payload(org: &str, b: &Bundle) -> Value {
    let rules: Map<String, Value> =
        b.rules.iter().map(|(k, t)| (k.clone(), json!({ "sha256": content_hash(t), "text": t }))).collect();
    json!({
        "org_id": org,
        "version": b.version,
        "bundle_sha256": b.sha256(),
        "surfaces": b.surfaces().into_iter().map(|(n, s)| json!({ "surface": n, "path": s.path, "kind": s.kind })).collect::<Vec<_>>(),
        "rules": rules,
        "skills": b.skills.iter().map(|s| json!({
            "name": s.name,
            "description": s.description,
            "sha256": content_hash(&s.body),
            "body": s.body,
        })).collect::<Vec<_>>(),
        "mcp_servers": b.mcp_servers.iter().map(|s| json!({
            "name": s.name, "url": s.url, "auth": s.auth, "transport": s.transport,
        })).collect::<Vec<_>>(),
        "checks": "passed: TOML-safe names, URLs, descriptions and rules; no hidden text; no permission front matter; \
                   surface paths and kinds allowlisted; rendered size within limits",
    })
}

async fn publish(ctx: ToolCtx, a: PublishArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    {
        let org = org.clone();
        ctx.hub.db().read_async(move |c| require_org(c, &org)).await?;
    }
    let who = verified_caller(&ctx.caller, "publishing a harness config bundle")?;
    if !Authz::new(ctx.hub.cfg()).holds(&ctx.caller, &[Authority::Operator], &org) {
        return Err(UaError::denied(
            "operator_required",
            "publishing a harness config bundle is for an operator (a verified human)",
        ));
    }
    let bundle = policy::validate(&a.bundle)?;
    let payload = publish_payload(&org, &bundle);
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let taken: Option<i64> = tx
                .query_row(
                    "SELECT id FROM harness_config_bundles WHERE org_id = ?1 AND version = ?2",
                    [org.as_str(), bundle.version.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            if taken.is_some() {
                return Err(UaError::conflict_code(
                    "version_published",
                    format!("version {:?} already published", bundle.version),
                ));
            }
            match approvals::gate(tx, hub.cfg(), &caller, PUBLISH_TOOL, &payload)? {
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
            tx.execute("UPDATE harness_config_bundles SET active = 0 WHERE org_id = ?1 AND active = 1", [&org])?;
            tx.execute(
                "INSERT INTO harness_config_bundles (org_id, version, published_at, published_by, bundle_json, \
                 active) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                params![org, bundle.version, now, who, bundle.to_json()],
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
    if matches!(ctx.caller.kind, ActorKind::Anonymous) {
        return Err(UaError::Unauthenticated(
            "the harness config status needs an authenticated identity".into(),
        ));
    }
    let who = verified_caller(&ctx.caller, "reading the harness config status")?;
    // Operators see every node's proposals in their organization; anyone
    // else only their own nodes'. Nothing of another organization is read.
    let org = ctx.caller.org_id.clone();
    let scope: Option<String> = (!Authz::new(ctx.hub.cfg()).holds(
        &ctx.caller,
        &[Authority::Operator, Authority::LifecycleOperator],
        &org,
    ))
    .then_some(who);
    ctx.hub
        .db()
        .read_async(move |c| {
            let active = match active(c, &org) {
                Ok(a) => a.map(|a| {
                    json!({
                        "version": a.version,
                        "published_at": a.published_at,
                        "published_by": a.published_by,
                        "bundle": a.bundle.to_value(),
                    })
                }),
                Err(e) => {
                    Some(json!({ "error": e.to_string(), "code": e.reason_code().unwrap_or(e.code()) }))
                }
            };
            let filter = "org_id = ?2 \
                 AND (?1 IS NULL OR (agent = ?1 AND node IN (SELECT node FROM nodes WHERE agent = ?1 AND org_id = ?2)))";
            let pending: i64 = c.query_row(
                &format!(
                    "SELECT COUNT(*) FROM harness_config_proposals WHERE status = 'pending' AND {filter}"
                ),
                params![scope, org],
                |r| r.get(0),
            )?;
            let mut stmt = c.prepare(&format!(
                "SELECT id, node, surface, path, bundle_version, status, created_at, approval_id \
                 FROM harness_config_proposals WHERE {filter} ORDER BY created_at DESC, id DESC LIMIT 25"
            ))?;
            let recent = stmt
                .query_map(params![scope, org], |r| {
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
                "scope": if scope.is_some() { "own_nodes" } else { "all" },
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
             (OAuth or none), rendered by each node into CLAUDE.md, AGENTS.md, .cursorrules, codex and opencode \
             config. Refused: bearer/token auth or embedded secrets, unclean MCP URLs, TOML-breaking names, URLs, \
             descriptions or rules, hidden text, permission front matter, surface kinds other than rules and mcp, \
             unsafe surface paths, oversized renders. Always needs a one-time human approval showing every item \
             in full and bound to the bundle's SHA-256; a version is published once. Makes it the active bundle. \
             Returns {ok, version, bundle_id, published_at, published_by, surfaces, mcp_servers, skills}.",
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
             proposals: the caller's own nodes' proposals, or every node's for an operator. Read-only.",
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
             grants the node holds. action report {bundle_version, proposals}: drift, at most 32 surfaces, rate \
             limited per node; bundle_version is required, each path must be the hub's rendered path and each \
             desired_hash the hub's render; each parks one harness_config_apply approval bound to {node, surface, \
             path, bundle_version, desired_hash} and the content last applied (by hash); approval_pending shows \
             the hub's full diff beside it. action \
             applied {surface, desired_hash}: after the node wrote a surface, consumes that approved pass.",
            node_config,
        )
        .handler_may_gate(crate::HandlerGate::Always)
        .family("nodes"),
    );
}
