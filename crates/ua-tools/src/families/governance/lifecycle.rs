//! Agent lifecycle: pause, resume, terminate, retire and unretire an agent.
//!
//! An agent is `active`, `paused`, `terminated` or `retired`. The current
//! state is one row in `agent_lifecycle` (an agent with no row is `active`);
//! every change also appends an `agent.lifecycle` ledger event
//! (`kind: lifecycle.changed`) in the same write transaction.
//!
//! What a state does:
//!
//! - **Claims.** A paused, terminated or retired agent takes no work: the one
//!   claim gate ([`super::claim_block`]) refuses its `task_claim` (renewals
//!   too), `task_update` into `doing`, dispatch runs bound to it and its
//!   nodes' enqueues and claims, with the reason code `agent_<state>`.
//! - **Work in flight.** Pause, terminate and retire request a stop on what
//!   the hub can reach and report each as a `stops` row with an honest
//!   `control`: live dispatch runs go through the `dispatch_cancel` path
//!   (`confirmed` or `requested`), claimed node items are flagged for the
//!   node (`requested`), and a self-picked-up `doing` claim has no process
//!   the hub controls (`unsupported`). Pause leaves queued node items queued:
//!   `node_claim` refuses the paused owner, so they wait for the resume.
//!   Terminate and retire also cancel queued node items.
//! - **Terminate** also releases the agent's `doing` claims (back to `open`)
//!   in the state change's transaction, so another agent can take the work.
//! - **Retire** is the decommission marker. It is refused while the agent
//!   holds `doing` claims, and in the same transaction it revokes the
//!   agent's managed tokens (`agent_tokens`), OAuth sign-ins and node
//!   session credentials. The HTTP
//!   adapter refuses a retired identity's static token too ([`is_retired`]).
//!   `agent_resume` cannot undo it; only `agent_unretire` can, and that
//!   re-issues nothing.
//!
//! Authority: a lifecycle operator (or a human identity) may change any
//! agent. An agent may pause or terminate itself, and resume only from a
//! stop it imposed on itself. A stop an operator imposes is recorded in
//! `imposed_by` and survives the agent's own later transitions (an operator
//! pause followed by a self-terminate is still the operator's stop); only an
//! operator transition back to `active` clears it. Retire and unretire are
//! operator actions only, for an agent's own label too.
//!
//! **Forget** (`agent_forget`, lifecycle operators only) deletes a retired
//! agent's row, its lifecycle row and its profile bindings, so the label can
//! be registered again; its sessions, notes and revoked tokens stay as
//! history in its organization. It first revokes, again, every managed
//! token, OAuth sign-in and session credential issued for the label since
//! the retire, so a credential minted after the retire never comes back to
//! life with the label. It is refused for a label hub configuration names
//! ([`agents::Reserved`]: a static token, `[profiles]`, `oauth_identities`
//! and the rest): the retired lifecycle row is the only thing that keeps a
//! static configuration token, which cannot be revoked, from
//! authenticating, so such a label is forgotten only after the operator
//! removes it from configuration. Refusing was chosen over a tombstone
//! that [`is_retired`] would honour: a tombstone keeps the label unusable
//! forever, which is what forget exists to undo, and it would need a second
//! store that every credential path must remember to read.
//!
//! Organizations: a lifecycle row is in its agent's organization, and every
//! action works in the caller's organization. The stops an action requests
//! (doing claims, node items, dispatch runs) and the doing-claim refusal of
//! a retire read that organization only. A label another organization's
//! agent holds reads as an agent with no lifecycle record (`agent_state`),
//! and a change to it is refused as a taken label. Agent labels are one hub
//! namespace, so a default-organization lifecycle operator can recover a
//! label any organization holds: `agent_retire` and `agent_forget` with
//! `any_org=true` act in the agent's own organization through the same code,
//! and another organization's agent answers only
//! `{agent, org_id, changed, retired or forgotten, hub_recovery}`. Events
//! about another organization's agent carry no label, reason or actor
//! (`ORG-EVENT-DEFAULT`, through `agents::emit`).

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::WriteTx;

use super::{clean_reason, now, verified_actor};
use crate::families::agents::{self, validate_label};
use crate::families::dispatch;
use crate::families::plans::{ledger_label, ledger_text};
use crate::families::{node_queue, tokens};
use crate::hub::Hub;
use crate::registry::ToolCtx;
use ua_org::authz::{Authority, Authz};

pub const CHANNEL: &str = "agent.lifecycle";
const MAX_OWNER: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    Pause,
    Resume,
    Terminate,
    Retire,
    Unretire,
    Forget,
}

impl Verb {
    fn as_str(self) -> &'static str {
        match self {
            Verb::Pause => "pause",
            Verb::Resume => "resume",
            Verb::Terminate => "terminate",
            Verb::Retire => "retire",
            Verb::Unretire => "unretire",
            Verb::Forget => "forget",
        }
    }

    fn target(self) -> &'static str {
        match self {
            Verb::Pause => "paused",
            Verb::Resume | Verb::Unretire => "active",
            Verb::Terminate => "terminated",
            Verb::Retire | Verb::Forget => "retired",
        }
    }

    fn operator_only(self) -> bool {
        matches!(self, Verb::Retire | Verb::Unretire | Verb::Forget)
    }

    fn reason_required(self) -> bool {
        matches!(self, Verb::Pause | Verb::Terminate | Verb::Retire | Verb::Forget)
    }
}

/// One `agent_lifecycle` row.
#[derive(Debug, Clone)]
struct Row {
    agent: String,
    state: String,
    previous: Option<String>,
    reason: Option<String>,
    actor: String,
    /// The operator whose stop is in force, if one is: set when an operator
    /// stops the agent, kept through the agent's own transitions, cleared
    /// only when an operator returns it to `active`.
    imposed_by: Option<String>,
    owner: Option<String>,
    since: String,
}

const COLUMNS: &str = "agent, state, previous, reason, actor, imposed_by, owner, since";

fn row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        agent: r.get(0)?,
        state: r.get(1)?,
        previous: r.get(2)?,
        reason: r.get(3)?,
        actor: r.get(4)?,
        imposed_by: r.get(5)?,
        owner: r.get(6)?,
        since: r.get(7)?,
    })
}

/// `agent`'s lifecycle row in any organization. An agent label is one
/// hub-wide namespace and an agent belongs to one organization, so the claim
/// gate and the HTTP adapter read a label's state wherever it is.
fn load(c: &Connection, agent: &str) -> UaResult<Option<Row>> {
    Ok(c.query_row(&format!("SELECT {COLUMNS} FROM agent_lifecycle WHERE agent = ?1"), [agent], row_from)
        .optional()?)
}

/// `agent`'s lifecycle row in organization `org` only.
fn load_in(c: &Connection, org: &str, agent: &str) -> UaResult<Option<Row>> {
    Ok(c.query_row(
        &format!("SELECT {COLUMNS} FROM agent_lifecycle WHERE org_id = ?1 AND agent = ?2"),
        [org, agent],
        row_from,
    )
    .optional()?)
}

fn state_json(agent: &str, row: Option<&Row>) -> Value {
    match row {
        None => json!({
            "agent": agent, "state": "active", "previous": null, "reason": null, "actor": null,
            "imposed_by": null, "since": null, "owner_of_record": null, "owner_source": null,
        }),
        Some(r) => json!({
            "agent": r.agent,
            "state": r.state,
            "previous": r.previous,
            "reason": r.reason,
            "actor": r.actor,
            "imposed_by": r.imposed_by,
            "since": r.since,
            "owner_of_record": r.owner,
            "owner_source": r.owner.as_ref().map(|_| "explicit"),
        }),
    }
}

/// A stopped agent's state, as the claim gate reports it.
pub(crate) struct Stopped {
    state: String,
    reason: Option<String>,
    actor: String,
}

impl Stopped {
    pub fn code(&self) -> &'static str {
        match self.state.as_str() {
            "paused" => "agent_paused",
            "terminated" => "agent_terminated",
            _ => "agent_retired",
        }
    }

    pub fn refusal(&self, agent: &str) -> String {
        let why = self.reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default();
        if self.state == "retired" {
            format!(
                "agent {agent:?} is retired (by {}){why}. A retired identity takes no work; an operator must \
                 unretire it explicitly (coordination_manage agent_unretire)",
                self.actor
            )
        } else {
            format!(
                "agent {agent:?} is {} (by {}){why}. A {} agent takes no work until it is resumed \
                 (coordination_manage agent_resume)",
                self.state, self.actor, self.state
            )
        }
    }
}

/// `agent`'s state when it is paused, terminated or retired (matched
/// without regard to case), else `None`.
pub(crate) fn stopped(c: &Connection, agent: &str) -> UaResult<Option<Stopped>> {
    Ok(load(c, agent.trim())?.filter(|r| r.state != "active").map(|r| Stopped {
        state: r.state,
        reason: r.reason,
        actor: r.imposed_by.unwrap_or(r.actor),
    }))
}

/// Whether `label` is a retired identity. The HTTP adapter refuses such a
/// bearer whatever credential it presents.
pub fn is_retired(c: &Connection, label: &str) -> UaResult<bool> {
    Ok(load(c, label.trim())?.is_some_and(|r| r.state == "retired"))
}

// --- arguments ------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StateArgs {
    /// Agent label.
    pub agent: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatesArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeArgs {
    /// Agent label.
    pub agent: String,
    /// Why (required to pause or terminate), at most 500 characters.
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetireArgs {
    /// Agent label.
    pub agent: String,
    /// Why (required), at most 500 characters.
    pub reason: Option<String>,
    /// Owner of record: an identity label, at most 120 characters.
    pub owner: Option<String>,
    /// Hub recovery: retire the agent of whichever organization holds the
    /// label, in that organization. The default organization's lifecycle
    /// operators only.
    pub any_org: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForgetArgs {
    /// Agent label of a retired agent.
    pub agent: String,
    /// Why (required), at most 500 characters.
    pub reason: Option<String>,
    /// Hub recovery: forget the agent of whichever organization holds the
    /// label, in that organization. The default organization's lifecycle
    /// operators only.
    pub any_org: Option<bool>,
}

// --- reads ----------------------------------------------------------------------

/// `coordination_manage(action="agent_state")`. Another organization's
/// agent reads as one with no lifecycle record, exactly as an unknown label.
pub(crate) async fn agent_state(ctx: ToolCtx, a: StateArgs) -> UaResult<Value> {
    let label = validate_label(Some(&a.agent), "agent")?;
    let org = ctx.caller.org_id.clone();
    ctx.hub.db().read_async(move |c| Ok(state_json(&label, load_in(c, &org, &label)?.as_ref()))).await
}

/// `coordination_manage(action="agent_states")`: the caller's organization's
/// agents and lifecycle rows only.
pub(crate) async fn agent_states(ctx: ToolCtx, _a: StatesArgs) -> UaResult<Value> {
    let operators = ctx.hub.cfg().lifecycle_operators().to_vec();
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {COLUMNS} FROM agent_lifecycle WHERE org_id = ?1 ORDER BY agent"
            ))?;
            let changed: Vec<Row> = stmt.query_map([&org], row_from)?.collect::<Result<_, _>>()?;
            let mut labels: Vec<String> = c
                .prepare("SELECT label FROM agents WHERE org_id = ?1")?
                .query_map([&org], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            labels.extend(changed.iter().map(|r| r.agent.clone()));
            labels.sort_by_key(|l| l.to_ascii_lowercase());
            labels.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
            let registered: Vec<Value> = labels
                .iter()
                .map(|l| state_json(l, changed.iter().find(|r| r.agent.eq_ignore_ascii_case(l))))
                .collect();
            Ok(json!({
                "agents": changed.iter().map(|r| state_json(&r.agent, Some(r))).collect::<Vec<_>>(),
                "registered": registered,
                "operators": operators,
            }))
        })
        .await
}

// --- the transition -------------------------------------------------------------

fn authorize(who: &str, maintainer: bool, label: &str, verb: Verb, current: Option<&Row>) -> UaResult<()> {
    if verb.operator_only() && !maintainer {
        return Err(UaError::denied(
            "not_lifecycle_operator",
            format!(
                "{who:?} may not {} {label:?}: retirement is a lifecycle operator action (lifecycle_operators), \
                 for an agent's own label too",
                verb.as_str()
            ),
        ));
    }
    if maintainer {
        return Ok(());
    }
    if !who.eq_ignore_ascii_case(label) {
        return Err(UaError::denied(
            "not_own_agent",
            format!(
                "{who:?} may not {} {label:?}: changing another agent's lifecycle is a lifecycle operator action",
                verb.as_str()
            ),
        ));
    }
    // An operator's stop is lifted by an operator only, whatever the agent
    // did to itself since (a self-terminate does not make the stop its own).
    if verb == Verb::Resume
        && let Some(r) = current
        && r.state != "active"
    {
        let by =
            r.imposed_by.as_deref().or((!r.actor.eq_ignore_ascii_case(label)).then_some(r.actor.as_str()));
        if let Some(by) = by {
            return Err(UaError::denied(
                "resume_needs_operator",
                format!("{label:?} was stopped by {by:?}; only a lifecycle operator may resume it"),
            ));
        }
    }
    Ok(())
}

fn check_transition(label: &str, verb: Verb, state: &str) -> UaResult<()> {
    if state == "retired" && matches!(verb, Verb::Pause | Verb::Resume | Verb::Terminate) {
        return Err(UaError::conflict_code(
            "agent_retired",
            format!(
                "{label:?} is retired; {} cannot change a retired agent. An operator must unretire it \
                 explicitly (coordination_manage agent_unretire)",
                verb.as_str()
            ),
        ));
    }
    if verb == Verb::Unretire && !matches!(state, "retired" | "active") {
        return Err(UaError::invalid(format!("{label:?} is not retired (it is {state}); use agent_resume")));
    }
    if state == "terminated" && verb == Verb::Pause {
        return Err(UaError::invalid(format!("{label:?} is terminated; resume it before pausing")));
    }
    Ok(())
}

/// `agent`'s `doing` claims in organization `org` (the agent's), with that
/// organization beside each. A task of another organization whose claimant
/// text matches the label is never the agent's: the claim gate reads the
/// claimant's own organization, so it is left alone.
fn doing_claims(c: &Connection, org: &str, agent: &str) -> UaResult<Vec<(i64, String)>> {
    let mut stmt = c.prepare(
        "SELECT id, org_id FROM tasks WHERE org_id = ?2 AND claimed_by = ?1 COLLATE NOCASE \
         AND status = 'doing' ORDER BY id",
    )?;
    let ids = stmt.query_map([agent, org], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    Ok(ids)
}

/// Revoke `agent`'s managed tokens (in its organization `org`), OAuth
/// sign-ins and session credentials. Returns what was revoked.
fn revoke_credentials(
    tx: &mut WriteTx<'_>,
    org: &str,
    agent: &str,
    who: &str,
    at: &str,
    why: &str,
) -> UaResult<Value> {
    let token_ids: Vec<i64> = tx
        .prepare(
            "SELECT id FROM agent_tokens WHERE org_id = ?2 AND agent_label = ?1 COLLATE NOCASE \
             AND status = 'active' ORDER BY id",
        )?
        .query_map([agent, org], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    tx.execute(
        "UPDATE agent_tokens SET status = 'revoked', revoked_at = ?2 \
         WHERE org_id = ?3 AND agent_label = ?1 COLLATE NOCASE AND status = 'active'",
        params![agent, at, org],
    )?;
    let families: Vec<String> = tx
        .prepare(
            "SELECT family_id FROM oauth_grants WHERE subject = ?1 COLLATE NOCASE AND revoked_at IS NULL",
        )?
        .query_map([agent], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut oauth_tokens = 0;
    for f in &families {
        oauth_tokens += tokens::revoke_family(tx, f, why)?;
    }
    let session_credentials = crate::families::node_queue::revoke_for_agent(tx, org, agent, why, who)?;
    if !token_ids.is_empty() {
        agents::emit(
            tx,
            org,
            "agent.token.revoked",
            json!({
                "agent": ledger_text(org, agent), "token_ids": token_ids, "reason": why,
                "revoked_at": at,
            }),
            who,
            None,
        )?;
    }
    if !families.is_empty() {
        agents::emit(
            tx,
            org,
            "agent.oauth.sessions_revoked",
            json!({
                "identity": ledger_text(org, agent),
                "revoked_sessions": families.len(),
                "revoked_tokens": oauth_tokens,
                "reason": why,
            }),
            who,
            None,
        )?;
    }
    Ok(
        json!({ "agent_tokens": token_ids, "oauth_sessions": families, "session_credentials": session_credentials }),
    )
}

/// Return `agent`'s `doing` claims to `open` (terminate).
fn release_claims(
    tx: &mut WriteTx<'_>,
    org: &str,
    agent: &str,
    who: &str,
    reason: &str,
) -> UaResult<Vec<Value>> {
    let mut out = Vec::new();
    for (id, org) in doing_claims(tx, org, agent)? {
        let prev: Option<String> = tx.query_row(
            "SELECT updated_at FROM tasks WHERE org_id = ?1 AND id = ?2",
            params![org, id],
            |r| r.get(0),
        )?;
        let n = tx.execute(
            "UPDATE tasks SET status = 'open', claimed_by = NULL, claimed_at = NULL, lock_expires_at = NULL, \
             next_owner = NULL, ownership_generation = ownership_generation + 1, updated_at = ?3 \
             WHERE id = ?1 AND org_id = ?4 AND claimed_by = ?2 COLLATE NOCASE AND status = 'doing'",
            params![id, agent, crate::families::tasks::next_revision(prev.as_deref()), org],
        )?;
        if n == 1 {
            use crate::families::tasks::{emit, ledger_text};
            emit(
                tx,
                &org,
                "agent.task.claim_released",
                json!({
                    "task_id": id,
                    "claimant": ledger_text(&org, agent),
                    "expired": false,
                    "status_after": "open",
                    "reason": ledger_text(&org, &format!("agent terminated: {reason}")),
                    "authority": "agent_lifecycle",
                }),
                who,
            )?;
        }
        out.push(json!({
            "path": "claim",
            "ref": format!("task:{id}"),
            "control": if n == 1 { "released" } else { "unchanged" },
            "detail": if n == 1 { "returned to open" } else { "task moved on before release" },
        }));
    }
    Ok(out)
}

/// Cancel `agent`'s node items in organization `org` (the agent's): claimed
/// ones always (the node stops them on its next heartbeat), queued ones too
/// when `queued` is set. Another organization's item for the same label
/// text is never the agent's and is left alone.
///
/// The stop list (the answer and `lifecycle.stops_requested`) keeps the
/// item and run ids of a non-default organization on purpose: they are
/// hub-generated, the same ids `node_queue::ledger_payload` keeps for that
/// organization's events, and the operator needs them to follow the stop.
/// Nothing else of such a row is copied: the details are fixed texts and
/// reason codes from the cancel path, never its node name, prompt or reason.
fn stop_node_items(
    tx: &mut WriteTx<'_>,
    org: &str,
    agent: &str,
    who: &str,
    queued: bool,
) -> UaResult<Vec<Value>> {
    let filter = if queued {
        "org_id = ?2 AND agent = ?1 COLLATE NOCASE AND status IN ('queued','claimed') AND run_id IS NULL \
         ORDER BY created_at"
    } else {
        "org_id = ?2 AND agent = ?1 COLLATE NOCASE AND status = 'claimed' AND run_id IS NULL ORDER BY created_at"
    };
    let mut out = Vec::new();
    for item in node_queue::items_where(tx, filter, [agent, org])? {
        let res = node_queue::cancel_item(tx, &item.org_id, &item.id, who, "agent lifecycle stop")?;
        out.push(json!({
            "path": "node",
            "ref": item.id,
            "task_id": item.task_id,
            "control": if res["changed"] == json!(true) { "requested" } else { "unchanged" },
            "detail": if item.status == "queued" { "will not start" } else { "relayed on the node's next heartbeat" },
        }));
    }
    Ok(out)
}

/// `agent`'s live runs in organization `org` (the agent's), each with that
/// organization, like the task claims above.
fn live_runs(c: &Connection, org: &str, agent: &str) -> UaResult<Vec<(String, i64, String)>> {
    let mut stmt = c.prepare(
        "SELECT run_id, task_id, org_id FROM dispatch_runs WHERE org_id = ?2 AND agent_label = ?1 COLLATE NOCASE \
         AND state IN ('claimed','launched','running') AND termination_outcome IS NULL ORDER BY created_at",
    )?;
    let rows =
        stmt.query_map([agent, org], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Cancel each run `(run_id, task_id, org)` through the `dispatch_cancel`
/// path, in the run's organization, reporting what happened.
pub(crate) async fn stop_runs(
    hub: &Hub,
    who: &str,
    runs: Vec<(String, i64, String)>,
    reason: &str,
) -> Vec<Value> {
    let mut out = Vec::new();
    for (run_id, task_id, org) in runs {
        let res = dispatch::cancel_run(hub, org, who.to_string(), run_id.clone(), reason.to_string()).await;
        let (control, detail) = match res {
            Ok(v) if v["ok"] == json!(false) => ("unchanged", v["reason"].as_str().unwrap_or("").to_string()),
            Ok(v) if v["cessation"] == json!("confirmed") => {
                ("confirmed", "the run's process was stopped".into())
            }
            Ok(v) => ("requested", format!("termination {}", v["termination"].as_str().unwrap_or("unknown"))),
            Err(e) => ("failed", e.to_string()),
        };
        out.push(json!({ "path": "dispatch", "ref": run_id, "task_id": task_id, "control": control, "detail": detail }));
    }
    out
}

struct Changed {
    state: Value,
    changed: bool,
    stops: Vec<Value>,
    runs: Vec<(String, i64, String)>,
    revoked: Option<Value>,
    /// The organization the change was made in (the agent's).
    org: String,
}

/// Whether an action asked for hub recovery (`any_org`): the caller must be a
/// lifecycle operator of the default organization, the hub-level authority
/// (checked over [`ua_core::DEFAULT_ORG`], which no other organization's
/// caller holds).
fn hub_recovery(ctx: &ToolCtx, any_org: Option<bool>, verb: Verb) -> UaResult<bool> {
    if any_org != Some(true) {
        return Ok(false);
    }
    if !Authz::new(ctx.hub.cfg()).holds(&ctx.caller, &[Authority::LifecycleOperator], ua_core::DEFAULT_ORG) {
        return Err(UaError::denied(
            "not_lifecycle_operator",
            format!(
                "hub recovery (agent_{} with any_org) is for the default organization's lifecycle operators only",
                verb.as_str()
            ),
        ));
    }
    Ok(true)
}

/// The organization a change works in: the caller's own, or under hub
/// recovery the one holding `label` (the caller's own when none does, so an
/// unknown label answers as it always has). Outside hub recovery a label
/// another organization holds is refused as taken: its agent is not the
/// caller's to change, and the label namespace already shows that it is held.
fn action_org(
    c: &Connection,
    reserved: &agents::Reserved,
    caller_org: &str,
    label: &str,
    hub: bool,
) -> UaResult<String> {
    match agents::label_org(c, reserved, label)? {
        Some(held) if hub => Ok(held),
        Some(held) if held != caller_org => Err(agents::label_taken(label)),
        _ => Ok(caller_org.to_string()),
    }
}

/// The lifecycle event payload of a change in organization `org`: another
/// organization's carries no label, reason, actor or owner.
fn redact_stops(org: &str, stops: &[Value]) -> Value {
    if org == ua_core::DEFAULT_ORG {
        return json!(stops);
    }
    json!(stops
        .iter()
        .map(|s| json!({ "path": s["path"], "ref": s["ref"], "task_id": s["task_id"], "control": s["control"] }))
        .collect::<Vec<_>>())
}

async fn change(
    ctx: ToolCtx,
    agent: &str,
    verb: Verb,
    reason: Option<&str>,
    owner: Option<&str>,
    any_org: Option<bool>,
) -> UaResult<Value> {
    let label = validate_label(Some(agent), "agent")?;
    let reason = clean_reason(
        reason,
        verb.reason_required().then_some(match verb {
            Verb::Pause => "pause an agent",
            Verb::Terminate => "terminate an agent",
            Verb::Forget => "forget an agent",
            _ => "retire an agent",
        }),
    )?;
    let owner = match owner.map(str::trim).filter(|o| !o.is_empty()) {
        None => None,
        Some(_) if verb != Verb::Retire => return Err(UaError::invalid("owner is recorded on retire only")),
        Some(o) if o.chars().count() > MAX_OWNER => {
            return Err(UaError::invalid(format!("owner must be at most {MAX_OWNER} characters")));
        }
        Some(o) => Some(validate_label(Some(o), "owner")?),
    };
    let who = verified_actor(&ctx.caller, "changing an agent's lifecycle")?;
    let hub = hub_recovery(&ctx, any_org, verb)?;
    let caller_org = ctx.caller.org_id.clone();
    let maintainer = Authz::new(ctx.hub.cfg()).holds(
        &ctx.caller,
        &[Authority::Operator, Authority::LifecycleOperator],
        &caller_org,
    );
    let (l2, w2, r2, co) = (label.clone(), who.clone(), reason.clone(), caller_org.clone());
    let reserved = agents::Reserved::of(ctx.hub.cfg());
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let (label, who, reason) = (l2, w2, r2);
            let org = action_org(tx, &reserved, &co, &label, hub)?;
            agents::require_org(tx, &org)?;
            let current = load_in(tx, &org, &label)?;
            let state = current.as_ref().map_or("active", |r| r.state.as_str()).to_string();
            authorize(&who, maintainer, &label, verb, current.as_ref())?;
            if verb == Verb::Forget {
                return forget(tx, &reserved, &org, &label, &who, &reason, current.as_ref());
            }
            check_transition(&label, verb, &state)?;
            let target = verb.target();
            if state == target {
                return Ok(Changed {
                    state: state_json(&label, current.as_ref()),
                    changed: false,
                    stops: Vec::new(),
                    runs: Vec::new(),
                    revoked: None,
                    org,
                });
            }
            let at = now();
            let mut revoked = None;
            if verb == Verb::Retire {
                let doing = doing_claims(tx, &org, &label)?;
                if !doing.is_empty() {
                    let shown: Vec<String> = doing.iter().take(20).map(|(t, _)| format!("#{t}")).collect();
                    return Err(UaError::conflict_code(
                        "agent_has_doing_claims",
                        format!(
                            "cannot retire {label:?}: it holds {} doing claim(s) ({}). Release or cancel them \
                             first (task_update, coordination_manage task_claim_release, or agent_terminate). \
                             Nothing was changed.",
                            doing.len(),
                            shown.join(", ")
                        ),
                    ));
                }
                revoked = Some(revoke_credentials(tx, &org, &label, &who, &at, "agent_retired")?);
            }
            let stored = current.as_ref().map_or(label.clone(), |r| r.agent.clone());
            // Who imposed the stop in force: an operator's stop is recorded
            // and survives the agent's own transitions; a return to active
            // (which only an operator may make over an operator's stop)
            // clears it.
            let imposed_by = if target == "active" {
                None
            } else if (maintainer || hub) && !who.eq_ignore_ascii_case(&label) {
                Some(who.clone())
            } else {
                current.as_ref().and_then(|r| r.imposed_by.clone())
            };
            let n = tx.execute(
                "INSERT INTO agent_lifecycle (org_id, agent, state, previous, action, reason, actor, imposed_by, \
                 owner, since) VALUES (?10, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT(agent) DO UPDATE SET state = excluded.state, previous = excluded.previous, \
                 action = excluded.action, reason = excluded.reason, actor = excluded.actor, \
                 imposed_by = excluded.imposed_by, \
                 owner = COALESCE(excluded.owner, agent_lifecycle.owner), since = excluded.since \
                 WHERE agent_lifecycle.org_id = excluded.org_id",
                params![
                    stored,
                    target,
                    state,
                    verb.as_str(),
                    (!reason.is_empty()).then_some(&reason),
                    who,
                    imposed_by,
                    owner,
                    at,
                    org
                ],
            )?;
            // Another organization's lifecycle row for this label (one made
            // before the label was registered there) is never changed.
            if n == 0 {
                return Err(agents::label_taken(&label));
            }
            let mut payload = json!({
                "kind": "lifecycle.changed",
                "agent": ledger_text(&org, &stored),
                "state": target,
                "previous": state,
                "action": verb.as_str(),
                "reason": ledger_label(&org, (!reason.is_empty()).then_some(reason.as_str())),
                "actor": ledger_text(&org, &who),
                "imposed_by": ledger_label(&org, imposed_by.as_deref()),
                "at": at,
            });
            if verb == Verb::Retire {
                payload["owner"] = ledger_label(&org, owner.as_deref());
                payload["revoked"] = revoked.clone().unwrap_or(Value::Null);
            }
            agents::emit(tx, &org, CHANNEL, payload, &who, None)?;

            // Stops on what the hub can reach. Runs are cancelled after commit.
            let mut stops = Vec::new();
            let mut runs = Vec::new();
            if target != "active" {
                runs = live_runs(tx, &org, &stored)?;
                stops.extend(stop_node_items(tx, &org, &stored, &who, verb != Verb::Pause)?);
                let run_tasks: Vec<i64> = runs.iter().map(|(_, t, _)| *t).collect();
                if verb == Verb::Terminate {
                    stops.extend(release_claims(tx, &org, &stored, &who, &reason)?);
                } else {
                    for (id, _) in doing_claims(tx, &org, &stored)? {
                        if !run_tasks.contains(&id) {
                            stops.push(json!({
                                "path": "self-pickup",
                                "ref": format!("task:{id}"),
                                "control": "unsupported",
                                "detail": "no hub-controllable process; new claims and renewals are refused",
                            }));
                        }
                    }
                }
            }
            let row = load_in(tx, &org, &stored)?;
            Ok(Changed { state: state_json(&stored, row.as_ref()), changed: true, stops, runs, revoked, org })
        })
        .await?;

    let mut stops = out.stops;
    if !out.runs.is_empty() {
        let why = format!("agent {}: {reason}", verb.target());
        stops.extend(stop_runs(&ctx.hub, &who, out.runs, &why).await);
    }
    if out.changed && !stops.is_empty() {
        let org = out.org.clone();
        let (by, payload) = (
            who.clone(),
            json!({
                "kind": "lifecycle.stops_requested",
                "agent": ledger_text(&org, &label),
                "actor": ledger_text(&org, &who),
                "stops": redact_stops(&org, &stops),
            }),
        );
        ctx.hub.db().write_async(move |tx| agents::emit(tx, &org, CHANNEL, payload, &by, None)).await?;
    }
    // Hub recovery of another organization's agent answers without the
    // agent's own fields (its reasons, actors, owner, stops, credentials).
    if out.org != caller_org {
        let mut answer = json!({
            "agent": label,
            "org_id": out.org,
            "changed": out.changed,
            "hub_recovery": true,
        });
        if verb == Verb::Forget {
            answer["forgotten"] = json!(out.changed);
        } else {
            answer["retired"] = json!(true);
        }
        return Ok(answer);
    }
    let mut result = out.state;
    result["changed"] = json!(out.changed);
    result["stops"] = json!(stops);
    if let Some(r) = out.revoked {
        result["revoked"] = r;
    }
    if hub {
        result["hub_recovery"] = json!(true);
    }
    Ok(result)
}

/// Forget a retired agent of organization `org`: revoke every credential
/// issued for it since the retire, then delete its agent row, its lifecycle
/// row and its profile bindings there, so its label is free again. Its
/// sessions, handoff notes, wake rows and revoked tokens stay in `org` as
/// history. Refused unless the agent is retired (a retire already refused
/// it while it held doing claims), for a label hub configuration names (see
/// the module docs), and when two agent rows spell the label in different
/// letter cases (`agents.label` is case-sensitive; forget never deletes a
/// row it was not asked about).
#[allow(clippy::too_many_arguments)]
fn forget(
    tx: &mut WriteTx<'_>,
    reserved: &agents::Reserved,
    org: &str,
    label: &str,
    who: &str,
    reason: &str,
    current: Option<&Row>,
) -> UaResult<Changed> {
    if reserved.contains(label) {
        return Err(UaError::conflict_code(
            "agent_label_configured",
            format!(
                "{label:?} is named in hub configuration (a static token, [profiles], oauth_identities, \
                 human_identities, lifecycle_operators, Slack identities or a policy role); its retired \
                 record is what keeps a configured credential refused. Remove it from configuration, then \
                 forget it. Nothing was changed"
            ),
        ));
    }
    if current.is_none_or(|r| r.state != "retired") {
        return Err(UaError::conflict_code(
            "agent_not_retired",
            format!(
                "{label:?} is not retired; retire it (coordination_manage agent_retire) before forgetting it"
            ),
        ));
    }
    let stored = current.map_or(label.to_string(), |r| r.agent.clone());
    let spellings: Vec<String> = tx
        .prepare("SELECT label FROM agents WHERE org_id = ?1 AND label = ?2 COLLATE NOCASE")?
        .query_map(params![org, stored], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if spellings.len() > 1 {
        return Err(UaError::conflict_code(
            "agent_label_ambiguous",
            format!(
                "{} agent rows spell {stored:?} in different letter cases; forget deletes one exact agent. \
                 Nothing was changed",
                spellings.len()
            ),
        ));
    }
    let at = now();
    let revoked = revoke_credentials(tx, org, &stored, who, &at, "agent_forgotten")?;
    let agents_deleted = match spellings.first() {
        Some(exact) => {
            tx.execute("DELETE FROM agents WHERE org_id = ?1 AND label = ?2", params![org, exact])?
        }
        None => 0,
    };
    tx.execute("DELETE FROM agent_lifecycle WHERE org_id = ?1 AND agent = ?2", params![org, stored])?;
    let profiles = tx.execute(
        "DELETE FROM session_profiles WHERE org_id = ?1 AND identity = ?2 COLLATE NOCASE",
        params![org, stored],
    )?;
    agents::emit(
        tx,
        org,
        CHANNEL,
        json!({
            "kind": "lifecycle.forgotten",
            "agent": ledger_text(org, &stored),
            "reason": ledger_text(org, reason),
            "actor": ledger_text(org, who),
            "agent_rows": agents_deleted,
            "profile_bindings": profiles,
            "at": at,
        }),
        who,
        None,
    )?;
    Ok(Changed {
        state: json!({ "agent": stored, "state": "forgotten", "forgotten": true }),
        changed: true,
        stops: Vec::new(),
        runs: Vec::new(),
        revoked: Some(revoked),
        org: org.to_string(),
    })
}

/// `coordination_manage(action="agent_pause")`.
pub(crate) async fn agent_pause(ctx: ToolCtx, a: ChangeArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Pause, a.reason.as_deref(), None, None).await
}

/// `coordination_manage(action="agent_resume")`.
pub(crate) async fn agent_resume(ctx: ToolCtx, a: ChangeArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Resume, a.reason.as_deref(), None, None).await
}

/// `coordination_manage(action="agent_terminate")`.
pub(crate) async fn agent_terminate(ctx: ToolCtx, a: ChangeArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Terminate, a.reason.as_deref(), None, None).await
}

/// `coordination_manage(action="agent_retire")`.
pub(crate) async fn agent_retire(ctx: ToolCtx, a: RetireArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Retire, a.reason.as_deref(), a.owner.as_deref(), a.any_org).await
}

/// `coordination_manage(action="agent_unretire")`.
pub(crate) async fn agent_unretire(ctx: ToolCtx, a: ChangeArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Unretire, a.reason.as_deref(), None, None).await
}

/// `coordination_manage(action="agent_forget")`.
pub(crate) async fn agent_forget(ctx: ToolCtx, a: ForgetArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Forget, a.reason.as_deref(), None, a.any_org).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_refuse_what_the_state_does_not_allow() {
        assert!(check_transition("a", Verb::Resume, "retired").is_err());
        assert!(check_transition("a", Verb::Pause, "terminated").is_err());
        assert!(check_transition("a", Verb::Unretire, "paused").is_err());
        assert!(check_transition("a", Verb::Unretire, "retired").is_ok());
        assert!(check_transition("a", Verb::Resume, "paused").is_ok());
        assert!(check_transition("a", Verb::Retire, "paused").is_ok());
    }

    #[test]
    fn an_agent_resumes_only_from_its_own_stop() {
        let row = |actor: &str, imposed_by: Option<&str>| Row {
            agent: "a".into(),
            state: "terminated".into(),
            previous: Some("paused".into()),
            reason: None,
            actor: actor.into(),
            imposed_by: imposed_by.map(str::to_string),
            owner: None,
            since: String::new(),
        };
        assert!(authorize("a", false, "a", Verb::Resume, Some(&row("a", None))).is_ok());
        assert!(authorize("a", false, "a", Verb::Resume, Some(&row("operator", None))).is_err());
        // The agent's own last transition does not make an operator's stop its own.
        assert!(authorize("a", false, "a", Verb::Resume, Some(&row("a", Some("operator")))).is_err());
        assert!(authorize("op", true, "a", Verb::Resume, Some(&row("a", Some("operator")))).is_ok());
        assert!(authorize("a", false, "b", Verb::Pause, None).is_err());
        assert!(authorize("a", false, "a", Verb::Retire, None).is_err());
        assert!(authorize("op", true, "a", Verb::Retire, None).is_ok());
    }
}
