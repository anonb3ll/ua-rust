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

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, WriteTx, ledger};

use super::{clean_reason, now, verified_actor};
use crate::families::agents::validate_label;
use crate::families::dispatch;
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
}

impl Verb {
    fn as_str(self) -> &'static str {
        match self {
            Verb::Pause => "pause",
            Verb::Resume => "resume",
            Verb::Terminate => "terminate",
            Verb::Retire => "retire",
            Verb::Unretire => "unretire",
        }
    }

    fn target(self) -> &'static str {
        match self {
            Verb::Pause => "paused",
            Verb::Resume | Verb::Unretire => "active",
            Verb::Terminate => "terminated",
            Verb::Retire => "retired",
        }
    }

    fn operator_only(self) -> bool {
        matches!(self, Verb::Retire | Verb::Unretire)
    }

    fn reason_required(self) -> bool {
        matches!(self, Verb::Pause | Verb::Terminate | Verb::Retire)
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

fn load(c: &Connection, agent: &str) -> UaResult<Option<Row>> {
    Ok(c.query_row(&format!("SELECT {COLUMNS} FROM agent_lifecycle WHERE agent = ?1"), [agent], row_from)
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
}

// --- reads ----------------------------------------------------------------------

/// `coordination_manage(action="agent_state")`.
pub(crate) async fn agent_state(ctx: ToolCtx, a: StateArgs) -> UaResult<Value> {
    let label = validate_label(Some(&a.agent), "agent")?;
    ctx.hub.db().read_async(move |c| Ok(state_json(&label, load(c, &label)?.as_ref()))).await
}

/// `coordination_manage(action="agent_states")`.
pub(crate) async fn agent_states(ctx: ToolCtx, _a: StatesArgs) -> UaResult<Value> {
    let operators = ctx.hub.cfg().lifecycle_operators().to_vec();
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(&format!("SELECT {COLUMNS} FROM agent_lifecycle ORDER BY agent"))?;
            let changed: Vec<Row> = stmt.query_map([], row_from)?.collect::<Result<_, _>>()?;
            let mut labels: Vec<String> = c
                .prepare("SELECT label FROM agents")?
                .query_map([], |r| r.get(0))?
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

/// `agent`'s `doing` claims with each task's organization. An agent label
/// is one hub-wide namespace and an agent belongs to one organization, so
/// this reads the claims of that one agent wherever its tasks are; each
/// release acts in its task's own organization.
fn doing_claims(c: &Connection, agent: &str) -> UaResult<Vec<(i64, String)>> {
    let mut stmt = c.prepare(
        "SELECT id, org_id FROM tasks WHERE claimed_by = ?1 COLLATE NOCASE AND status = 'doing' ORDER BY id",
    )?;
    let ids = stmt.query_map([agent], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    Ok(ids)
}

/// Revoke `agent`'s managed tokens and OAuth sign-ins. Returns what was revoked.
fn revoke_credentials(tx: &mut WriteTx<'_>, agent: &str, who: &str, at: &str) -> UaResult<Value> {
    let token_ids: Vec<i64> = tx
        .prepare("SELECT id FROM agent_tokens WHERE agent_label = ?1 COLLATE NOCASE AND status = 'active' ORDER BY id")?
        .query_map([agent], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    tx.execute(
        "UPDATE agent_tokens SET status = 'revoked', revoked_at = ?2 \
         WHERE agent_label = ?1 COLLATE NOCASE AND status = 'active'",
        params![agent, at],
    )?;
    let families: Vec<String> = tx
        .prepare(
            "SELECT family_id FROM oauth_grants WHERE subject = ?1 COLLATE NOCASE AND revoked_at IS NULL",
        )?
        .query_map([agent], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut oauth_tokens = 0;
    for f in &families {
        oauth_tokens += tokens::revoke_family(tx, f, "agent_retired")?;
    }
    let session_credentials = crate::families::node_queue::revoke_for_agent(tx, agent, "agent_retired", who)?;
    if !token_ids.is_empty() {
        ledger::append(
            tx,
            EventInput::new(ua_core::DEFAULT_ORG,
                "agent.token.revoked",
                json!({ "agent": agent, "token_ids": token_ids, "reason": "agent_retired", "revoked_at": at }),
            )
            .by(who.to_string()),
        )?;
    }
    if !families.is_empty() {
        ledger::append(
            tx,
            EventInput::new(
                ua_core::DEFAULT_ORG,
                "agent.oauth.sessions_revoked",
                json!({
                    "identity": agent,
                    "revoked_sessions": families.len(),
                    "revoked_tokens": oauth_tokens,
                    "reason": "agent_retired",
                }),
            )
            .by(who.to_string()),
        )?;
    }
    Ok(
        json!({ "agent_tokens": token_ids, "oauth_sessions": families, "session_credentials": session_credentials }),
    )
}

/// Return `agent`'s `doing` claims to `open` (terminate).
fn release_claims(tx: &mut WriteTx<'_>, agent: &str, who: &str, reason: &str) -> UaResult<Vec<Value>> {
    let mut out = Vec::new();
    for (id, org) in doing_claims(tx, agent)? {
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

/// Cancel `agent`'s node items: claimed ones always (the node stops them on
/// its next heartbeat), queued ones too when `queued` is set. An agent-wide
/// lifecycle action: each item is cancelled in its own organization.
fn stop_node_items(tx: &mut WriteTx<'_>, agent: &str, who: &str, queued: bool) -> UaResult<Vec<Value>> {
    let filter = if queued {
        "agent = ?1 COLLATE NOCASE AND status IN ('queued','claimed') AND run_id IS NULL ORDER BY created_at"
    } else {
        "agent = ?1 COLLATE NOCASE AND status = 'claimed' AND run_id IS NULL ORDER BY created_at"
    };
    let mut out = Vec::new();
    for item in node_queue::items_where(tx, filter, [agent])? {
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

/// `agent`'s live runs in every organization, each with its organization
/// (an agent-wide lifecycle action, like the task claims above).
fn live_runs(c: &Connection, agent: &str) -> UaResult<Vec<(String, i64, String)>> {
    let mut stmt = c.prepare(
        "SELECT run_id, task_id, org_id FROM dispatch_runs WHERE agent_label = ?1 COLLATE NOCASE \
         AND state IN ('claimed','launched','running') AND termination_outcome IS NULL ORDER BY created_at",
    )?;
    let rows =
        stmt.query_map([agent], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
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
}

async fn change(
    ctx: ToolCtx,
    agent: &str,
    verb: Verb,
    reason: Option<&str>,
    owner: Option<&str>,
) -> UaResult<Value> {
    let label = validate_label(Some(agent), "agent")?;
    let reason = clean_reason(
        reason,
        verb.reason_required().then_some(match verb {
            Verb::Pause => "pause an agent",
            Verb::Terminate => "terminate an agent",
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
    let maintainer = Authz::new(ctx.hub.cfg()).holds(
        &ctx.caller,
        &[Authority::Operator, Authority::LifecycleOperator],
        ua_core::DEFAULT_ORG,
    );
    let (l2, w2, r2) = (label.clone(), who.clone(), reason.clone());
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let (label, who, reason) = (l2, w2, r2);
            let current = load(tx, &label)?;
            let state = current.as_ref().map_or("active", |r| r.state.as_str()).to_string();
            authorize(&who, maintainer, &label, verb, current.as_ref())?;
            check_transition(&label, verb, &state)?;
            let target = verb.target();
            if state == target {
                return Ok(Changed {
                    state: state_json(&label, current.as_ref()),
                    changed: false,
                    stops: Vec::new(),
                    runs: Vec::new(),
                    revoked: None,
                });
            }
            let at = now();
            let mut revoked = None;
            if verb == Verb::Retire {
                let doing = doing_claims(tx, &label)?;
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
                revoked = Some(revoke_credentials(tx, &label, &who, &at)?);
            }
            let stored = current.as_ref().map_or(label.clone(), |r| r.agent.clone());
            // Who imposed the stop in force: an operator's stop is recorded
            // and survives the agent's own transitions; a return to active
            // (which only an operator may make over an operator's stop)
            // clears it.
            let imposed_by = if target == "active" {
                None
            } else if maintainer && !who.eq_ignore_ascii_case(&label) {
                Some(who.clone())
            } else {
                current.as_ref().and_then(|r| r.imposed_by.clone())
            };
            tx.execute(
                "INSERT INTO agent_lifecycle (agent, state, previous, action, reason, actor, imposed_by, owner, since) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT(agent) DO UPDATE SET state = excluded.state, previous = excluded.previous, \
                 action = excluded.action, reason = excluded.reason, actor = excluded.actor, \
                 imposed_by = excluded.imposed_by, \
                 owner = COALESCE(excluded.owner, agent_lifecycle.owner), since = excluded.since",
                params![
                    stored,
                    target,
                    state,
                    verb.as_str(),
                    (!reason.is_empty()).then_some(&reason),
                    who,
                    imposed_by,
                    owner,
                    at
                ],
            )?;
            let mut payload = json!({
                "kind": "lifecycle.changed",
                "agent": stored,
                "state": target,
                "previous": state,
                "action": verb.as_str(),
                "reason": (!reason.is_empty()).then_some(&reason),
                "actor": who,
                "imposed_by": imposed_by,
                "at": at,
            });
            if verb == Verb::Retire {
                payload["owner"] = json!(owner);
                payload["revoked"] = revoked.clone().unwrap_or(Value::Null);
            }
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, CHANNEL, payload).by(who.clone()))?;

            // Stops on what the hub can reach. Runs are cancelled after commit.
            let mut stops = Vec::new();
            let mut runs = Vec::new();
            if target != "active" {
                runs = live_runs(tx, &stored)?;
                stops.extend(stop_node_items(tx, &stored, &who, verb != Verb::Pause)?);
                let run_tasks: Vec<i64> = runs.iter().map(|(_, t, _)| *t).collect();
                if verb == Verb::Terminate {
                    stops.extend(release_claims(tx, &stored, &who, &reason)?);
                } else {
                    for (id, _) in doing_claims(tx, &stored)? {
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
            let row = load(tx, &stored)?;
            Ok(Changed { state: state_json(&stored, row.as_ref()), changed: true, stops, runs, revoked })
        })
        .await?;

    let mut stops = out.stops;
    if !out.runs.is_empty() {
        let why = format!("agent {}: {reason}", verb.target());
        stops.extend(stop_runs(&ctx.hub, &who, out.runs, &why).await);
    }
    if out.changed && !stops.is_empty() {
        let (by, payload) = (
            who.clone(),
            json!({ "kind": "lifecycle.stops_requested", "agent": label, "actor": who, "stops": stops }),
        );
        ctx.hub
            .db()
            .write_async(move |tx| {
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, CHANNEL, payload).by(by))?;
                Ok(())
            })
            .await?;
    }
    let mut result = out.state;
    result["changed"] = json!(out.changed);
    result["stops"] = json!(stops);
    if let Some(r) = out.revoked {
        result["revoked"] = r;
    }
    Ok(result)
}

/// `coordination_manage(action="agent_pause")`.
pub(crate) async fn agent_pause(ctx: ToolCtx, a: ChangeArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Pause, a.reason.as_deref(), None).await
}

/// `coordination_manage(action="agent_resume")`.
pub(crate) async fn agent_resume(ctx: ToolCtx, a: ChangeArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Resume, a.reason.as_deref(), None).await
}

/// `coordination_manage(action="agent_terminate")`.
pub(crate) async fn agent_terminate(ctx: ToolCtx, a: ChangeArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Terminate, a.reason.as_deref(), None).await
}

/// `coordination_manage(action="agent_retire")`.
pub(crate) async fn agent_retire(ctx: ToolCtx, a: RetireArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Retire, a.reason.as_deref(), a.owner.as_deref()).await
}

/// `coordination_manage(action="agent_unretire")`.
pub(crate) async fn agent_unretire(ctx: ToolCtx, a: ChangeArgs) -> UaResult<Value> {
    change(ctx, &a.agent, Verb::Unretire, a.reason.as_deref(), None).await
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
