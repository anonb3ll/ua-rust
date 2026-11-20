//! Tool definitions, the registry and the governed call wrapper.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, UaError, UaResult};
use ua_store::{EventInput, ledger};

use crate::approvals::{self, GateOutcome};
use crate::hub::Hub;
use crate::policy::{self, Verdict};

/// What a tool receives besides its arguments.
#[derive(Clone)]
pub struct ToolCtx {
    pub hub: Hub,
    pub caller: Caller,
}

type BoxFut = Pin<Box<dyn Future<Output = UaResult<Value>> + Send>>;
type Handler = Arc<dyn Fn(ToolCtx, Value) -> BoxFut + Send + Sync>;

/// One registered tool.
#[derive(Clone)]
pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    pub family: &'static str,
    /// JSON Schema (2020-12) for the arguments object.
    pub input_schema: Value,
    /// True when the tool never changes state.
    pub read_only: bool,
    /// True when the tool always needs a one-time human approval, whatever
    /// the configuration says (merges, deletes, restarts).
    pub always_gated: bool,
    /// True when the handler evaluates the approval gate itself, on a payload
    /// bound to values it resolves (config, task, run), so the registry does
    /// not gate on the bare arguments.
    pub gates_in_handler: bool,
    /// When set, the approval gate binds this projection of the arguments
    /// instead of the arguments themselves, so a value that must never be
    /// stored (a secret) is not parked in the approvals table.
    pub gate_payload: Option<GatePayload>,
    handler: Handler,
}

/// Maps a call's arguments to the payload its approval binds.
pub type GatePayload = fn(&ua_core::Config, &Value) -> Value;

impl std::fmt::Debug for ToolDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolDef").field("name", &self.name).field("family", &self.family).finish()
    }
}

impl ToolDef {
    pub fn family(mut self, family: &'static str) -> Self {
        self.family = family;
        self
    }

    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    pub fn always_gated(mut self) -> Self {
        self.always_gated = true;
        self
    }

    /// The handler calls `approvals::gate` itself with a resolved payload.
    /// It can then refuse a call bound to fail before a human is asked.
    pub fn gates_in_handler(mut self) -> Self {
        self.gates_in_handler = true;
        self
    }

    /// Gate on `f(config, args)` rather than on the raw arguments.
    pub fn gate_payload(mut self, f: GatePayload) -> Self {
        self.gate_payload = Some(f);
        self
    }
}

/// Build a tool from a typed handler. `A` is the argument struct; derive
/// `Deserialize` and `JsonSchema` on it with `#[serde(deny_unknown_fields)]`.
pub fn tool<A, F, Fut>(name: &'static str, description: &'static str, f: F) -> ToolDef
where
    A: DeserializeOwned + JsonSchema + Send + 'static,
    F: Fn(ToolCtx, A) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = UaResult<Value>> + Send + 'static,
{
    let mut schema = serde_json::to_value(schemars::schema_for!(A)).unwrap_or_else(|_| json!({}));
    if let Some(obj) = schema.as_object_mut() {
        obj.remove("title");
        obj.entry("type").or_insert(json!("object"));
        obj.entry("properties").or_insert(json!({}));
    }
    let f = Arc::new(f);
    let handler: Handler = Arc::new(move |ctx, raw| {
        let f = f.clone();
        Box::pin(async move {
            let raw = if raw.is_null() { json!({}) } else { raw };
            let args: A = serde_json::from_value(raw).map_err(|e| UaError::invalid(e.to_string()))?;
            f(ctx, args).await
        })
    });
    ToolDef {
        name,
        description,
        family: "core",
        input_schema: schema,
        read_only: false,
        always_gated: false,
        gates_in_handler: false,
        gate_payload: None,
        handler,
    }
}

/// Run blocking work (SQLite, filesystem) off the async runtime.
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> UaResult<T> + Send + 'static) -> UaResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| UaError::internal(format!("blocking task failed: {e}")))?
}

/// All registered tools by name.
#[derive(Default, Clone)]
pub struct Registry {
    tools: BTreeMap<&'static str, ToolDef>,
}

impl Registry {
    pub fn add(&mut self, def: ToolDef) {
        if self.tools.insert(def.name, def.clone()).is_some() {
            panic!("tool {} registered twice", def.name);
        }
    }

    pub fn get(&self, name: &str) -> Option<&ToolDef> {
        self.tools.get(name)
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Every tool, unfiltered.
    pub fn all(&self) -> impl Iterator<Item = &ToolDef> {
        self.tools.values()
    }

    /// The tools `caller` can see. Profile filtering applies only when the
    /// caller's session enforces it; legacy aliases are then hidden too. A
    /// session-credential request sees only its grant's tools.
    pub fn visible_to<'a>(&'a self, caller: &'a Caller) -> impl Iterator<Item = &'a ToolDef> + 'a {
        let grant = crate::grant::current();
        // `acp-session` without a grant sees nothing: the profile is only
        // ever held by a verified session credential.
        let orphan = grant.is_none() && caller.profile == ua_core::Profile::AcpSession;
        self.tools.values().filter(move |t| {
            !orphan
                && grant.as_ref().is_none_or(|g| g.allows_tool(t.name))
                && (!caller.enforce_profile
                    || (caller.profile.allows_tool(t.name) && !ua_core::Profile::is_legacy_alias(t.name)))
        })
    }

    /// The governed call path. See the crate docs for the order of checks.
    pub async fn call(&self, hub: &Hub, caller: &Caller, name: &str, args: Value) -> UaResult<Value> {
        let Some(def) = self.tools.get(name) else {
            return Err(UaError::not_found(format!("unknown tool {name:?}")));
        };

        // A session credential's grant is the outer limit: no profile,
        // policy or approval can widen it. The `acp-session` profile without
        // a grant (it can only be reached by misconfiguration) gets nothing.
        let args = match crate::grant::current() {
            Some(g) => match g.narrow(name, args) {
                Ok(a) => a,
                Err(err) => {
                    record_decision(hub, caller, name, &err).await;
                    return Err(err);
                }
            },
            None if caller.profile == ua_core::Profile::AcpSession => {
                let err = UaError::denied(
                    "session_grant_required",
                    "the acp-session profile runs only under a verified session credential",
                );
                record_decision(hub, caller, name, &err).await;
                return Err(err);
            }
            None => args,
        };

        // The policy file is read once per call (cached by mtime). A file that
        // cannot be loaded refuses the call below, after the profile check.
        let loaded = hub.cfg().policy_file.as_deref().map(policy::load);

        // A policy overlay may lower an agent's profile below its default.
        let clamped;
        let caller = match &loaded {
            Some(Ok(p)) if caller.enforce_profile && caller.kind != ActorKind::Human => {
                let code_default = crate::sessions::default_profile(hub, &caller.label);
                match policy::overlay_profile(p, &caller.label, code_default, self.tools.keys().copied()) {
                    Some(overlay) if caller.profile.rank() > overlay.rank() => {
                        clamped = Caller { profile: overlay, ..caller.clone() };
                        &clamped
                    }
                    _ => caller,
                }
            }
            _ => caller,
        };

        if caller.enforce_profile {
            if !caller.profile.allows_tool(name) {
                let err = UaError::denied(
                    "profile_denied",
                    format!("tool {name} is not available to profile {}", caller.profile),
                );
                record_decision(hub, caller, name, &err).await;
                return Err(err);
            }
            if let Some(action) = args.get("action").and_then(Value::as_str)
                && !caller.profile.allows_action(name, action)
            {
                let err = UaError::denied(
                    "action_denied",
                    format!("action {action} of {name} is not available to profile {}", caller.profile),
                );
                record_decision(hub, caller, name, &err).await;
                return Err(err);
            }
        }

        let mut policy_gated = false;
        let mut reservation: Option<i64> = None;
        match loaded {
            None => {}
            Some(Err(reason)) => {
                let err =
                    UaError::denied("policy_unavailable", format!("policy gate failed closed: {reason}"));
                record_decision_rule(hub, caller, name, &err, "").await;
                return Err(err);
            }
            Some(Ok(p)) => {
                // Evaluate and reserve the `tool_calls` row in one write
                // transaction. The single writer serializes concurrent calls,
                // so rate limits and cooldowns count calls still in flight.
                let (c, n, a) = (caller.clone(), name.to_string(), args.clone());
                let verdict = hub
                    .db()
                    .write_async(move |tx| match policy::evaluate(tx, &p, &c, &n, &a) {
                        Ok(v) => {
                            let id = reserve_call(tx, &c, &n)?;
                            Ok(Ok((v, id)))
                        }
                        Err(r) => Ok(Err(r)),
                    })
                    .await
                    .unwrap_or_else(|e| {
                        Err(policy::Refusal {
                            error: UaError::denied(
                                "policy_unavailable",
                                format!("policy gate failed closed: {e}"),
                            ),
                            rule: String::new(),
                        })
                    });
                match verdict {
                    Ok((Verdict::Allow, id)) => reservation = Some(id),
                    Ok((Verdict::RequireApproval(_), id)) => {
                        reservation = Some(id);
                        policy_gated = true;
                    }
                    Err(refusal) => {
                        record_decision_rule(hub, caller, name, &refusal.error, &refusal.rule).await;
                        return Err(refusal.error);
                    }
                }
            }
        }

        if def.always_gated
            && let Err(refusal) = policy::check_prod_action(hub.cfg(), caller, name)
        {
            record_decision_rule(hub, caller, name, &refusal.error, &refusal.rule).await;
            release_reservation(hub, reservation).await;
            return Err(refusal.error);
        }

        let gated = def.always_gated || policy_gated || hub.cfg().approval_tools.iter().any(|t| t == name);
        if gated && !def.gates_in_handler {
            let gate_args = match def.gate_payload {
                Some(f) => f(hub.cfg(), &args),
                None => args.clone(),
            };
            let (h, c, n, a) = (hub.clone(), caller.clone(), name.to_string(), gate_args);
            let outcome = match hub.db().write_async(move |tx| approvals::gate(tx, h.cfg(), &c, &n, &a)).await
            {
                Ok(o) => o,
                Err(e) => {
                    release_reservation(hub, reservation).await;
                    return Err(e);
                }
            };
            match outcome {
                GateOutcome::Pass { .. } => {}
                GateOutcome::Pending { approval_id } => {
                    // A parked call has not run; it does not count against limits.
                    release_reservation(hub, reservation).await;
                    return Err(UaError::ApprovalRequired { tool: name.to_string(), approval_id });
                }
                GateOutcome::Denied { approval_id, reason } => {
                    let err = UaError::denied(
                        "approval_denied",
                        format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                    );
                    record_decision(hub, caller, name, &err).await;
                    release_reservation(hub, reservation).await;
                    return Err(err);
                }
            }
        }

        let ctx = ToolCtx { hub: hub.clone(), caller: caller.clone() };
        let started_at = ua_core::time::now();
        let clock = std::time::Instant::now();
        let result = (def.handler)(ctx, args).await;
        record_call(hub, caller, name, started_at, clock.elapsed(), &result, reservation).await;
        result
    }
}

/// One row per completed call in `tool_calls` (no arguments, no results).
async fn record_call(
    hub: &Hub,
    caller: &Caller,
    tool: &str,
    started_at: String,
    elapsed: std::time::Duration,
    result: &UaResult<Value>,
    reservation: Option<i64>,
) {
    let outcome = match result {
        Ok(_) => "ok".to_string(),
        Err(e) => e.code().to_string(),
    };
    let row = (
        tool.to_string(),
        caller.label.clone(),
        caller.profile.as_str().to_string(),
        serde_json::to_value(caller.transport)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
        started_at,
        elapsed.as_millis() as i64,
        outcome,
    );
    let res = hub
        .db()
        .write_async(move |tx| {
            match reservation {
                Some(id) => tx.execute(
                    "UPDATE tool_calls SET duration_ms = ?2, outcome = ?3 WHERE id = ?1",
                    rusqlite::params![id, row.5, row.6],
                )?,
                None => tx.execute(
                    "INSERT INTO tool_calls (tool, caller, profile, transport, started_at, duration_ms, outcome) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![row.0, row.1, row.2, row.3, row.4, row.5, row.6],
                )?,
            };
            Ok(())
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "could not record tool call");
    }
}

async fn record_decision(hub: &Hub, caller: &Caller, tool: &str, err: &UaError) {
    record_decision_rule(hub, caller, tool, err, "").await
}

/// Append an `agent.gateway.decision` deny event. `rule` names the policy
/// rule that fired; it is empty for profile and approval refusals.
pub(crate) async fn record_decision_rule(hub: &Hub, caller: &Caller, tool: &str, err: &UaError, rule: &str) {
    let reason_code = match err {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    };
    let mut payload = json!({
        "tool": tool,
        "decision": "deny",
        "reason_code": reason_code,
        "reason": err.to_string(),
        "profile": caller.profile.as_str(),
    });
    if !rule.is_empty() {
        payload["rule"] = json!(rule);
    }
    let originator = caller.label.clone();
    let res = hub
        .db()
        .write_async(move |tx| {
            ledger::append(tx, EventInput::new("agent.gateway.decision", payload).by(originator))?;
            Ok(())
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "could not record gateway decision");
    }
}

fn transport_name(caller: &Caller) -> String {
    serde_json::to_value(caller.transport)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Insert an in-flight `tool_calls` row (outcome `running`) so policy limits
/// see calls that have not finished yet. Returns its id.
fn reserve_call(tx: &rusqlite::Transaction<'_>, caller: &Caller, tool: &str) -> rusqlite::Result<i64> {
    tx.execute(
        "INSERT INTO tool_calls (tool, caller, profile, transport, started_at, duration_ms, outcome) \
         VALUES (?1, ?2, ?3, ?4, ?5, 0, 'running')",
        rusqlite::params![
            tool,
            caller.label,
            caller.profile.as_str(),
            transport_name(caller),
            ua_core::time::now()
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// Drop a reservation for a call that never ran (parked or refused later).
async fn release_reservation(hub: &Hub, reservation: Option<i64>) {
    let Some(id) = reservation else { return };
    let res = hub
        .db()
        .write_async(move |tx| {
            tx.execute("DELETE FROM tool_calls WHERE id = ?1 AND outcome = 'running'", [id])?;
            Ok(())
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "could not release a tool_calls reservation");
    }
}
