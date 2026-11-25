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
use crate::routes::Route;

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
    /// An argument that, when present (not null), moves the approval gate
    /// into the handler for that call: the handler then checks an
    /// alternative authority (a policy authorization) on resolved values.
    pub handler_gate_arg: Option<&'static str>,
    /// When set, the approval gate binds this projection of the arguments
    /// instead of the arguments themselves, so a value that must never be
    /// stored (a secret) is not parked in the approvals table.
    pub gate_payload: Option<GatePayload>,
    /// Calls whose handler may ask the approval gate itself, on values it
    /// resolves, besides any registry gate: such a call cannot be requested
    /// ahead (`POST /api/approvals/request` answers 409). Unlike
    /// [`ToolDef::gates_in_handler`] it does not change the call path.
    pub handler_may_gate: HandlerGate,
    /// An argument carries a secret (a token or credential value). Gating
    /// such a tool needs a `gate_payload` projection; without one the gate
    /// refuses rather than park the secret (`secret_args_unprojected`).
    pub secret_args: bool,
    /// For a `read_only` tool that still writes something on some calls
    /// (access counters, a heartbeat): true for the calls that do. Such a
    /// call always records its `tool_calls` row, even inside
    /// [`page_reads`].
    pub side_effects: Option<SideEffects>,
    /// A refusal decided on the caller and arguments alone, checked after
    /// admission and before any approval gate: a call it refuses parks no
    /// approval and runs nothing (it is recorded as a failed call).
    pub pre_gate: Option<PreGate>,
    /// Deserializes arguments into the tool's typed argument struct, so a
    /// request can be checked without running the handler.
    check: Checker,
    handler: Handler,
}

type Checker = Arc<dyn Fn(&Value) -> UaResult<()> + Send + Sync>;

/// Which calls of a tool may gate inside its handler.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HandlerGate {
    /// Never: only the registry gate applies.
    #[default]
    Never,
    /// Any call.
    Always,
    /// Calls whose `action` argument is one of these.
    Actions(&'static [&'static str]),
    /// Calls that carry this argument (not null).
    WithArg(&'static str),
}

/// See [`ToolDef::pre_gate`].
pub type PreGate = fn(&Caller, &Value) -> UaResult<()>;

/// Maps a call's arguments to the payload its approval binds.
pub type GatePayload = fn(&ua_core::Config, &Value) -> Value;

/// Whether one call of a read-only tool has a side effect (see
/// [`ToolDef::side_effects`]).
pub type SideEffects = fn(&Value) -> bool;

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

    /// When a call carries argument `arg`, the handler gates itself (see
    /// [`ToolDef::handler_gate_arg`]); without it the registry gate applies.
    pub fn handler_gates_with(mut self, arg: &'static str) -> Self {
        self.handler_gate_arg = Some(arg);
        self
    }

    fn handler_gates(&self, args: &Value) -> bool {
        self.gates_in_handler
            || self.handler_gate_arg.is_some_and(|k| args.get(k).is_some_and(|v| !v.is_null()))
    }

    /// The handler may gate this call itself (see [`ToolDef::handler_may_gate`]).
    pub fn handler_may_gate(mut self, when: HandlerGate) -> Self {
        self.handler_may_gate = when;
        self
    }

    /// An argument carries a secret (see [`ToolDef::secret_args`]).
    pub fn secret_args(mut self) -> Self {
        self.secret_args = true;
        self
    }

    /// The calls for which `f` is true write something although the tool is
    /// read-only (see [`ToolDef::side_effects`]).
    pub fn side_effects(mut self, f: SideEffects) -> Self {
        self.side_effects = Some(f);
        self
    }

    fn has_side_effects(&self, args: &Value) -> bool {
        self.side_effects.is_some_and(|f| f(args))
    }

    /// Whether this call's approval is (or may be) decided inside the
    /// handler on values only it resolves, so it cannot be requested ahead.
    pub fn handler_decides(&self, args: &Value) -> bool {
        self.handler_gates(args)
            || match self.handler_may_gate {
                HandlerGate::Never => false,
                HandlerGate::Always => true,
                HandlerGate::Actions(list) => {
                    args.get("action").and_then(Value::as_str).is_some_and(|a| list.contains(&a.trim()))
                }
                HandlerGate::WithArg(k) => {
                    args.get(k).is_some_and(|v| !v.is_null() && v != &Value::Bool(false))
                }
            }
    }

    /// Check `args` against the tool's typed arguments (unknown fields are
    /// refused) without running it.
    pub fn check_args(&self, args: &Value) -> UaResult<()> {
        (self.check)(args)
    }
    /// Gate on `f(config, args)` rather than on the raw arguments.
    pub fn gate_payload(mut self, f: GatePayload) -> Self {
        self.gate_payload = Some(f);
        self
    }

    /// Refuse a call with `f` before any approval is parked (see
    /// [`ToolDef::pre_gate`]).
    pub fn pre_gate(mut self, f: PreGate) -> Self {
        self.pre_gate = Some(f);
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
    let check: Checker = Arc::new(|raw: &Value| {
        let raw = if raw.is_null() { json!({}) } else { raw.clone() };
        serde_json::from_value::<A>(raw).map(drop).map_err(|e| UaError::invalid(e.to_string()))
    });
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
        handler_gate_arg: None,
        gate_payload: None,
        handler_may_gate: HandlerGate::Never,
        secret_args: false,
        side_effects: None,
        pre_gate: None,
        check,
        handler,
    }
}

/// The page composition a call runs in (see [`page_reads`]).
#[derive(Clone, Default)]
struct PageScope {
    /// The error code of the first inner read that failed.
    first_failure: Arc<std::sync::Mutex<Option<String>>>,
}

tokio::task_local! {
    static PAGE_READS: PageScope;
}

/// Run `f` as the composition of one page the hub renders itself for a
/// **verified human's browser session** (a Control Center `GET` page, or `GET
/// /api/board` with the session cookie). Adapters must not use it for any
/// other caller: an agent's reads would vanish from `agent_activity`,
/// `perf_summary` and `evidence_report`; use [`page_view`] instead.
///
/// Every call inside passes every check exactly as [`Registry::call`] always
/// does. A call that is *skip-eligible* (a `read_only` tool, no approval gate
/// applies, no side effect for these arguments, no policy-file reservation)
/// leaves no `tool_calls` row when it succeeds, so a page built from six or
/// eight reads does not serialise six or eight writes per view. A
/// skip-eligible call that fails is recorded with `page = 1`, which rate and
/// error calculations leave out (its successful siblings left no row).
/// Everything else records as usual: refusals reach the ledger, writes,
/// gated calls, side-effecting reads and, with a policy file loaded, every
/// call (its rate-limit reservation is a row). MCP and `/api/tools` calls
/// never run inside this scope.
pub async fn page_reads<F: Future>(f: F) -> F::Output {
    PAGE_READS.scope(PageScope::default(), f).await
}

/// [`page_reads`] for any caller that is not a verified human's browser
/// session: the inner skip-eligible reads leave no rows, and the view writes
/// one summary row of its own, tool `name`, with the composition's duration
/// and outcome (the first inner failure's code, else `ok`). The view stays
/// visible to `agent_activity`, `perf_summary` and `evidence_report` as one
/// call.
pub async fn page_view<F: Future>(hub: &Hub, caller: &Caller, name: &str, f: F) -> F::Output {
    let scope = PageScope::default();
    let first_failure = scope.first_failure.clone();
    let started_at = ua_core::time::now();
    let clock = std::time::Instant::now();
    let out = PAGE_READS.scope(scope, f).await;
    let outcome = first_failure.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let row = Row::new(
        caller,
        Recorded { tool: name, action_tool: None },
        started_at,
        clock.elapsed(),
        outcome.unwrap_or_else(|| "ok".into()),
        false,
    );
    insert_row(hub, row).await;
    out
}

/// Whether this call may leave no `tool_calls` row if it succeeds (see
/// [`page_reads`]).
fn skip_eligible(def: &ToolDef, args: &Value, gated: bool, reservation: Option<i64>) -> bool {
    def.read_only
        && !gated
        && !def.has_side_effects(args)
        && reservation.is_none()
        && PAGE_READS.try_with(|_| ()).is_ok()
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
        let Admitted { caller, args, policy_gated, reservation, route, route_policy_gated } =
            self.admit(hub, caller, name, args, true).await?;
        let caller = &caller;
        let routed = route.as_ref().and_then(Route::recorded);

        // A refusal the tool decides on the caller alone comes before any
        // approval is parked, and is recorded as the call's failure.
        if let Err(e) = pre_gate_check(self, def, route.as_ref(), caller, &args) {
            let result = Err(e);
            let rec = Recorded { tool: name, action_tool: routed.as_deref() };
            let started_at = ua_core::time::now();
            record_call(hub, caller, rec, started_at, std::time::Duration::ZERO, &result, reservation, false)
                .await;
            return result;
        }

        let plan =
            self.gate_plan(hub.cfg(), def, name, &args, policy_gated, route.as_ref(), route_policy_gated);
        if let Some(bind) = &plan.bind {
            let gate_args = match bind.payload(hub.cfg()) {
                Ok(p) => p,
                Err(e) => {
                    release_reservation(hub, caller, reservation).await;
                    return Err(e);
                }
            };
            let gate_tool = bind.name.clone();
            let via = (gate_tool != name).then(|| name.to_string());
            let (h, c, n, a) = (hub.clone(), caller.clone(), gate_tool.clone(), gate_args);
            let outcome = match hub
                .db()
                .write_async(move |tx| approvals::gate_via(tx, h.cfg(), &c, &n, &a, via.as_deref()))
                .await
            {
                Ok(o) => o,
                Err(e) => {
                    release_reservation(hub, caller, reservation).await;
                    return Err(e);
                }
            };
            match outcome {
                GateOutcome::Pass { .. } => {}
                GateOutcome::Pending { approval_id } => {
                    // A parked call has not run; it does not count against limits.
                    release_reservation(hub, caller, reservation).await;
                    return Err(UaError::ApprovalRequired { tool: gate_tool, approval_id });
                }
                GateOutcome::Denied { approval_id, reason } => {
                    let err = UaError::denied(
                        "approval_denied",
                        format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                    );
                    record_decision_routed(hub, caller, name, routed.as_deref(), &err, "").await;
                    release_reservation(hub, caller, reservation).await;
                    return Err(err);
                }
            }
        }

        let page = skip_eligible(def, &args, plan.gated, reservation);
        let ctx = ToolCtx { hub: hub.clone(), caller: caller.clone() };
        let started_at = ua_core::time::now();
        let clock = std::time::Instant::now();
        let result = (def.handler)(ctx, args).await;
        let rec = Recorded { tool: name, action_tool: routed.as_deref() };
        match (&result, page) {
            (Ok(_), true) => {}
            (Err(e), true) => {
                let _ = PAGE_READS.try_with(|s| {
                    s.first_failure
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .get_or_insert(e.code().to_string());
                });
                record_call(hub, caller, rec, started_at, clock.elapsed(), &result, reservation, true).await;
            }
            _ => {
                record_call(hub, caller, rec, started_at, clock.elapsed(), &result, reservation, false).await
            }
        }
        result
    }

    /// Which approval, if any, a call that passed [`Registry::admit`] must
    /// hold. The consolidated tool's own gates (its `always_gated` flag, a
    /// policy `require_approval` on its name, `approval_tools`) apply as
    /// always. For a routed call the gates of the action's own name apply
    /// too: the standalone tool's `always_gated` flag, a policy rule and an
    /// `approval_tools` entry for it (or for `tool:action`). When both
    /// apply, one approval covers the call, bound as a direct call of the
    /// standalone tool would bind it, so a human approves the action itself
    /// whichever door reached it and is asked once.
    #[allow(clippy::too_many_arguments)]
    fn gate_plan<'a>(
        &'a self,
        cfg: &ua_core::Config,
        def: &'a ToolDef,
        name: &str,
        args: &'a Value,
        policy_gated: bool,
        route: Option<&'a Route>,
        route_policy_gated: bool,
    ) -> GatePlan<'a> {
        let listed = |t: &str| crate::routes::listed(cfg, t);
        let door_gated = def.always_gated || policy_gated || listed(name);
        let mut key_gated = false;
        let mut bind = None;
        if let Some(r) = route
            && let Some(key) = r.gate_name()
        {
            let standalone = r.standalone().and_then(|s| self.tools.get(s));
            key_gated = route_policy_gated || listed(&key) || standalone.is_some_and(|d| d.always_gated);
            // The standalone tool's handler may gate itself, as on a direct
            // call; an own key follows the consolidated tool's flags.
            let (bdef, bargs) = match standalone {
                Some(d) => (d, &r.args),
                None => (def, args),
            };
            // An own action whose handler always asks a human itself takes
            // that one approval only.
            if key_gated && !bdef.handler_gates(bargs) && !r.handler_gated() {
                bind = Some(Bind { name: key, def: bdef, args: bargs });
            }
        }
        if bind.is_none() && door_gated && !def.handler_gates(args) {
            bind = Some(Bind { name: name.to_string(), def, args });
        }
        GatePlan { gated: door_gated || key_gated, bind }
    }

    /// What an approval requested ahead of a call (`POST
    /// /api/approvals/request`) may bind: the same grant, profile, policy
    /// and prod-action checks as [`Registry::call`], then the tool and
    /// payload the call's own gate would bind (the `gate_payload`
    /// projection, so a secret value is never parked; for a routed call,
    /// the standalone tool's name and payload, see [`crate::routes`]).
    /// Nothing runs and no call is reserved.
    ///
    /// A tool that evaluates its gate in its handler binds values only the
    /// handler resolves, so it cannot be requested ahead and answers
    /// [`ApprovalRequest::GatesInHandler`]; a call no rule gates answers
    /// [`ApprovalRequest::NotGated`].
    pub async fn approval_request(
        &self,
        hub: &Hub,
        caller: &Caller,
        name: &str,
        args: Value,
    ) -> UaResult<ApprovalRequest> {
        let Some(def) = self.tools.get(name) else {
            return Err(UaError::not_found(format!("unknown tool {name:?}")));
        };
        let Admitted { args, policy_gated, route, route_policy_gated, .. } =
            self.admit(hub, caller, name, args, false).await?;
        pre_gate_check(self, def, route.as_ref(), caller, &args)?;
        let plan =
            self.gate_plan(hub.cfg(), def, name, &args, policy_gated, route.as_ref(), route_policy_gated);
        if !plan.gated {
            return Ok(ApprovalRequest::NotGated);
        }
        let standalone =
            route.as_ref().and_then(|r| r.standalone().and_then(|s| self.tools.get(s)).zip(Some(r)));
        // An own `tool:action` key the registry binds is requestable: it is
        // exactly what the call parks first. Otherwise a handler that may
        // gate decides on values only it resolves.
        let own_bind = route.as_ref().zip(plan.bind.as_ref()).is_some_and(|(r, b)| {
            r.target == crate::routes::Target::Own && r.gate_name().as_deref() == Some(b.name.as_str())
        });
        if !own_bind
            && (def.handler_decides(&args) || standalone.is_some_and(|(d, r)| d.handler_decides(&r.args)))
        {
            return Ok(ApprovalRequest::GatesInHandler);
        }
        // The arguments must be a call the tool would accept: what a human
        // approves is exactly what can run.
        def.check_args(&args)?;
        if let Some((d, r)) = standalone {
            d.check_args(&r.args)?;
        }
        let Some(bind) = plan.bind else { return Ok(ApprovalRequest::GatesInHandler) };
        Ok(ApprovalRequest::Payload { tool: bind.name.clone(), payload: bind.payload(hub.cfg())? })
    }

    /// Every check before the approval gate: the session grant, the profile
    /// (after a policy overlay), the policy rules and, for an always-gated
    /// tool, the prod-action identity check. With `reserve`, the policy
    /// verdict and a `tool_calls` reservation are taken in one write
    /// transaction; without, the policy is evaluated on a read.
    ///
    /// A call of a tool that dispatches on an `action` is resolved with
    /// [`crate::routes::route`] after the grant: the profile, the policy
    /// rules and the prod-action check then also apply under the action's
    /// own name (see [`Route::gate_name`]), on the action's arguments.
    async fn admit(
        &self,
        hub: &Hub,
        caller: &Caller,
        name: &str,
        args: Value,
        reserve: bool,
    ) -> UaResult<Admitted> {
        let Some(def) = self.tools.get(name) else {
            return Err(UaError::not_found(format!("unknown tool {name:?}")));
        };
        require_caller_org(hub, caller).await?;

        // A hub-internal identity with a narrow grant may make only the calls
        // the grant names, whatever its profile or enforce_profile say.
        if let Some(why) = crate::families::github::grant_refusal(caller, name, &args) {
            let err = UaError::denied("grant_denied", why);
            record_decision(hub, caller, name, &err).await;
            return Err(err);
        }
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

        // Which action of a consolidated tool this is. An action the routing
        // table does not know never runs (refused after the profile check of
        // the tool itself, so a hidden tool reads as hidden).
        let route_res = crate::routes::route(name, &args);
        let routed = route_res.as_ref().ok().and_then(Option::as_ref).and_then(Route::recorded);
        let routed = routed.as_deref();

        // The policy file is read once per call (cached by mtime). A file that
        // cannot be loaded refuses the call below, after the profile check.
        let loaded = hub.cfg().policy_file.as_deref().map(policy::load);

        // A policy overlay may lower an agent's profile below its default.
        let caller = match &loaded {
            Some(Ok(p)) if caller.enforce_profile && caller.kind != ActorKind::Human => {
                let code_default = crate::sessions::default_profile(hub, &caller.org_id, &caller.label);
                match policy::overlay_profile(p, &caller.label, code_default, self.tools.keys().copied()) {
                    Some(overlay) if caller.profile.rank() > overlay.rank() => {
                        Caller { profile: overlay, ..caller.clone() }
                    }
                    _ => caller.clone(),
                }
            }
            _ => caller.clone(),
        };

        if caller.enforce_profile {
            if !caller.profile.allows_tool(name) {
                let err = UaError::denied(
                    "profile_denied",
                    format!("tool {name} is not available to profile {}", caller.profile),
                );
                record_decision_routed(hub, &caller, name, routed, &err, "").await;
                return Err(err);
            }
            if let Some(action) = profile_action(name, &args)
                && !caller.profile.allows_action(name, action)
            {
                let err = UaError::denied(
                    "action_denied",
                    format!("action {action} of {name} is not available to profile {}", caller.profile),
                );
                record_decision_routed(hub, &caller, name, routed, &err, "").await;
                return Err(err);
            }
        }
        let route = route_res?;
        if caller.enforce_profile {
            // The action runs a standalone tool's handler: the profile must
            // allow that tool too (or grant it as an action).
            if let Some(r) = &route
                && let Some(standalone) = r.standalone()
                && !caller.profile.allows_routed(standalone)
            {
                let err = UaError::denied(
                    "profile_denied",
                    format!(
                        "action {} of {name} runs tool {standalone}, which is not available to profile {}",
                        r.action, caller.profile
                    ),
                );
                record_decision_routed(hub, &caller, name, routed, &err, "").await;
                return Err(err);
            }
        }

        let mut policy_gated = false;
        let mut route_policy_gated = false;
        let mut reservation: Option<i64> = None;
        match loaded {
            None => {}
            Some(Err(reason)) => {
                let err =
                    UaError::denied("policy_unavailable", format!("policy gate failed closed: {reason}"));
                record_decision_routed(hub, &caller, name, routed, &err, "").await;
                return Err(err);
            }
            Some(Ok(p)) => {
                // Evaluate and reserve the `tool_calls` row in one write
                // transaction. The single writer serializes concurrent calls,
                // so rate limits and cooldowns count calls still in flight.
                // A routed call is evaluated under its own name too, on the
                // action's arguments; either refusal refuses it.
                let (c, n, a) = (caller.clone(), name.to_string(), args.clone());
                let key = route.as_ref().and_then(|r| r.gate_name().map(|k| (k, r.args.clone())));
                let rec = routed.map(str::to_string);
                let eval = move |conn: &rusqlite::Connection| -> Result<(Verdict, Verdict), policy::Refusal> {
                    let door = policy::evaluate(conn, &p, &c, &n, &a)?;
                    let own = match &key {
                        Some((k, ka)) => policy::evaluate_routed(conn, &p, &c, k, ka)?,
                        None => Verdict::Allow,
                    };
                    Ok((door, own))
                };
                let verdict = if reserve {
                    let (c, n) = (caller.clone(), name.to_string());
                    hub.db()
                        .write_async(move |tx| match eval(tx) {
                            Ok(v) => {
                                let id = reserve_call(tx, &c, &n, rec.as_deref())?;
                                Ok(Ok((v, Some(id))))
                            }
                            Err(r) => Ok(Err(r)),
                        })
                        .await
                } else {
                    hub.db().read_async(move |c2| Ok(eval(c2).map(|v| (v, None)))).await
                }
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
                    Ok(((door, own), id)) => {
                        reservation = id;
                        policy_gated = matches!(door, Verdict::RequireApproval(_));
                        route_policy_gated = matches!(own, Verdict::RequireApproval(_));
                    }
                    Err(refusal) => {
                        record_decision_routed(hub, &caller, name, routed, &refusal.error, &refusal.rule)
                            .await;
                        return Err(refusal.error);
                    }
                }
            }
        }

        // The prod-action identity check, for the tool called and for an
        // always-gated standalone tool a routed action runs.
        let standalone_always = route
            .as_ref()
            .and_then(Route::standalone)
            .and_then(|s| self.tools.get(s))
            .filter(|d| d.always_gated)
            .map(|d| d.name);
        for prod in def.always_gated.then_some(name).into_iter().chain(standalone_always) {
            if let Err(refusal) = policy::check_prod_action(hub.cfg(), &caller, prod) {
                record_decision_routed(hub, &caller, name, routed, &refusal.error, &refusal.rule).await;
                release_reservation(hub, &caller, reservation).await;
                return Err(refusal.error);
            }
        }

        Ok(Admitted { caller, args, policy_gated, reservation, route, route_policy_gated })
    }
}

/// Refuse a caller whose organization `orgs` does not hold, or holds as
/// suspended, before anything runs: no handler, no grant or policy
/// evaluation, no `tool_calls` row and no decision event (an event or row
/// for an organization that does not exist could not be written anyway).
///
/// One primary-key read per call of another organization. The default
/// organization is seeded with the schema and cannot be deleted, so its
/// callers, every caller today, skip it. It is checked here rather than
/// only when a credential resolves because the registry is the one path
/// every caller takes (HTTP and MCP credentials, the hub's own per
/// organization jobs, stdio, tests), and rather than cached because a
/// suspension must apply to the next call.
async fn require_caller_org(hub: &Hub, caller: &Caller) -> UaResult<()> {
    if caller.org_id == ua_core::DEFAULT_ORG {
        return Ok(());
    }
    let org = caller.org_id.clone();
    let status: Option<String> = hub
        .db()
        .read_async(move |c| {
            use rusqlite::OptionalExtension;
            Ok(c.query_row("SELECT status FROM orgs WHERE id = ?1", [&org], |r| r.get(0)).optional()?)
        })
        .await?;
    match status.as_deref() {
        Some("active") => Ok(()),
        None => Err(UaError::denied(
            "unknown_organization",
            format!("unknown organization {:?}; nothing ran and nothing was written", caller.org_id),
        )),
        Some(_) => Err(UaError::denied(
            "organization_suspended",
            format!("organization {:?} is suspended; nothing ran and nothing was written", caller.org_id),
        )),
    }
}

/// The approval one call must hold (see [`Registry::gate_plan`]).
struct GatePlan<'a> {
    /// Some approval gate applies (the call is not skip-eligible).
    gated: bool,
    /// What the registry gate binds; `None` when nothing is gated or a
    /// handler gates the call itself.
    bind: Option<Bind<'a>>,
}

/// The tool name an approval binds, and the definition and arguments whose
/// projection is its payload.
struct Bind<'a> {
    name: String,
    def: &'a ToolDef,
    args: &'a Value,
}

impl Bind<'_> {
    fn payload(&self, cfg: &ua_core::Config) -> UaResult<Value> {
        match self.def.gate_payload {
            Some(f) => Ok(f(cfg, self.args)),
            None if self.def.secret_args => Err(unprojected_secret(&self.name)),
            None => Ok(self.args.clone()),
        }
    }
}

/// The action a profile's action allow-list is checked against: the
/// `action` as the caller wrote it (the lists name actions that way, e.g.
/// `plan_create` for `plan_manage`), or, when the call names none (absent or
/// `null`), the tool's default action, which is what the call runs (see
/// [`crate::routes::action_of`]). `None` for a tool with no action.
fn profile_action<'a>(name: &str, args: &'a Value) -> Option<&'a str> {
    match args.get("action") {
        Some(Value::String(s)) => Some(s.as_str()),
        None | Some(Value::Null) => crate::routes::manager(name).and_then(|m| m.default_action),
        Some(_) => None,
    }
}

/// A gated call of a tool whose arguments carry a secret and that has no
/// projection: refused rather than park the secret in the approvals table.
fn unprojected_secret(name: &str) -> UaError {
    UaError::denied(
        "secret_args_unprojected",
        format!("tool {name} carries a secret argument and has no approval projection; it cannot be gated"),
    )
}

/// A call that passed every check before the approval gate.
struct Admitted {
    /// The caller, with any policy overlay applied.
    caller: Caller,
    /// The arguments after the session grant's narrowing.
    args: Value,
    /// A policy `require_approval` rule matched.
    policy_gated: bool,
    /// The reserved `tool_calls` row, when a policy was evaluated.
    reservation: Option<i64>,
    /// The action of a consolidated tool, resolved.
    route: Option<Route>,
    /// A policy `require_approval` rule matched the action's own name.
    route_policy_gated: bool,
}

/// What [`Registry::approval_request`] found.
#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalRequest {
    /// The approval would bind this payload under this tool name (the tool
    /// called, or the standalone tool or `tool:action` key a consolidated
    /// tool's action is gated as).
    Payload { tool: String, payload: Value },
    /// No rule gates the call, so there is nothing to approve.
    NotGated,
    /// The tool evaluates its gate in its handler on values it resolves;
    /// call the tool itself to park its approval.
    GatesInHandler,
}

/// One `tool_calls` row (no arguments, no results).
struct Row {
    /// The caller's organization: every row records where the call was made.
    org_id: String,
    tool: String,
    /// For a call of a consolidated tool, the standalone tool (or
    /// `tool:action` key) its action ran.
    action_tool: Option<String>,
    caller: String,
    profile: String,
    transport: String,
    started_at: String,
    duration_ms: i64,
    outcome: String,
    page: bool,
}

impl Row {
    fn new(
        caller: &Caller,
        tool: Recorded<'_>,
        started_at: String,
        elapsed: std::time::Duration,
        outcome: String,
        page: bool,
    ) -> Self {
        Self {
            org_id: caller.org_id.clone(),
            tool: tool.tool.to_string(),
            action_tool: tool.action_tool.map(str::to_string),
            caller: caller.label.clone(),
            profile: caller.profile.as_str().to_string(),
            transport: transport_name(caller),
            started_at,
            duration_ms: elapsed.as_millis() as i64,
            outcome,
            page,
        }
    }
}

async fn insert_row(hub: &Hub, row: Row) {
    let res = hub
        .db()
        .write_async(move |tx| {
            tx.execute(
                "INSERT INTO tool_calls (org_id, tool, caller, profile, transport, started_at, duration_ms, outcome, \
                 page, action_tool) VALUES (?10, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    row.tool,
                    row.caller,
                    row.profile,
                    row.transport,
                    row.started_at,
                    row.duration_ms,
                    row.outcome,
                    row.page,
                    row.action_tool,
                    row.org_id
                ],
            )?;
            Ok(())
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "could not record tool call");
    }
}

/// One row per completed call in `tool_calls` (no arguments, no results):
/// the reservation's row finished, or a new row (`page` marks a page-scope
/// read, see [`page_reads`]).
#[allow(clippy::too_many_arguments)]
async fn record_call(
    hub: &Hub,
    caller: &Caller,
    tool: Recorded<'_>,
    started_at: String,
    elapsed: std::time::Duration,
    result: &UaResult<Value>,
    reservation: Option<i64>,
    page: bool,
) {
    let outcome = match result {
        Ok(_) => "ok".to_string(),
        Err(e) => e.code().to_string(),
    };
    let row = Row::new(caller, tool, started_at, elapsed, outcome, page);
    let Some(id) = reservation else { return insert_row(hub, row).await };
    let res = hub
        .db()
        .write_async(move |tx| {
            tx.execute(
                "UPDATE tool_calls SET duration_ms = ?2, outcome = ?3 WHERE org_id = ?4 AND id = ?1",
                rusqlite::params![id, row.duration_ms, row.outcome, row.org_id],
            )?;
            Ok(())
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "could not record tool call");
    }
}

/// The names one `tool_calls` row records: the tool called, and the action
/// a consolidated tool ran.
#[derive(Clone, Copy)]
struct Recorded<'a> {
    tool: &'a str,
    action_tool: Option<&'a str>,
}

async fn record_decision(hub: &Hub, caller: &Caller, tool: &str, err: &UaError) {
    record_decision_rule(hub, caller, tool, err, "").await
}

/// Append an `agent.gateway.decision` deny event. `rule` names the policy
/// rule that fired; it is empty for profile and approval refusals.
pub(crate) async fn record_decision_rule(hub: &Hub, caller: &Caller, tool: &str, err: &UaError, rule: &str) {
    record_decision_routed(hub, caller, tool, None, err, rule).await
}

/// [`record_decision_rule`] for a call of a consolidated tool: the event
/// names the tool called (`tool`) and the action it would have run
/// (`action_tool`: the standalone tool or `tool:action` key).
pub(crate) async fn record_decision_routed(
    hub: &Hub,
    caller: &Caller,
    tool: &str,
    action_tool: Option<&str>,
    err: &UaError,
    rule: &str,
) {
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
    if let Some(a) = action_tool {
        payload["action_tool"] = json!(a);
    }
    let originator = caller.label.clone();
    let res = hub
        .db()
        .write_async(move |tx| {
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG, "agent.gateway.decision", payload).by(originator),
            )?;
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
fn reserve_call(
    tx: &rusqlite::Transaction<'_>,
    caller: &Caller,
    tool: &str,
    action_tool: Option<&str>,
) -> rusqlite::Result<i64> {
    tx.execute(
        "INSERT INTO tool_calls (org_id, tool, caller, profile, transport, started_at, duration_ms, outcome, \
         action_tool) VALUES (?7, ?1, ?2, ?3, ?4, ?5, 0, 'running', ?6)",
        rusqlite::params![
            tool,
            caller.label,
            caller.profile.as_str(),
            transport_name(caller),
            ua_core::time::now(),
            action_tool,
            caller.org_id
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// Drop `caller`'s reservation for a call that never ran (parked or refused
/// later).
/// The pre-gate of the tool called and, for a routed action, of the
/// standalone tool it runs (on the action's arguments).
fn pre_gate_check(
    reg: &Registry,
    def: &ToolDef,
    route: Option<&Route>,
    caller: &Caller,
    args: &Value,
) -> UaResult<()> {
    if let Some(f) = def.pre_gate {
        f(caller, args)?;
    }
    if let Some(r) = route
        && let Some(d) = r.standalone().and_then(|s| reg.tools.get(s))
        && let Some(f) = d.pre_gate
    {
        f(caller, &r.args)?;
    }
    Ok(())
}

async fn release_reservation(hub: &Hub, caller: &Caller, reservation: Option<i64>) {
    let Some(id) = reservation else { return };
    let org = caller.org_id.clone();
    let res = hub
        .db()
        .write_async(move |tx| {
            tx.execute(
                "DELETE FROM tool_calls WHERE org_id = ?2 AND id = ?1 AND outcome = 'running'",
                rusqlite::params![id, org],
            )?;
            Ok(())
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "could not release a tool_calls reservation");
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ua_core::Profile;

    use super::profile_action;

    #[test]
    fn a_call_with_no_action_is_filtered_as_the_default_action() {
        // Absent and null are the default action; a written action is as
        // written; a tool without actions has none.
        assert_eq!(profile_action("oauth_device_manage", &json!({})), Some("list"));
        assert_eq!(profile_action("oauth_device_manage", &json!({ "action": null })), Some("list"));
        assert_eq!(profile_action("config_revision_manage", &json!({})), Some("list"));
        assert_eq!(profile_action("mcp_gateway", &json!({})), Some("call"));
        assert_eq!(profile_action("node_config", &json!({})), Some("get"));
        assert_eq!(profile_action("oauth_device_manage", &json!({ "action": "revoke" })), Some("revoke"));
        assert_eq!(profile_action("plan_manage", &json!({ "action": "plan_create" })), Some("plan_create"));
        assert_eq!(profile_action("plan_manage", &json!({})), None, "no default: route() refuses it");
        assert_eq!(profile_action("task_add", &json!({})), None);
        // So an allow-list that excludes the default refuses a call naming
        // none, as it refuses one naming the default. No shipped allow-list
        // profile sees a default-action tool, so this is the filter itself:
        // research sees plan_manage and lists `plan_create` but not `list`.
        let filter = |p: Profile, tool: &str, args: serde_json::Value| {
            profile_action(tool, &args).is_none_or(|a| p.allows_action(tool, a))
        };
        assert!(!filter(Profile::Research, "plan_manage", json!({ "action": "list" })));
        assert!(filter(Profile::Research, "plan_manage", json!({ "action": "plan_create" })));
        for tool in ["oauth_device_manage", "config_revision_manage", "mcp_gateway", "node_config"] {
            assert!(!filter(Profile::Research, tool, json!({})), "{tool}");
            assert!(filter(Profile::Coordinator, tool, json!({})), "{tool}");
        }
    }
}

/// The registry refuses a caller whose organization `orgs` does not hold
/// before any tool runs ([`require_caller_org`]), so the tenant tests that go
/// through [`Registry::call`] stop there. These run handlers directly,
/// bypassing the registry, to prove each family's own guard stays behind
/// it: the family's `require_org` (with its own wording, including on a
/// write that inserts nothing, which the trigger cannot see) and the
/// `org_exists` insert trigger on a raw insert.
#[cfg(test)]
mod family_org_guards {
    use serde_json::{Value, json};
    use ua_core::{ActorKind, Caller, Config, Profile, UaResult, identity::Transport};

    use super::ToolCtx;
    use crate::Hub;

    const GHOST: &str = "org-ghost-not-real";

    fn ghost() -> Caller {
        Caller {
            label: "builder-1".into(),
            kind: ActorKind::Agent,
            profile: Profile::Operator,
            enforce_profile: false,
            session_key: Some("builder-1-s".into()),
            transport: Transport::Mcp,
            org_id: GHOST.into(),
        }
    }

    /// The tool's handler alone: no admission, organization check, grant,
    /// policy, gate or `tool_calls` row.
    async fn handler_only(hub: &Hub, tool: &str, args: Value) -> UaResult<Value> {
        let reg = crate::builtin_registry_shared();
        let def = reg.get(tool).unwrap_or_else(|| panic!("no tool {tool}"));
        (def.handler)(ToolCtx { hub: hub.clone(), caller: ghost() }, args).await
    }

    fn count(hub: &Hub, sql: &str) -> i64 {
        hub.db().read(|c| Ok(c.query_row(sql, [], |r| r.get(0))?)).unwrap()
    }

    #[tokio::test]
    async fn each_familys_own_guard_refuses_an_unknown_organization_behind_the_registry() {
        let hub = Hub::in_memory(Config::for_home(std::env::temp_dir())).unwrap();
        let unknown = format!("unknown organization {GHOST:?}");
        for (tool, args, wording) in [
            ("task_add", json!({ "title": "fake task" }), "no task was changed"),
            (
                "plan_manage",
                json!({ "action": "create", "params": { "goal": "fake plan", "steps": ["one"] } }),
                "no plan was changed",
            ),
            ("routine_add", json!({ "title": "fake routine", "trigger": "api" }), "no routine was changed"),
            // A pause or a delete inserts nothing, so only the family's
            // guard sees it.
            ("routine_pause", json!({ "routine_id": 1 }), "no routine was changed"),
            (
                "plan_manage",
                json!({ "action": "delete", "params": { "plan_id": "fake-plan" } }),
                "no plan was changed",
            ),
        ] {
            let e = handler_only(&hub, tool, args).await.unwrap_err();
            assert!(e.to_string().contains(&format!("{unknown}; {wording}")), "{tool}: {e:?}");
            assert!(!e.to_string().contains("nothing ran and nothing was written"), "{tool}: {e:?}");
        }
        for table in ["tasks", "plans", "routines"] {
            assert_eq!(count(&hub, &format!("SELECT COUNT(*) FROM {table} WHERE org_id = '{GHOST}'")), 0);
        }
        assert_eq!(count(&hub, "SELECT COUNT(*) FROM tool_calls"), 0);

        // The insert trigger stays behind both.
        let e = hub
            .db()
            .write(|tx| {
                tx.execute("INSERT INTO tasks (org_id, title) VALUES (?1, 'fake task')", [GHOST])?;
                Ok(())
            })
            .unwrap_err();
        assert!(e.to_string().contains("unknown organization"), "{e:?}");
        assert_eq!(count(&hub, &format!("SELECT COUNT(*) FROM tasks WHERE org_id = '{GHOST}'")), 0);
    }
}
