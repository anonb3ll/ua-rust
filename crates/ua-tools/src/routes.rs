//! Consolidated tools and the actions behind them.
//!
//! Several tools take an `action` argument and run one of many operations
//! (`plan_manage`, `delegation_manage`, `coordination_manage`, ...). Many of
//! those operations are also registered as a standalone tool with the same
//! handler (`plan_manage` action `delete` runs what `plan_delete` runs). An
//! operator gates a tool by name, so a gate on `plan_delete` must also hold
//! when the delete is reached through `plan_manage`.
//!
//! [`MANAGERS`] is the one table that says, for every action of every such
//! tool, what the action is:
//!
//! - [`Target::Standalone`]: the action runs the handler of that registered
//!   tool on the action's `params`. [`crate::Registry::call`] applies that
//!   tool's profile entry, policy rules, `approval_tools` entry and gate
//!   flags to the call, under that name and on `params`, besides everything
//!   that applies to the consolidated tool's own name. An approval binds the
//!   same (tool, payload) as a direct call of the standalone tool would.
//! - [`Target::Own`]: there is no standalone tool. The gate key is
//!   `tool:action` (`plan_manage:close`), which `approval_tools` entries and
//!   policy `tool` patterns may name; its payload is the call's arguments.
//! - [`Target::Nested`]: the handler itself makes a full governed call of
//!   that tool, which applies every check once; nothing more applies at the
//!   consolidated tool.
//! - [`Target::Refused`]: the handler always refuses the action (an
//!   operation that was not ported, or comments that are append-only).
//!
//! An action the table does not know is refused before the tool runs, so a
//! new action cannot run until it has an entry here (the `routes` tests
//! check the table against each tool's own action list).

use serde_json::{Value, json};
use ua_core::UaError;

use crate::families::{delegation, messaging, observability, plans};

/// What one action of a consolidated tool runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The handler of this registered tool, on the action's `params`.
    Standalone(&'static str),
    /// No standalone tool: gated as `tool:action` on the call's arguments.
    Own,
    /// The handler makes a governed call of this tool itself.
    Nested(&'static str),
    /// The handler refuses the action.
    Refused,
}

/// How a tool reads its `action` argument before matching it, so the table
/// resolves exactly the actions the handler accepts.
#[derive(Clone, Copy)]
pub enum Norm {
    /// Taken as given.
    Exact,
    /// Leading and trailing whitespace dropped.
    Trim,
    /// Trimmed and lower-cased.
    TrimLower,
    /// The tool's own canonicalizer (it also resolves legacy names).
    Custom(fn(&str) -> Option<&'static str>),
}

/// One tool that dispatches on an `action` argument.
pub struct Manager {
    pub tool: &'static str,
    pub norm: Norm,
    /// Alternative names (after [`Norm`]) and the action each stands for.
    pub aliases: &'static [(&'static str, &'static str)],
    /// The action of a call that carries none (or `null`).
    pub default_action: Option<&'static str>,
    /// Action-name prefixes the handler refuses wholesale.
    pub refused_prefixes: &'static [&'static str],
    /// Own actions whose handler always takes its own one-time human
    /// approval (on values it resolves). Their `tool:action` key takes
    /// policy rules, but the registry parks no second approval for it: one
    /// logical call, one approval.
    pub handler_gated: &'static [&'static str],
    /// Every action the handler accepts, with what it runs.
    pub actions: &'static [(&'static str, Target)],
}

use Target::{Nested, Own, Refused, Standalone};

/// Every tool that dispatches on an `action` argument.
pub const MANAGERS: &[Manager] = &[
    Manager {
        tool: "plan_manage",
        norm: Norm::Custom(plan_action),
        aliases: &[],
        default_action: None,
        refused_prefixes: &[],
        handler_gated: &[],
        actions: &[
            ("create", Standalone("plan_create")),
            ("update", Standalone("plan_update")),
            ("get", Standalone("plan_get")),
            ("list", Standalone("plan_list")),
            ("checkpoint", Standalone("plan_checkpoint")),
            ("resume", Standalone("plan_resume")),
            ("step_retry", Standalone("plan_step_retry")),
            ("step_claim", Standalone("plan_step_claim")),
            ("handoff", Standalone("plan_handoff")),
            ("close", Own),
            ("delete", Standalone("plan_delete")),
            ("step_add", Own),
            ("step_edit", Own),
            ("step_remove", Own),
            ("step_reorder", Own),
            ("edit", Own),
        ],
    },
    Manager {
        tool: "delegation_manage",
        norm: Norm::Custom(delegation_action),
        aliases: &[],
        default_action: None,
        refused_prefixes: &[],
        handler_gated: &[],
        actions: &[
            ("create", Standalone("delegate")),
            ("list", Standalone("delegate_list")),
            ("claim", Standalone("delegate_claim")),
            ("release", Standalone("delegate_release")),
            ("cancel", Standalone("delegate_cancel")),
            ("fail", Own),
            ("complete", Own),
            ("retry", Own),
            ("get", Own),
            ("lookup", Own),
            ("spec_check", Standalone("delegation_spec_check")),
            ("spec_template", Standalone("delegation_spec_template")),
            ("spec_build", Standalone("delegation_spec_build")),
        ],
    },
    Manager {
        tool: "observability_manage",
        norm: Norm::Custom(observability_action),
        aliases: &[],
        default_action: None,
        refused_prefixes: &[],
        handler_gated: &[],
        actions: &[
            ("activity", Standalone("agent_activity")),
            ("metrics", Standalone("metrics_snapshot")),
            ("anomalies", Standalone("check_anomalies")),
            ("performance", Standalone("perf_summary")),
            ("agents", Standalone("agent_list")),
            ("context", Standalone("agent_context")),
            ("delegation_stats", Own),
        ],
    },
    Manager {
        tool: "coordination_manage",
        norm: Norm::Custom(coordination_action),
        aliases: &[],
        default_action: None,
        refused_prefixes: &[],
        handler_gated: &["node_command_start", "node_item_restart"],
        actions: &[
            ("agent_context", Standalone("agent_context")),
            ("agent_forget", Own),
            ("agent_list", Standalone("agent_list")),
            ("agent_pause", Own),
            ("agent_resume", Own),
            ("agent_retire", Own),
            ("agent_state", Own),
            ("agent_states", Own),
            ("agent_terminate", Own),
            ("agent_unretire", Own),
            ("conversation_handoff", Own),
            ("conversation_handoffs", Own),
            ("message_ack", Own),
            ("message_inbox", Own),
            ("node_acceptance_attest", Own),
            ("node_acceptance_evaluate", Own),
            ("node_acceptance_start", Own),
            ("node_acceptance_status", Own),
            ("node_command_adopt", Own),
            ("node_command_start", Own),
            ("node_command_status", Own),
            ("node_forget", Own),
            ("node_item_cancel", Own),
            ("node_item_reconcile", Own),
            ("node_item_restart", Own),
            ("node_reassign", Own),
            ("node_retire", Own),
            ("node_unretire", Own),
            ("project_repo_bind", Own),
            ("project_repo_get", Own),
            ("project_repo_list", Own),
            ("project_repo_unbind", Own),
            ("queue_close_merged", Own),
            ("queue_fold", Own),
            ("queue_health", Own),
            ("queue_park", Own),
            ("queue_stale", Own),
            ("queue_sweep", Own),
            ("queue_unpark", Own),
            ("session_credential_revoke", Own),
            ("session_handoff_ack", Own),
            ("session_handoff_discard", Own),
            ("session_handoff_propose", Own),
            ("session_handoff_recover", Own),
            ("session_handoff_seal", Own),
            ("session_handoff_update", Own),
            ("session_wake_decline", Own),
            ("session_wake_grant", Own),
            ("session_wake_opt_in", Own),
            ("session_wake_status", Own),
            ("task_check_record", Own),
            ("task_check_verify", Own),
            ("task_claim_release", Own),
            ("task_hold", Own),
            ("task_hold_get", Own),
            ("task_holds", Own),
            ("task_workflow_get", Own),
            ("task_workflow_set", Own),
            ("work_proposal_decide", Own),
            ("work_proposal_file", Own),
            ("work_proposal_get", Own),
            ("work_proposal_list", Own),
            ("work_proposal_recover", Own),
            ("work_proposal_withdraw", Own),
        ],
    },
    Manager {
        tool: "autonomous_cycle_manage",
        norm: Norm::TrimLower,
        aliases: &[],
        default_action: None,
        refused_prefixes: &[],
        handler_gated: &[],
        actions: &[
            ("start", Standalone("autonomous_cycle_start")),
            ("get", Standalone("autonomous_cycle_get")),
            ("get_for_task", Own),
            ("transition", Standalone("autonomous_cycle_transition")),
            ("kill", Standalone("autonomous_cycle_kill")),
            ("record_usage", Standalone("autonomous_cycle_record_usage")),
            ("list", Standalone("autonomous_cycle_list")),
        ],
    },
    Manager {
        tool: "export_data",
        norm: Norm::TrimLower,
        aliases: &[
            ("export_tasks", "tasks"),
            ("export_memory", "memory"),
            ("export_journal", "journal"),
            ("export_migration_manifest", "manifest"),
            ("compare_migration_manifests", "compare"),
        ],
        default_action: None,
        refused_prefixes: &[],
        handler_gated: &[],
        actions: &[
            ("tasks", Standalone("export_tasks")),
            ("memory", Standalone("export_memory")),
            ("journal", Standalone("export_journal")),
            ("manifest", Nested("export_migration_manifest")),
            ("compare", Nested("compare_migration_manifests")),
            ("import", Refused),
            ("rollback", Refused),
        ],
    },
    Manager {
        tool: "config_revision_manage",
        norm: Norm::Exact,
        aliases: &[],
        default_action: Some("list"),
        refused_prefixes: &[],
        handler_gated: &["commit", "rollback"],
        actions: &[
            ("list", Own),
            ("diff", Own),
            ("show", Own),
            ("capture", Own),
            ("commit", Own),
            ("rollback", Own),
        ],
    },
    Manager {
        tool: "relay_manage",
        norm: Norm::TrimLower,
        aliases: &[],
        default_action: None,
        refused_prefixes: &[],
        handler_gated: &[],
        actions: &[
            ("check", Own),
            ("draft", Own),
            ("request_send", Own),
            ("send", Own),
            ("status", Own),
            ("list", Own),
            ("cancel", Own),
            ("resolve", Own),
        ],
    },
    Manager {
        tool: "oauth_device_manage",
        norm: Norm::Trim,
        aliases: &[],
        default_action: Some("list"),
        refused_prefixes: &[],
        handler_gated: &["revoke"],
        actions: &[("list", Own), ("revoke", Own)],
    },
    Manager {
        tool: "mcp_gateway",
        norm: Norm::Exact,
        aliases: &[],
        default_action: Some("call"),
        refused_prefixes: &[],
        handler_gated: &[],
        actions: &[("call", Own), ("list", Own)],
    },
    Manager {
        tool: "skill_registry",
        norm: Norm::TrimLower,
        aliases: &[],
        default_action: None,
        refused_prefixes: &["source_"],
        handler_gated: &[],
        actions: &[
            ("publish", Own),
            ("list", Own),
            ("get", Own),
            ("assign", Own),
            ("unassign", Own),
            ("resolve", Own),
            ("drift", Own),
            ("source_add", Own),
            ("source_revoke", Own),
            ("source_list", Own),
            ("catalog", Refused),
            ("install", Refused),
            ("team_install", Refused),
            ("starter_preview", Refused),
            ("starter_install", Refused),
        ],
    },
    Manager {
        tool: "node_config",
        norm: Norm::Exact,
        aliases: &[],
        default_action: Some("get"),
        refused_prefixes: &[],
        handler_gated: &[],
        actions: &[("get", Own), ("report", Own), ("applied", Own)],
    },
    Manager {
        tool: "task_comment",
        norm: Norm::TrimLower,
        aliases: &[],
        default_action: None,
        refused_prefixes: &[],
        handler_gated: &[],
        actions: &[
            ("append", Own),
            ("list", Own),
            ("get", Own),
            ("update", Refused),
            ("delete", Refused),
            ("edit", Refused),
            ("remove", Refused),
        ],
    },
    Manager {
        tool: "goal_manage",
        norm: Norm::TrimLower,
        aliases: &[],
        default_action: None,
        refused_prefixes: &[],
        handler_gated: &[],
        actions: &[
            ("add", Own),
            ("list", Own),
            ("tree", Own),
            ("get", Own),
            ("link", Own),
            ("unlink", Own),
            ("edit", Own),
            ("close", Own),
            ("reopen", Own),
            ("ancestry", Own),
        ],
    },
];

fn plan_action(a: &str) -> Option<&'static str> {
    plans::canonical_action(a).ok()
}

fn delegation_action(a: &str) -> Option<&'static str> {
    delegation::canonical_action(a).ok()
}

fn observability_action(a: &str) -> Option<&'static str> {
    observability::canonical_action(a).ok()
}

fn coordination_action(a: &str) -> Option<&'static str> {
    let a = a.trim();
    messaging::COORDINATION_ACTIONS.iter().copied().find(|x| *x == a)
}

/// The table entry for `tool`, when it dispatches on an `action`.
pub fn manager(tool: &str) -> Option<&'static Manager> {
    MANAGERS.iter().find(|m| m.tool == tool)
}

impl Manager {
    /// The canonical action `raw` names, as the handler resolves it, and
    /// what it runs. `None` when the handler would not accept it.
    pub fn resolve(&self, raw: &str) -> Option<(&'static str, Target)> {
        let name: String = match self.norm {
            Norm::Exact => raw.to_string(),
            Norm::Trim => raw.trim().to_string(),
            Norm::TrimLower => raw.trim().to_ascii_lowercase(),
            Norm::Custom(f) => f(raw)?.to_string(),
        };
        let name =
            self.aliases.iter().find(|(a, _)| *a == name).map(|(_, to)| (*to).to_string()).unwrap_or(name);
        if let Some((a, t)) = self.actions.iter().find(|(a, _)| *a == name) {
            return Some((a, *t));
        }
        self.refused_prefixes.iter().find(|p| name.starts_with(**p)).map(|p| (*p, Refused))
    }

    /// The action names, for messages.
    fn action_names(&self) -> Vec<&'static str> {
        self.actions.iter().filter(|(_, t)| *t != Refused).map(|(a, _)| *a).collect()
    }
}

/// The gate key of an action with no standalone tool.
pub fn own_key(tool: &str, action: &str) -> String {
    format!("{tool}:{action}")
}

/// One call of a consolidated tool, resolved.
#[derive(Debug, Clone)]
pub struct Route {
    pub manager: &'static str,
    pub action: &'static str,
    pub target: Target,
    /// The arguments the gates of [`Route::gate_name`] see: the action's
    /// `params` (an empty object when absent) for a standalone or nested
    /// tool, the whole call for an own key.
    pub args: Value,
}

impl Route {
    /// The name the profile, policy and approval gates apply under, besides
    /// the consolidated tool's own: the standalone tool or `tool:action`.
    /// `None` for a nested call (it is governed on its own) and a refused
    /// action.
    pub fn gate_name(&self) -> Option<String> {
        match self.target {
            Standalone(t) => Some(t.to_string()),
            Own => Some(own_key(self.manager, self.action)),
            Nested(_) | Refused => None,
        }
    }

    /// What `tool_calls.action_tool` records for the call.
    pub fn recorded(&self) -> Option<String> {
        match self.target {
            Standalone(t) | Nested(t) => Some(t.to_string()),
            Own => Some(own_key(self.manager, self.action)),
            Refused => None,
        }
    }

    /// An own action whose handler always takes its own human approval (see
    /// [`Manager::handler_gated`]).
    pub fn handler_gated(&self) -> bool {
        self.target == Own && manager(self.manager).is_some_and(|m| m.handler_gated.contains(&self.action))
    }

    /// The standalone tool whose definition (gate flags, projection) applies.
    pub fn standalone(&self) -> Option<&'static str> {
        match self.target {
            Standalone(t) => Some(t),
            _ => None,
        }
    }
}

/// Resolve a call of `tool`. `Ok(None)` only for a tool that is neither in
/// [`MANAGERS`] nor in [`DOORS`]. For a tool in the table, an `action` that
/// is unknown, not a string, or missing with no default is refused here,
/// before anything runs; a missing or `null` action is the default.
pub fn route(tool: &str, args: &Value) -> Result<Option<Route>, UaError> {
    if let Some(d) = DOORS.iter().find(|d| d.tool == tool) {
        return Ok(Some(Route {
            manager: d.tool,
            action: d.action,
            target: Standalone(d.target),
            args: (d.args)(args),
        }));
    }
    let Some(m) = manager(tool) else { return Ok(None) };
    // A tool in the table always routes or is refused here: `null` means
    // absent (as the handlers' `Option` actions read it), absent means the
    // default action, and anything that is not a string never reaches a
    // handler, so no future handler can fall back to a default the
    // registry did not gate.
    let raw = match args.get("action") {
        None | Some(Value::Null) => match m.default_action {
            Some(d) => d,
            None => return Err(UaError::invalid(format!("{tool}: action is required"))),
        },
        Some(Value::String(s)) => s.as_str(),
        Some(other) => {
            return Err(UaError::invalid(format!("{tool}: action must be a string, not {other}")));
        }
    };
    let Some((action, target)) = m.resolve(raw) else {
        return Err(UaError::invalid(format!(
            "{tool}: unknown action {raw:?}; it is one of {}",
            m.action_names().join(", ")
        )));
    };
    let args = match target {
        Standalone(_) | Nested(_) => match args.get("params") {
            None | Some(Value::Null) => json!({}),
            Some(p) => p.clone(),
        },
        Own | Refused => args.clone(),
    };
    Ok(Some(Route { manager: m.tool, action, target, args }))
}

/// A standalone tool that is a second door to another tool's operation: it
/// runs the same creation path on arguments it maps. A call of it passes the
/// other tool's profile entry, policy rules and approval gate too, on the
/// mapped arguments, exactly as a consolidated tool's routed action does.
pub struct Door {
    pub tool: &'static str,
    /// The operation's name in messages.
    pub action: &'static str,
    /// The tool whose gates apply.
    pub target: &'static str,
    /// The door's arguments as the target tool's arguments. The door's
    /// handler builds its call from the same mapping.
    pub args: fn(&Value) -> Value,
}

/// Every door to another tool's operation.
pub const DOORS: &[Door] =
    &[Door { tool: "handoff", action: "create", target: "delegate", args: delegation::handoff_as_delegate }];

/// The canonical action of a call of `tool`, as the registry routed it:
/// each consolidated tool's handler dispatches on this, so the registry's
/// gates and the handler always agree on which action runs, including the
/// action of a call that names none.
pub fn action_of(tool: &str, raw: Option<&str>) -> Result<&'static str, UaError> {
    let m = manager(tool).ok_or_else(|| UaError::internal(format!("{tool} is not in routes::MANAGERS")))?;
    let raw = match raw.or(m.default_action) {
        Some(r) => r,
        None => return Err(UaError::invalid(format!("{tool}: action is required"))),
    };
    m.resolve(raw).map(|(a, _)| a).ok_or_else(|| {
        UaError::invalid(format!(
            "{tool}: unknown action {raw:?}; it is one of {}",
            m.action_names().join(", ")
        ))
    })
}

/// The error of a handler that has no arm for an action the table resolves.
/// The `routes` tests call every action of every tool and fail on it.
pub fn unhandled(tool: &str, action: &str) -> UaError {
    UaError::internal(format!("{tool}: action {action:?} is in routes::MANAGERS but has no handler"))
}

/// The name an `approval_tools` entry or a plain policy `tool` stands for.
/// A `tool:action` spelling of an action that has a standalone tool reads as
/// that tool (`plan_manage:delete` is `plan_delete`), and an alias spelling
/// of an own action as its canonical key, so the operator's intent holds;
/// [`check_gate_name`] still flags the spelling. Anything else is as written.
pub fn canonical_gate_name(entry: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    let Some((tool, action)) = entry.split_once(':') else { return Cow::Borrowed(entry) };
    let Some(m) = manager(tool) else { return Cow::Borrowed(entry) };
    match m.resolve(action) {
        Some((_, Standalone(t) | Nested(t))) => Cow::Borrowed(t),
        Some((a, Own)) if a != action => Cow::Owned(own_key(tool, a)),
        _ => Cow::Borrowed(entry),
    }
}

/// Whether `approval_tools` gates `name` (a tool or a `tool:action` key).
pub fn listed(cfg: &ua_core::Config, name: &str) -> bool {
    cfg.approval_tools.iter().any(|t| canonical_gate_name(t) == name)
}

/// Every `tool:action` gate key (actions with no standalone tool).
pub fn own_keys() -> impl Iterator<Item = String> {
    MANAGERS
        .iter()
        .flat_map(|m| m.actions.iter().filter(|(_, t)| *t == Own).map(move |(a, _)| own_key(m.tool, a)))
}

/// Whether `name` is something a gate can name: a registered tool, a tool
/// a disabled feature leaves out, or a `tool:action` key. Otherwise the
/// reason, with the name to use when `name` is a `tool:action` spelling of
/// an action that has a standalone tool.
pub fn check_gate_name(name: &str) -> Result<(), String> {
    if crate::builtin_registry_shared().get(name).is_some()
        || crate::compiled_out_tools().any(|(t, _)| t == name)
    {
        return Ok(());
    }
    let Some((tool, action)) = name.split_once(':') else {
        return Err(format!("{name}: no such tool"));
    };
    let Some(m) = manager(tool) else {
        return Err(format!("{name}: {tool} takes no action argument"));
    };
    match m.resolve(action) {
        Some((a, Own)) if a == action => Ok(()),
        Some((a, Own)) => Err(format!("{name}: read as {}; write that", own_key(tool, a))),
        Some((_, Standalone(t) | Nested(t))) => {
            Err(format!("{name}: that action is gated as {t} (this entry is read as {t}; write {t})"))
        }
        Some((_, Refused)) => Err(format!("{name}: {tool} refuses that action")),
        None => Err(format!("{name}: {tool} has no action {action:?}")),
    }
}

/// Whether a policy `tool` pattern is a plain name (no glob characters), so
/// it can be checked with [`check_gate_name`].
pub fn is_plain_name(pattern: &str) -> bool {
    !pattern.contains(['*', '?', '[', ']', '{', '}'])
}

#[cfg(test)]
mod tests {
    //! The table must decide every action of every tool that dispatches on
    //! one: these fail when a tool gains an action, or a tool gains an
    //! `action` argument, without an entry in [`MANAGERS`].

    use std::collections::BTreeSet;

    use super::*;
    use crate::families::{delegation, observability, plans};

    fn registered(name: &str) -> bool {
        crate::builtin_registry_shared().get(name).is_some()
            || crate::compiled_out_tools().any(|(t, _)| t == name)
    }

    fn table_actions(tool: &str) -> BTreeSet<&'static str> {
        manager(tool).unwrap().actions.iter().map(|(a, _)| *a).collect()
    }

    #[test]
    fn every_tool_with_an_action_argument_is_in_the_table() {
        let reg = crate::builtin_registry_shared();
        let with_action: BTreeSet<&str> = reg
            .all()
            .filter(|d| d.input_schema["properties"].get("action").is_some())
            .map(|d| d.name)
            .collect();
        let table: BTreeSet<&str> =
            MANAGERS.iter().map(|m| m.tool).filter(|t| reg.get(t).is_some()).collect();
        assert_eq!(
            with_action, table,
            "a tool that dispatches on `action` needs an entry in routes::MANAGERS deciding each action"
        );
        for m in MANAGERS {
            assert!(registered(m.tool), "{} is not a tool", m.tool);
        }
    }

    #[test]
    fn every_manager_action_has_a_mapping_decision() {
        // Tools that resolve actions with their own canonicalizer and list:
        // the table must name exactly that list. Every other tool here
        // dispatches on `action_of`, so the table is its list by
        // construction, and the `manager_gates` tests run every action of
        // every tool to check each reaches a handler arm.
        let own = |list: &[&'static str]| list.iter().copied().collect::<BTreeSet<_>>();
        let cases: [(&str, BTreeSet<&str>); 4] = [
            ("plan_manage", own(&plans::ACTIONS)),
            ("delegation_manage", own(&delegation::ACTIONS)),
            ("observability_manage", own(&observability::ACTIONS)),
            ("coordination_manage", own(messaging::COORDINATION_ACTIONS)),
        ];
        for m in MANAGERS {
            if !cases.iter().any(|(t, _)| *t == m.tool) {
                assert!(
                    !matches!(m.norm, Norm::Custom(_)),
                    "{}: a custom canonicalizer needs its action list compared here",
                    m.tool
                );
            }
        }
        for (tool, actions) in cases {
            assert_eq!(table_actions(tool), actions, "{tool}: every action needs a mapping decision");
        }
        // Every action the table names resolves to itself, and every target
        // is a tool this hub serves; an own key names no registered tool.
        for m in MANAGERS {
            for (a, t) in m.actions {
                assert_eq!(m.resolve(a), Some((*a, *t)), "{}:{a}", m.tool);
                match t {
                    Standalone(s) | Nested(s) => {
                        assert!(registered(s), "{}:{a} -> {s} is not a tool", m.tool)
                    }
                    Own => assert!(!registered(&own_key(m.tool, a))),
                    Refused => {}
                }
            }
            for (alias, to) in m.aliases {
                assert!(m.actions.iter().any(|(a, _)| a == to), "{}: alias {alias} -> {to}", m.tool);
            }
        }
    }

    #[test]
    fn a_call_with_no_action_resolves_to_the_handlers_default() {
        // The handler's default comes from its argument struct: a required
        // `action` has none; a serde default shows in the schema; an optional
        // `action` with no schema default is resolved by `action_of`, i.e.
        // by this table, so the table must have one.
        let reg = crate::builtin_registry_shared();
        for m in MANAGERS {
            let Some(def) = reg.get(m.tool) else { continue };
            let schema = &def.input_schema;
            let required = schema["required"].as_array().is_some_and(|r| r.iter().any(|v| v == "action"));
            let schema_default = schema["properties"]["action"].get("default").and_then(Value::as_str);
            match (required, schema_default) {
                (true, _) => assert_eq!(m.default_action, None, "{}: action is required", m.tool),
                (false, Some(d)) => assert_eq!(m.default_action, Some(d), "{}: handler default", m.tool),
                (false, None) => {
                    assert!(m.default_action.is_some(), "{}: optional action needs a default", m.tool)
                }
            }
            // A call with none routes exactly as one naming the default.
            // (With no default, a call with none is refused.)
            let none = route(m.tool, &json!({})).ok().flatten().map(|r| (r.action, r.target));
            let named = m.default_action.map(|d| route(m.tool, &json!({ "action": d })).unwrap().unwrap());
            assert_eq!(none, named.map(|r| (r.action, r.target)), "{}", m.tool);
            assert_eq!(
                action_of(m.tool, None).ok(),
                m.default_action.and_then(|d| m.resolve(d)).map(|(a, _)| a)
            );
        }
    }

    #[test]
    fn a_tool_in_the_table_always_routes_or_is_refused() {
        // With a default (oauth_device_manage) and without (plan_manage).
        for tool in ["oauth_device_manage", "plan_manage"] {
            for bad in [json!(123), json!(true), json!({}), json!([]), json!(["list"])] {
                let e = route(tool, &json!({ "action": bad })).unwrap_err();
                assert_eq!(e.code(), "invalid_argument", "{tool} {bad}");
                assert!(e.to_string().contains("must be a string"), "{e}");
            }
        }
        // `null` is absent: the default where there is one, else refused.
        let r = route("oauth_device_manage", &json!({ "action": null })).unwrap().unwrap();
        assert_eq!(r.gate_name().as_deref(), Some("oauth_device_manage:list"));
        assert!(route("plan_manage", &json!({ "action": null })).is_err());
        for m in MANAGERS {
            for args in [json!({}), json!({ "action": null }), json!({ "action": 1 })] {
                match route(m.tool, &args) {
                    Ok(Some(_)) => {
                        assert!(m.default_action.is_some() && !args["action"].is_number(), "{}", m.tool)
                    }
                    Ok(None) => panic!("{} {args} routed to nothing", m.tool),
                    Err(_) => assert!(m.default_action.is_none() || args["action"].is_number(), "{}", m.tool),
                }
            }
        }
        assert!(route("task_add", &json!({ "action": 1 })).unwrap().is_none());
    }

    #[test]
    fn doors_name_registered_tools_and_map_their_arguments() {
        for d in DOORS {
            assert!(registered(d.tool) && registered(d.target), "{} -> {}", d.tool, d.target);
            assert!(manager(d.tool).is_none(), "{} is a door, not a manager", d.tool);
        }
        let mapped = delegation::handoff_as_delegate(&json!({
            "task_spec": "s", "to_agent": "b", "agent": "a", "deadline": null, "priority": "high"
        }));
        assert_eq!(
            mapped,
            json!({ "task_spec": "s", "to_agent": "b", "from_agent": "a", "priority": "high", "callback": "none" })
        );
        let reg = crate::builtin_registry_shared();
        reg.get("delegate").unwrap().check_args(&mapped).unwrap();
    }

    #[test]
    fn a_misspelled_key_reads_as_the_standalone_tool() {
        assert_eq!(canonical_gate_name("plan_manage:delete"), "plan_delete");
        assert_eq!(canonical_gate_name("plan_manage:PLAN_DELETE"), "plan_delete");
        assert_eq!(canonical_gate_name("export_data:manifest"), "export_migration_manifest");
        assert_eq!(canonical_gate_name("delegation_manage:delegate_retry"), "delegation_manage:retry");
        assert_eq!(canonical_gate_name("plan_manage:close"), "plan_manage:close");
        assert_eq!(canonical_gate_name("plan_delete"), "plan_delete");
        assert_eq!(canonical_gate_name("plan_manage:nope"), "plan_manage:nope");
        assert!(
            check_gate_name("delegation_manage:delegate_retry")
                .unwrap_err()
                .contains("delegation_manage:retry")
        );
    }

    #[test]
    fn a_standalone_target_takes_the_same_arguments() {
        // A standalone target runs the same handler on `params`; its schema
        // must not have an `action` of its own.
        let reg = crate::builtin_registry_shared();
        for m in MANAGERS {
            for (a, t) in m.actions {
                if let Standalone(s) = t
                    && let Some(def) = reg.get(s)
                {
                    assert!(def.input_schema["properties"].get("action").is_none(), "{}:{a} -> {s}", m.tool);
                }
            }
        }
    }

    #[test]
    fn legacy_and_alias_spellings_resolve_like_the_handler() {
        let r = |tool: &str, action: &str| route(tool, &json!({ "action": action, "params": { "x": 1 } }));
        let gate = |tool: &str, action: &str| r(tool, action).unwrap().unwrap().gate_name();
        assert_eq!(gate("plan_manage", "delete").as_deref(), Some("plan_delete"));
        assert_eq!(gate("plan_manage", " Plan_Delete ").as_deref(), Some("plan_delete"));
        assert_eq!(gate("plan_manage", "claim").as_deref(), Some("plan_step_claim"));
        assert_eq!(gate("plan_manage", "close").as_deref(), Some("plan_manage:close"));
        assert_eq!(gate("delegation_manage", "delegate").as_deref(), Some("delegate"));
        assert_eq!(gate("delegation_manage", "delegate_cancel").as_deref(), Some("delegate_cancel"));
        assert_eq!(gate("delegation_manage", "retry").as_deref(), Some("delegation_manage:retry"));
        assert_eq!(gate("observability_manage", "perf_summary").as_deref(), Some("perf_summary"));
        assert_eq!(gate("export_data", "EXPORT_TASKS").as_deref(), Some("export_tasks"));
        assert_eq!(gate("export_data", "manifest"), None, "a nested call is governed by itself");
        assert_eq!(gate("skill_registry", "source_add").as_deref(), Some("skill_registry:source_add"));
        assert_eq!(gate("skill_registry", "source_discover"), None);
        assert_eq!(gate("coordination_manage", " agent_list").as_deref(), Some("agent_list"));
        // The standalone payload is `params`; an own key binds the call.
        assert_eq!(r("plan_manage", "delete").unwrap().unwrap().args, json!({ "x": 1 }));
        let own = r("plan_manage", "close").unwrap().unwrap();
        assert_eq!(own.args, json!({ "action": "close", "params": { "x": 1 } }));
        // Defaults, and what is not this table's to refuse.
        let d = route("config_revision_manage", &json!({})).unwrap().unwrap();
        assert_eq!(d.gate_name().as_deref(), Some("config_revision_manage:list"));
        assert!(route("plan_manage", &json!({})).is_err(), "no default: an action is required");
        assert!(route("task_add", &json!({ "action": "x" })).unwrap().is_none());
        assert!(route("plan_manage", &json!({ "action": "explode" })).is_err());
        assert!(route("config_revision_manage", &json!({ "action": "List" })).is_err());
    }

    #[test]
    fn gate_names_are_checked() {
        assert!(check_gate_name("plan_delete").is_ok());
        assert!(check_gate_name("plan_manage:close").is_ok());
        assert!(check_gate_name("delegation_manage:retry").is_ok());
        let e = check_gate_name("plan_manage:delete").unwrap_err();
        assert!(e.contains("gated as plan_delete"), "{e}");
        assert!(check_gate_name("plan_manage:nope").is_err());
        assert!(check_gate_name("task_add:x").is_err());
        assert!(check_gate_name("no_such_tool").is_err());
        assert!(own_keys().any(|k| k == "coordination_manage:queue_park"));
    }
}
