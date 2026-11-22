//! Capability answers: can this agent do this task, and what does this hub
//! offer at all.
//!
//! Tools: `check_agent_capability` (does an agent's profile expose the tools
//! a task says it needs) and `capability_catalog` (a read-only inventory of
//! agents, tools by family, programs, workflows, skills, health, boundaries
//! and what the MCP server supports, with an optional dispatch-readiness
//! check). Neither writes, installs or opens an approval.
//!
//! A task states its needs as `[requires: tool_a, tool_b]` (or
//! `[requires-tools: ...]`) in its notes; names are case-folded. Nothing is
//! inferred from prose. An agent's allowed tools are what its default profile
//! exposes, the same rule the call wrapper enforces.
//!
//! Readiness (the catalog's `prerequisites`) adds what dispatch needs besides
//! tools: an identity the hub can authenticate (an active token or a
//! configured profile) and somewhere to run (a configured harness, or a live
//! node the agent owns). Each gap is a `missing_config` entry
//! `{gate, action, detail}`.
//!
//! Visibility: the catalog's `boundaries`, `health` and agents' `host` are a
//! map of the hub, shown only to operators (humans, lifecycle operators, the
//! coordinator and operator profiles). Everyone else gets them as null or
//! absent, named in `redacted`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{Config, Profile, UaError, UaResult};

use super::agents;
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, blocking, tool};
use ua_org::authz::{Authority, Authz};

const MAX_SKILLS: usize = 100;

/// Tool names a task's notes say it needs.
pub fn required_tools(notes: &str) -> BTreeSet<String> {
    let lower = notes.to_ascii_lowercase();
    let mut out = BTreeSet::new();
    for marker in ["[requires:", "[requires-tools:"] {
        let mut from = 0;
        while let Some(i) = lower[from..].find(marker) {
            let start = from + i + marker.len();
            let rest = &notes[start..];
            let end = rest.find([']', '\n']).unwrap_or(rest.len());
            if rest[end..].starts_with(']') {
                for name in rest[..end].split(',').map(str::trim).filter(|n| !n.is_empty()) {
                    out.insert(name.to_ascii_lowercase());
                }
            }
            from = start;
        }
    }
    out
}

/// Whether `label` is an identity this hub knows: a registered agent, an
/// issued token, a configured profile, or a human.
fn known_label(c: &Connection, cfg: &Config, label: &str) -> UaResult<bool> {
    if cfg.is_human(label) || cfg.profiles.contains_key(label) {
        return Ok(true);
    }
    let known: Option<i64> =
        c.query_row("SELECT known FROM agents WHERE label = ?1", [label], |r| r.get(0)).optional()?;
    if known == Some(1) {
        return Ok(true);
    }
    let token: Option<i64> = c
        .query_row(
            "SELECT 1 FROM agent_tokens WHERE agent_label = ?1 AND status = 'active' LIMIT 1",
            [label],
            |r| r.get(0),
        )
        .optional()?;
    Ok(token.is_some())
}

/// What one agent may call: `None` when its profile is unrestricted.
fn allowed_tools(reg: &Registry, profile: Profile) -> Option<BTreeSet<String>> {
    if profile == Profile::Coordinator {
        return None;
    }
    Some(reg.all().filter(|t| profile.allows_tool(t.name)).map(|t| t.name.to_string()).collect())
}

fn check(c: &Connection, hub: &Hub, reg: &Registry, task_id: i64, agent: &str) -> UaResult<Value> {
    let agent = agent.trim();
    if agent.is_empty() || !known_label(c, hub.cfg(), agent)? {
        return Err(UaError::invalid(format!("agent_label {agent:?} is not a known agent")));
    }
    let notes: Option<Option<String>> =
        c.query_row("SELECT notes FROM tasks WHERE id = ?1", [task_id], |r| r.get(0)).optional()?;
    let Some(notes) = notes else { return Err(UaError::not_found(format!("no task with id {task_id}"))) };
    let required = required_tools(notes.as_deref().unwrap_or(""));
    let registered: BTreeSet<String> = reg.all().map(|t| t.name.to_string()).collect();
    let unknown: Vec<&String> = required.iter().filter(|t| !registered.contains(*t)).collect();
    let profile = crate::sessions::default_profile(hub, agent);
    let allowed = allowed_tools(reg, profile);
    let missing: Vec<&String> = match &allowed {
        None => Vec::new(),
        Some(a) => required.iter().filter(|t| registered.contains(*t) && !a.contains(*t)).collect(),
    };
    Ok(json!({
        "task_id": task_id,
        "agent": agent,
        "profile": profile.as_str(),
        "capable": missing.is_empty() && unknown.is_empty(),
        "required_tools": required,
        "allowed_tools": allowed,
        "missing_tools": missing,
        "unknown_tools": unknown,
    }))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckArgs {
    /// The task whose `[requires: ...]` notes are checked.
    pub task_id: i64,
    /// The candidate agent.
    pub agent_label: String,
}

async fn check_agent_capability(ctx: ToolCtx, a: CheckArgs) -> UaResult<Value> {
    let hub = ctx.hub.clone();
    ctx.hub
        .db()
        .read_async(move |c| check(c, &hub, crate::builtin_registry_shared(), a.task_id, &a.agent_label))
        .await
}

// --- the catalog ----------------------------------------------------------------

/// Product skills in the workspace (`.claude/skills/*/SKILL.md`), by name.
fn skills(workspace: &Path) -> Vec<Value> {
    let root = workspace.join(".claude").join("skills");
    let Ok(dir) = std::fs::read_dir(&root) else { return Vec::new() };
    let mut names: Vec<String> = dir
        .filter_map(Result::ok)
        .filter(|e| e.path().join("SKILL.md").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    names
        .into_iter()
        .take(MAX_SKILLS)
        .map(|n| json!({ "name": n, "path": format!(".claude/skills/{n}/SKILL.md") }))
        .collect()
}

/// What this hub's MCP server supports, and what each client gets from it.
fn mcp_surface() -> Value {
    let caps = json!({
        "tool_annotations": { "status": "supported", "summary": "readOnlyHint and destructiveHint on every tool" },
        "structured_outputs": { "status": "supported", "summary": "every result and error is structured JSON" },
        "elicitation": {
            "status": "unsupported",
            "fallback_behavior": "an approval-gated call returns approval_required with an approval_id; a human \
                resolves it in /ui or with approval_resolve, then the identical call is retried",
        },
        "progress": { "status": "unsupported", "fallback_behavior": "long calls answer when done" },
        "resource_subscriptions": {
            "status": "unsupported",
            "fallback_behavior": "poll the tools, or read GET /api/events/stream (server-sent events)",
        },
    });
    let clients = [
        ("claude", "Claude Code / Claude Desktop", "Interactive developer CLI and desktop assistant"),
        ("codex", "Codex", "Autonomous coding and test automation worker"),
        ("agy", "Google Antigravity", "Agentic IDE and terminal orchestration client"),
        ("cursor", "Cursor", "IDE pair programmer client"),
    ];
    if !cfg!(feature = "mcp-server") {
        // Built without the hub's MCP server: no /mcp route, no `ua mcp`.
        return json!({
            "server": {
                "transports": [],
                "endpoint": null,
                "status": "not_built",
                "note": "built without the mcp-server feature: this hub serves no MCP (no /mcp route, no `ua mcp`); \
                    tools are reachable through the JSON API at /api/tools",
            },
            "clients": [],
        });
    }
    json!({
        "server": {
            "transports": ["stdio", "streamable_http"],
            "endpoint": "/mcp",
            "capabilities": caps,
        },
        "clients": clients.iter().map(|(id, name, role)| json!({
            "client_id": id,
            "client_name": name,
            "primary_role": role,
            "supported_transports": ["streamable_http", "stdio"],
            "capabilities": caps,
        })).collect::<Vec<_>>(),
    })
}

/// Tools a disabled Cargo feature leaves out of this build, and why:
/// `[{tool, feature}]`, empty in a default build.
fn compiled_out() -> Value {
    crate::compiled_out_tools().map(|(tool, feature)| json!({ "tool": tool, "feature": feature })).collect()
}

/// Configuration-gated health, from configuration alone (no probes).
fn health(cfg: &Config) -> Value {
    let status = |on: bool| if on { "LIVE" } else { "DORMANT" };
    json!({
        "hub_auth": { "status": status(cfg.enforce_auth), "gate": "enforce_auth" },
        "approval_queue": { "status": status(!cfg.approval_tools.is_empty()), "gate": "approval_tools" },
        "vault": { "status": status(cfg.vault_path.is_some()), "gate": "vault_path" },
        "search_provider": { "status": "LIVE", "gate": format!("search_provider={}", cfg.search_provider) },
        "dispatch_harnesses": { "status": status(!cfg.harnesses.is_empty()), "gate": "harnesses" },
        "node_queue_sweep": { "status": status(cfg.node_wait_sweep_s > 0), "gate": "node_wait_sweep_s" },
    })
}

/// What dispatching work to `agent` needs besides tools, as
/// `{gate, action, detail}` entries; empty when nothing is missing.
fn missing_config(c: &Connection, cfg: &Config, agent: &str) -> UaResult<Vec<Value>> {
    let mut missing = Vec::new();
    let token: Option<i64> = c
        .query_row(
            "SELECT 1 FROM agent_tokens WHERE agent_label = ?1 AND status = 'active' \
             AND (expires_at IS NULL OR expires_at > ?2) LIMIT 1",
            rusqlite::params![agent, ua_core::time::now()],
            |r| r.get(0),
        )
        .optional()?;
    let static_token = cfg.static_tokens().iter().any(|(l, _)| l == agent);
    if token.is_none() && !static_token && !cfg.profiles.contains_key(agent) {
        missing.push(json!({
            "gate": "agent_identity",
            "action": format!("issue {agent} a token (`ua token issue` or agent_token_issue) or give it a profile in [profiles]"),
            "detail": format!("{agent} has no active token and no configured profile, so it cannot authenticate"),
        }));
    }
    if cfg.harnesses.is_empty() {
        let now = jiff::Timestamp::now();
        let mut stmt = c.prepare(
            "SELECT last_heartbeat, heartbeat_floor FROM nodes WHERE agent = ?1 AND retired_at IS NULL",
        )?;
        let mut live = false;
        for row in
            stmt.query_map([agent], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?)))?
        {
            let (last, floor) = row?;
            if super::nodes::liveness(last.as_deref(), floor.as_deref(), false, now).live {
                live = true;
                break;
            }
        }
        if !live {
            missing.push(json!({
                "gate": "executor",
                "action": format!("configure a [harnesses.<name>] entry, or run a node registered by {agent}"),
                "detail": format!("no harness is configured and {agent} has no live, non-retired node"),
            }));
        }
    }
    Ok(missing)
}

/// Whether `caller` sees the catalog's hub map (boundaries, health, hosts).
/// Whether `caller` may see hub boundaries (the program allowlist among them).
/// An operator (a verified human); a profile grants nothing.
pub(crate) fn is_operator(caller: &ua_core::Caller, cfg: &Config) -> bool {
    Authz::new(cfg).holds(caller, &[Authority::Operator], ua_core::DEFAULT_ORG)
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogArgs {
    /// With agent_label: check whether that agent can take this task.
    pub task_id: Option<i64>,
    /// With task_id: the candidate agent.
    pub agent_label: Option<String>,
}

async fn capability_catalog(ctx: ToolCtx, a: CatalogArgs) -> UaResult<Value> {
    let check_pair = match (a.task_id, a.agent_label.as_deref().map(str::trim).filter(|s| !s.is_empty())) {
        (None, None) => None,
        (Some(t), Some(l)) => Some((t, l.to_string())),
        _ => {
            return Err(UaError::invalid(
                "pass both task_id and agent_label to check dispatch prerequisites",
            ));
        }
    };
    let hub = ctx.hub.clone();
    let cfg = ctx.hub.cfg().clone();
    let operator = is_operator(&ctx.caller, &cfg);
    let reg = crate::builtin_registry_shared();
    let mut families: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for t in reg.all() {
        families.entry(t.family).or_default().push(t.name);
    }
    for v in families.values_mut() {
        v.sort_unstable();
    }
    let mut tools: Vec<&str> = reg.all().map(|t| t.name).collect();
    tools.sort_unstable();
    let gated: Vec<&str> = {
        let mut g: Vec<&str> = reg
            .all()
            .filter(|t| {
                t.always_gated || t.gates_in_handler || cfg.approval_tools.iter().any(|a| a == t.name)
            })
            .map(|t| t.name)
            .collect();
        g.sort_unstable();
        g
    };
    let (agents_list, prerequisites) = ctx
        .hub
        .db()
        .read_async(move |c| {
            let agents: Vec<Value> = agents::list_agents(c)?
                .into_iter()
                .map(|a| {
                    let mut row = json!({
                        "label": a["label"], "status": a["status"], "kind": a["kind"], "known": a["known"],
                    });
                    if operator {
                        row["host"] = a["host"].clone();
                    }
                    row
                })
                .collect();
            let pre = match check_pair {
                None => None,
                Some((t, l)) => {
                    let mut m = check(c, &hub, crate::builtin_registry_shared(), t, &l)?;
                    let missing = missing_config(c, hub.cfg(), &l)?;
                    m["ready"] = json!(m["capable"] == json!(true) && missing.is_empty());
                    m["missing_config"] = json!(missing);
                    Some(m)
                }
            };
            Ok((agents, pre))
        })
        .await?;
    let cfg2 = cfg.clone();
    let (workflows, skills_found) = blocking(move || {
        let wf: Vec<Value> = super::workflows::engine::list_definitions(&cfg2)
            .into_iter()
            .map(|w| json!({ "name": w["name"], "description": w["description"] }))
            .collect();
        Ok((wf, skills(&cfg2.workspace_root())))
    })
    .await?;
    let clis = cfg.shell_allowlist();
    let (health, boundaries, redacted) = if operator {
        let boundaries = json!({
            "workspace": cfg.workspace_root().display().to_string(),
            "vault_write_dirs": cfg.vault_write_dirs,
            "approval_gated_tools": gated,
            "shell_allowlist": clis,
        });
        (health(&cfg), boundaries, json!([]))
    } else {
        (Value::Null, Value::Null, json!(["boundaries", "health", "agents.host", "clis"]))
    };
    // The program allowlist is `boundaries.shell_allowlist` again: the same
    // redaction applies.
    let clis = if operator { json!(clis) } else { Value::Null };
    Ok(json!({
        "read_only": true,
        "install_is_explicit": true,
        "approval_gated": true,
        "versions": { "ua_rust": env!("CARGO_PKG_VERSION") },
        "build_features": crate::build_features(),
        "compiled_out_tools": compiled_out(),
        "agents": agents_list,
        "mcp_tools": tools,
        "tool_families": families,
        "mcp_client_matrix": mcp_surface(),
        "clis": clis,
        "skills": skills_found,
        "workflows": workflows,
        "harnesses": cfg.harnesses.keys().collect::<Vec<_>>(),
        "health": health,
        "boundaries": boundaries,
        "redacted": redacted,
        "prerequisites": prerequisites,
    }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "check_agent_capability",
            "Check whether a candidate agent can take a task: the task's [requires: tool_a, tool_b] notes \
             against the tools the agent's default profile exposes. Nothing is inferred from prose. Returns \
             {task_id, agent, profile, capable, required_tools, allowed_tools (null when unrestricted), \
             missing_tools, unknown_tools (not registered on this hub)}.",
            check_agent_capability,
        )
        .read_only()
        .family("capability"),
    );
    r.add(
        tool(
            "capability_catalog",
            "Read-only inventory of this hub: agents, every tool by family, allowlisted programs, harnesses, \
             workflows, workspace skills, configuration health, boundaries (workspace, vault write dirs, \
             approval-gated tools), what the MCP server supports per client, the optional Cargo features this \
             build has (build_features: code_intel, readability, mcp_gateway, mcp_server, embeddings) and the \
             tools a disabled feature leaves out (compiled_out_tools: [{tool, feature}]). Boundaries, health, agent \
             hosts and the allowlisted programs (clis) are shown to operators only; for everyone else they \
             are null or absent and named in `redacted`. With task_id and agent_label it also reports whether \
             that agent is ready for that task: prerequisites {capable, ready, missing_config: [{gate, action, \
             detail}]}, where gate is \
             agent_identity (no active token or profile) or executor (no harness and no live owned node). Never \
             installs, writes or opens an approval.",
            capability_catalog,
        )
        .read_only()
        .family("capability"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_come_only_from_markers() {
        let notes =
            "Port it. [requires: FS_READ, run_cmd]\n[REQUIRES-TOOLS: Git_Diff_Staged ]\n[requires: broken";
        let got: Vec<String> = required_tools(notes).into_iter().collect();
        assert_eq!(got, ["fs_read", "git_diff_staged", "run_cmd"]);
        assert!(required_tools("needs fs_read").is_empty());
    }
}
