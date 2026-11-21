//! Registry-wide approval contracts: no gated call parks a plaintext secret,
//! and every tool whose handler asks the approval gate itself is marked, so
//! `POST /api/approvals/request` answers 409 for it.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Map, Value, json};
use ua_core::{Caller, Config, identity::Transport};
use ua_tools::{ApprovalRequest, Hub, ToolDef, builtin_registry};

/// Argument names that carry a secret value.
fn secret_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "token",
        "secret",
        "secrets",
        "password",
        "passphrase",
        "api_key",
        "private_key",
        "credential",
        "credentials",
        "value",
        "new_value",
    ]
    .iter()
    .any(|s| n == *s || n.ends_with(&format!("_{s}")))
}

/// Every property name in a schema, nested objects, items and `$defs` too.
fn property_names(schema: &Value, out: &mut Vec<String>) {
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        for (k, sub) in props {
            out.push(k.clone());
            property_names(sub, out);
        }
    }
    for key in ["items", "additionalProperties"] {
        if let Some(sub) = schema.get(key) {
            property_names(sub, out);
        }
    }
    for key in ["anyOf", "oneOf", "allOf"] {
        for sub in schema.get(key).and_then(Value::as_array).into_iter().flatten() {
            property_names(sub, out);
        }
    }
    for sub in schema.get("$defs").and_then(Value::as_object).into_iter().flat_map(|d| d.values()) {
        property_names(sub, out);
    }
}

fn sentinel(field: &str) -> String {
    format!("PLAINTEXT-SECRET-{field}-0123456789abcdef0123456789")
}

/// Arguments for `def` from its schema: every required property, plus every
/// secret-named one, each secret set to a sentinel.
fn arguments(def: &ToolDef) -> Value {
    let schema = &def.input_schema;
    let props = schema.get("properties").and_then(Value::as_object).cloned().unwrap_or_default();
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut out = Map::new();
    for (k, p) in &props {
        if !(required.contains(&k.as_str()) || secret_name(k)) {
            continue;
        }
        let ty = p.get("type").and_then(|t| t.as_str().or_else(|| t.get(0).and_then(Value::as_str)));
        let v = if secret_name(k) {
            json!(sentinel(k))
        } else {
            match ty {
                Some("integer") | Some("number") => json!(1),
                Some("boolean") => json!(false),
                Some("array") => json!([]),
                Some("object") => json!({}),
                _ => json!("x"),
            }
        };
        out.insert(k.clone(), v);
    }
    Value::Object(out)
}

#[test]
fn every_secret_bearing_tool_is_marked_and_projected() {
    let reg = builtin_registry();
    let cfg = {
        let mut c = Config::for_home(std::env::temp_dir());
        c.managed_secret_key =
            Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string().into());
        c
    };
    let mut marked = Vec::new();
    for def in reg.all() {
        let mut names = Vec::new();
        property_names(&def.input_schema, &mut names);
        let secrets: Vec<&String> = names.iter().filter(|n| secret_name(n)).collect();
        if !secrets.is_empty() {
            assert!(def.secret_args, "{} has secret-named arguments {secrets:?} but is not marked", def.name);
        }
        if !def.secret_args {
            continue;
        }
        marked.push(def.name);
        // Gated, it must bind a projection or be decided in its handler.
        let args = arguments(def);
        match def.gate_payload {
            Some(project) => {
                let bound = project(&cfg, &args).to_string();
                assert!(!bound.contains("PLAINTEXT-SECRET"), "{} binds a secret: {bound}", def.name);
            }
            None => assert!(def.handler_decides(&args), "{} would park its secret", def.name),
        }
    }
    marked.sort_unstable();
    assert_eq!(
        marked,
        ["agent_token_issue", "agent_token_rotate", "managed_secret_set", "mcp_server_register"],
        "update this list (and the tool's projection) when a secret argument is added"
    );
}

#[tokio::test]
async fn no_tool_parks_a_plaintext_secret_through_the_request_route() {
    let reg = builtin_registry();
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.managed_secret_key =
        Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string().into());
    // Every tool gated, so every one is requestable unless its handler decides.
    cfg.approval_tools = reg.all().map(|d| d.name.to_string()).collect();
    let hub = Hub::in_memory(cfg).unwrap();
    let human = Caller { kind: ua_core::ActorKind::Human, ..Caller::local("operator", Transport::Http) };
    for def in reg.all() {
        let args = arguments(def);
        if !args.to_string().contains("PLAINTEXT-SECRET") {
            continue;
        }
        if let Ok(ApprovalRequest::Payload { payload: p, .. }) =
            reg.approval_request(&hub, &human, def.name, args).await
        {
            assert!(!p.to_string().contains("PLAINTEXT-SECRET"), "{} parks a secret: {p}", def.name);
        }
    }
}

/// A tool call that takes a handler-gate path: the tool and its arguments.
type GatedCall = (&'static str, Value);

/// Source files that call `approvals::gate(` from a handler, how many call
/// sites each has, and the calls of registered tools that can reach them
/// (tool name and an argument object that takes that path).
fn handler_gate_sites() -> BTreeMap<&'static str, (usize, Vec<GatedCall>)> {
    let action = |a: &str| json!({ "action": a });
    BTreeMap::from([
        (
            "config_revisions.rs",
            (
                1,
                vec![
                    ("config_revision_manage", action("commit")),
                    ("config_revision_manage", action("rollback")),
                ],
            ),
        ),
        ("families/audit/mod.rs", (1, vec![("security_audit", json!({ "remediate": true }))])),
        (
            "families/cycles.rs",
            (
                1,
                vec![
                    ("autonomous_cycle_manage", action("transition")),
                    ("autonomous_cycle_transition", json!({})),
                ],
            ),
        ),
        (
            "families/dispatch/tools.rs",
            (2, vec![("dispatch_task", json!({})), ("dispatch_resume", json!({}))]),
        ),
        (
            "families/managed_secrets.rs",
            (2, vec![("managed_secret_set", json!({})), ("managed_secret_delete", json!({}))]),
        ),
        (
            "families/harness_config/mod.rs",
            (2, vec![("harness_config_publish", json!({})), ("node_config", action("applied"))]),
        ),
        ("families/mcp/gateway.rs", (1, vec![("mcp_gateway", json!({}))])),
        (
            "families/mcp/mod.rs",
            (
                1,
                vec![
                    ("mcp_server_register", json!({})),
                    ("mcp_server_review", json!({})),
                    ("mcp_server_revoke", json!({})),
                ],
            ),
        ),
        (
            "families/node_queue/mod.rs",
            (
                1,
                vec![
                    ("node_dispatch", json!({})),
                    ("coordination_manage", action("node_command_start")),
                    ("coordination_manage", action("node_item_restart")),
                ],
            ),
        ),
        (
            "families/node_queue/relay.rs",
            (2, vec![("node_followup", json!({})), ("node_permission", json!({}))]),
        ),
        ("families/relay/mod.rs", (2, vec![("relay_manage", action("send"))])),
        ("families/skill_registry.rs", (1, vec![("skill_registry", action("publish"))])),
        ("families/tokens.rs", (1, vec![("oauth_device_manage", action("revoke"))])),
        (
            "families/workflows/engine.rs",
            (
                1,
                vec![
                    ("workflow_run", json!({})),
                    ("langgraph_run", json!({})),
                    ("langgraph_workflow_run", json!({})),
                    ("langgraph_progress_note", json!({})),
                    ("routine_fire", json!({})),
                ],
            ),
        ),
        ("families/workspace/shell.rs", (1, vec![("run_cmd", json!({}))])),
        ("families/zulip.rs", (1, vec![("zulip_send_message", json!({}))])),
    ])
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn every_tool_that_gates_in_its_handler_is_marked() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut found = BTreeMap::new();
    for f in files {
        let rel = f.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
        // The registry's own gate and the gate itself are not handler gates.
        if rel == "registry.rs" || rel == "approvals.rs" {
            continue;
        }
        let n = std::fs::read_to_string(&f).unwrap().matches("approvals::gate(").count();
        if n > 0 {
            found.insert(rel, n);
        }
    }
    let sites = handler_gate_sites();
    let expected: BTreeMap<String, usize> = sites.iter().map(|(k, (n, _))| (k.to_string(), *n)).collect();
    assert_eq!(
        found, expected,
        "a handler gate was added or moved: list the file, its call sites and the tools that reach it, and mark \
         those tools (gates_in_handler, handler_gates_with or handler_may_gate)"
    );
    let reg = builtin_registry();
    // The scan reads every source file, compiled or not; a tool whose feature
    // is off in this build is not registered and has nothing to check.
    let compiled_out: Vec<&str> = ua_tools::compiled_out_tools().map(|(t, _)| t).collect();
    for (file, (_, calls)) in &sites {
        for (tool, args) in calls {
            if compiled_out.contains(tool) {
                continue;
            }
            let def = reg.get(tool).unwrap_or_else(|| panic!("{file}: no tool {tool}"));
            assert!(
                def.handler_decides(args),
                "{tool} ({args}) gates in its handler ({file}) but is not marked"
            );
        }
    }
    // A tool nothing in its handler gates stays requestable.
    for tool in ["task_add", "task_update", "crew_intervene", "delegate", "handoff"] {
        assert!(!reg.get(tool).unwrap().handler_decides(&json!({})), "{tool}");
    }
}
