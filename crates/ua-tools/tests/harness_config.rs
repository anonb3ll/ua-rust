//! Harness config bundles: byte-compatible rendering against golden fixtures
//! rendered by the Python hub, and the publish / get / report / applied flow
//! through the governed registry (approval binding, ownership, the skills
//! registry feeding the served bundle).

use std::path::PathBuf;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::families::harness_config::render;
use ua_tools::{Hub, Registry, builtin_registry};

// --- golden renders ---------------------------------------------------------------

fn fixtures() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/harness_config");
    let mut out: Vec<(String, Value)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
            (p.file_stem().unwrap().to_string_lossy().into_owned(), v)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(out.len() >= 7, "fixtures missing in {}", dir.display());
    out
}

#[test]
fn every_surface_renders_byte_identical_to_the_python_hub() {
    let mut surfaces = 0;
    for (case, fx) in fixtures() {
        let bundle = render::normalize(&fx["raw"]).unwrap_or_else(|e| panic!("{case}: {e}"));
        assert_eq!(bundle.to_value(), fx["bundle"], "{case}: normalized bundle");
        assert_eq!(bundle.to_json(), fx["bundle_json"].as_str().unwrap(), "{case}: stored bundle_json");
        let rendered = render::render_all(&bundle).unwrap();
        let expected = fx["rendered"].as_object().unwrap();
        assert_eq!(
            rendered.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "{case}: surface set"
        );
        for (surface, want) in expected {
            let got = &rendered[surface];
            assert_eq!(got.content, want["content"].as_str().unwrap(), "{case}/{surface}: content");
            assert_eq!(got.hash, want["hash"].as_str().unwrap(), "{case}/{surface}: hash");
            assert_eq!(got.path, want["path"].as_str().unwrap(), "{case}/{surface}: path");
            assert_eq!(got.kind, want["kind"].as_str().unwrap(), "{case}/{surface}: kind");
            assert_eq!(
                render::diff_from_empty(&got.path, &got.content),
                want["diff_from_empty"].as_str().unwrap(),
                "{case}/{surface}: diff"
            );
            surfaces += 1;
        }
        // A bundle read back from its stored JSON renders the same bytes.
        let reloaded: render::Bundle = serde_json::from_str(fx["bundle_json"].as_str().unwrap()).unwrap();
        assert_eq!(render::render_all(&reloaded).unwrap(), rendered, "{case}: reload");
    }
    assert!(surfaces >= 30, "only {surfaces} surfaces compared");
}

// --- the flow through the registry ------------------------------------------------

struct H {
    hub: Hub,
    reg: Registry,
    _ws: tempfile::TempDir,
}

fn caller(label: &str, kind: ActorKind) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

fn device() -> Caller {
    caller("builder-1", ActorKind::Agent)
}

fn other_agent() -> Caller {
    caller("builder-2", ActorKind::Agent)
}

/// A lifecycle operator that is an agent: it publishes, a human approves.
fn ops() -> Caller {
    caller("ops-bot", ActorKind::Agent)
}

fn human() -> Caller {
    Caller { profile: Profile::Operator, enforce_profile: false, ..caller("operator", ActorKind::Human) }
}

const NODE: &str = "node-a";

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

impl H {
    fn new() -> Self {
        let ws = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        cfg.lifecycle_operators = Some(vec!["operator".into(), "ops-bot".into()]);
        cfg.workspace = Some(ws.path().to_path_buf());
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _ws: ws }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) failed: {e:?}"),
        }
    }

    async fn approve(&self, id: i64) {
        self.ok(&human(), "approval_resolve", json!({ "id": id, "decision": "approve" })).await;
    }

    async fn publish(&self, bundle: Value) -> Value {
        let args = json!({ "bundle": bundle });
        let parked = self.call(&ops(), "harness_config_publish", args.clone()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, .. } = parked else {
            panic!("expected an approval: {parked:?}")
        };
        self.approve(approval_id).await;
        self.ok(&ops(), "harness_config_publish", args).await
    }

    async fn register(&self) {
        self.ok(&device(), "node_register", json!({ "node": NODE, "facts": { "backends": ["codex"] } }))
            .await;
    }

    async fn config(&self, args: Value) -> Result<Value, UaError> {
        let mut args = args;
        args["node"] = json!(NODE);
        self.call(&device(), "node_config", args).await
    }

    fn scalar(&self, sql: &str) -> Value {
        let sql = sql.to_string();
        self.hub
            .db()
            .read(move |c| {
                Ok(c.query_row(&sql, [], |r| {
                    Ok(match r.get::<_, rusqlite::types::Value>(0)? {
                        rusqlite::types::Value::Null => Value::Null,
                        rusqlite::types::Value::Integer(i) => json!(i),
                        rusqlite::types::Value::Text(t) => json!(t),
                        other => json!(format!("{other:?}")),
                    })
                })?)
            })
            .unwrap()
    }

    fn events(&self, kind: &str) -> i64 {
        self.scalar(&format!(
            "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.harness_config' \
             AND json_extract(payload, '$.kind') = '{kind}'"
        ))
        .as_i64()
        .unwrap()
    }
}

fn proposal(get: &Value, surface: &str) -> Value {
    let r = &get["rendered"][surface];
    json!({
        "surface": surface,
        "path": r["path"],
        "desired_hash": r["hash"],
        "observed_hash": null,
        "diff": "",
    })
}

#[tokio::test]
async fn publish_needs_an_operator_and_a_human_approval_bound_to_the_content() {
    let h = H::new();
    let bundle = json!({ "version": "1.0.0", "rules": { "claude": "be careful\n" } });

    // A plain agent is not an operator.
    let e = h.call(&device(), "harness_config_publish", json!({ "bundle": bundle })).await.unwrap_err();
    assert_eq!(reason(&e), "operator_required", "{e:?}");
    // A bearer MCP server is refused before any approval is asked.
    let bad = json!({ "version": "2", "mcp_servers": [{ "name": "x", "url": "https://x.example.com", "auth": "bearer" }] });
    let e = h.call(&ops(), "harness_config_publish", json!({ "bundle": bad })).await.unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");

    // The pass binds the content: a different bundle under the same version
    // is a new request, not the approved one.
    let parked = h.call(&ops(), "harness_config_publish", json!({ "bundle": bundle })).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = parked else { panic!("{parked:?}") };
    h.approve(approval_id).await;
    let changed = json!({ "version": "1.0.0", "rules": { "claude": "be reckless\n" } });
    let e = h.call(&ops(), "harness_config_publish", json!({ "bundle": changed })).await.unwrap_err();
    assert!(
        matches!(e, UaError::ApprovalRequired { approval_id: other, .. } if other != approval_id),
        "{e:?}"
    );

    let out = h.ok(&ops(), "harness_config_publish", json!({ "bundle": bundle })).await;
    assert_eq!(out["version"], "1.0.0");
    assert_eq!(out["surfaces"], json!(["agents", "claude", "codex", "cursor", "opencode"]));
    assert_eq!(h.events("harness_config_publish"), 1);

    // A version is published once; the refusal comes before any approval.
    let e = h.call(&ops(), "harness_config_publish", json!({ "bundle": bundle })).await.unwrap_err();
    assert_eq!(reason(&e), "version_published", "{e:?}");

    let status = h.ok(&device(), "harness_config_status", json!({})).await;
    assert_eq!(status["active"]["version"], "1.0.0");
    assert_eq!(status["apply_tool"], "harness_config_apply");
}

#[tokio::test]
async fn a_node_gets_reports_drift_and_applies_only_with_an_approved_pass() {
    let h = H::new();
    h.register().await;
    // Nothing published yet.
    let v = h.config(json!({ "action": "get" })).await.unwrap();
    assert_eq!(v["bundle"], Value::Null);
    assert_eq!(v["rendered"], json!({}));

    h.publish(json!({ "version": "v1", "rules": { "claude": "rules\n" } })).await;
    let got = h.config(json!({})).await.unwrap();
    assert_eq!(got["version"], "v1");
    assert_eq!(got["proposal_mode"], true);
    assert_eq!(got["apply_grants"], json!([]));
    let claude = &got["rendered"]["claude"];
    assert_eq!(claude["content"], "rules\n");
    assert_eq!(claude["hash"], render::content_hash("rules\n"));
    assert_eq!(
        got["surfaces"]["claude"],
        json!({ "path": "CLAUDE.md", "hash": claude["hash"], "kind": "rules" })
    );

    // A stale version, an invented hash and too many proposals are refused.
    let p = proposal(&got, "claude");
    let e =
        h.config(json!({ "action": "report", "bundle_version": "v0", "proposals": [p] })).await.unwrap_err();
    assert!(matches!(e, UaError::ConflictCode { .. }), "{e:?}");
    let mut forged = p.clone();
    forged["desired_hash"] = json!("ab".repeat(32));
    let e = h
        .config(json!({ "action": "report", "bundle_version": "v1", "proposals": [forged] }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "desired_hash_mismatch", "{e:?}");
    let many: Vec<Value> = (0..33).map(|_| p.clone()).collect();
    let e =
        h.config(json!({ "action": "report", "bundle_version": "v1", "proposals": many })).await.unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");
    let e = h.config(json!({ "action": "report", "bundle_version": "v1" })).await.unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");

    // One report parks one approval per surface; a repeat reuses both.
    let report =
        json!({ "action": "report", "bundle_version": "v1", "proposals": [p, proposal(&got, "agents")] });
    let r1 = h.config(report.clone()).await.unwrap();
    assert_eq!(r1["ok"], true);
    assert_eq!(r1["proposals"].as_array().unwrap().len(), 2);
    assert_eq!(r1["proposals"][0]["status"], "pending");
    let r2 = h.config(report).await.unwrap();
    assert_eq!(r2["proposals"][0]["proposal_id"], r1["proposals"][0]["proposal_id"]);
    assert_eq!(r2["proposals"][0]["approval_id"], r1["proposals"][0]["approval_id"]);
    assert_eq!(h.scalar("SELECT COUNT(*) FROM approvals WHERE tool = 'harness_config_apply'"), json!(2));
    assert_eq!(h.scalar("SELECT COUNT(*) FROM harness_config_drift"), json!(4));
    assert_eq!(h.events("harness_config_report"), 2);

    // The approval binds node, surface, path, version and hash.
    let approval_id = r1["proposals"][0]["approval_id"].as_i64().unwrap();
    let payload: Value = serde_json::from_str(
        h.scalar(&format!("SELECT payload FROM approvals WHERE id = {approval_id}")).as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        payload,
        json!({ "node": NODE, "surface": "claude", "path": "CLAUDE.md", "bundle_version": "v1", "desired_hash": claude["hash"] })
    );

    // Before approval, applied parks (stays pending) and writes nothing.
    let applied = json!({ "action": "applied", "surface": "claude", "desired_hash": claude["hash"] });
    let e = h.config(applied.clone()).await.unwrap_err();
    assert!(matches!(e, UaError::ApprovalRequired { approval_id: id, .. } if id == approval_id), "{e:?}");

    h.approve(approval_id).await;
    let got = h.config(json!({ "action": "get" })).await.unwrap();
    let grants = got["apply_grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1, "{got}");
    assert_eq!(grants[0]["surface"], "claude");
    assert_eq!(grants[0]["desired_hash"], claude["hash"]);

    // The pass is consumed once.
    let ok = h.config(applied.clone()).await.unwrap();
    assert_eq!(ok["proposal_id"], r1["proposals"][0]["proposal_id"]);
    assert_eq!(ok["approval_id"], approval_id);
    assert_eq!(h.events("harness_config_applied"), 1);
    let e = h.config(applied).await.unwrap_err();
    assert!(matches!(e, UaError::NotFound(_)), "{e:?}");
    let got = h.config(json!({ "action": "get" })).await.unwrap();
    assert_eq!(got["apply_grants"], json!([]));
}

#[tokio::test]
async fn another_agents_node_is_refused() {
    let h = H::new();
    h.register().await;
    h.publish(json!({ "version": "v1" })).await;
    let e = h.call(&other_agent(), "node_config", json!({ "node": NODE })).await.unwrap_err();
    assert_eq!(reason(&e), "node_owned_elsewhere");
    let e = h
        .call(&other_agent(), "node_config", json!({ "node": NODE, "action": "report", "proposals": [] }))
        .await;
    assert_eq!(reason(&e.unwrap_err()), "node_owned_elsewhere");
    // A human has no node.
    let e = h.call(&human(), "node_config", json!({ "node": NODE })).await.unwrap_err();
    assert_eq!(reason(&e), "agent_identity_required");
    let e = h.call(&device(), "node_config", json!({ "node": "node-z" })).await.unwrap_err();
    assert!(matches!(e, UaError::NotFound(_)), "{e:?}");
    let e = h.call(&device(), "node_config", json!({ "node": NODE, "action": "nope" })).await.unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");
}

#[tokio::test]
async fn registry_skills_assigned_to_the_agent_ride_in_its_bundle() {
    let h = H::new();
    h.register().await;
    let dir = h.hub.cfg().workspace_root().join("skills/review-diff");
    std::fs::create_dir_all(&dir).unwrap();
    let md = "---\nname: review-diff\ndescription: Review a diff for correctness. Use when asked to check a change \
              before it lands.\n---\n\n# Review a diff\n\nRead the whole diff first.\nThen read the tests.\nThen \
              report each finding with a file and line.\n";
    std::fs::write(dir.join("SKILL.md"), md).unwrap();

    let out = h
        .ok(
            &ops(),
            "skill_registry",
            json!({ "action": "publish", "params": { "name": "review-diff", "path": "skills/review-diff" } }),
        )
        .await;
    assert_eq!(out["ok"], true, "{out}");
    assert_eq!(out["skill"]["version"], 1);
    assert_eq!(out["skill"]["content_hash"], render::content_hash(md));
    let again = h
        .ok(&ops(), "skill_registry", json!({ "action": "publish", "params": { "name": "review-diff", "path": "skills/review-diff/SKILL.md" } }))
        .await;
    assert_eq!(again["idempotent"], true);
    // Versions are immutable.
    let res = h.hub.db().write(|tx| Ok(tx.execute("UPDATE skill_versions SET content = 'x'", [])?));
    assert!(res.is_err());

    h.ok(
        &ops(),
        "skill_registry",
        json!({ "action": "assign", "params": { "skill_name": "review-diff", "target": "developer", "target_type": "profile" } }),
    )
    .await;
    let resolved = h
        .ok(
            &ops(),
            "skill_registry",
            json!({ "action": "resolve", "params": { "agent_label": "builder-1" } }),
        )
        .await;
    assert_eq!(resolved["skills"][0]["name"], "review-diff");
    assert_eq!(resolved["skills"][0]["via"], "profile");

    h.publish(json!({ "version": "v1", "skills": [{ "name": "inline", "description": "d", "body": "b" }] }))
        .await;
    let got = h.config(json!({})).await.unwrap();
    let skills = got["bundle"]["skills"].as_array().unwrap();
    assert_eq!(skills.len(), 2, "{got}");
    assert_eq!(skills[1]["name"], "review-diff");
    assert_eq!(skills[1]["body"], md);
    assert!(skills[1]["description"].as_str().unwrap().starts_with("Review a diff"));
    assert_eq!(got["assigned_skills"][0]["included"], true);
    // The served bundle renders to the hashes it is served with, so a node
    // rendering it locally agrees with the hub.
    let served: render::Bundle = serde_json::from_value(got["bundle"].clone()).unwrap();
    for (s, r) in render::render_all(&served).unwrap() {
        assert_eq!(got["rendered"][&s]["hash"], r.hash, "{s}");
    }
    assert!(got["rendered"]["opencode"]["content"].as_str().unwrap().contains("review-diff"));

    // A profile assignment reaches every agent of that profile; an agent
    // assignment only that agent.
    h.ok(&other_agent(), "node_register", json!({ "node": "node-b" })).await;
    let theirs = h.call(&other_agent(), "node_config", json!({ "node": "node-b" })).await.unwrap();
    assert_eq!(theirs["bundle"]["skills"].as_array().unwrap().len(), 2, "same profile, same skills");
    h.ok(
        &ops(),
        "skill_registry",
        json!({ "action": "assign", "params": { "skill_name": "review-diff", "target": "builder-1" } }),
    )
    .await;
    h.ok(
        &ops(),
        "skill_registry",
        json!({ "action": "unassign", "params": { "skill_name": "review-diff", "target": "developer", "target_type": "profile" } }),
    )
    .await;
    let theirs = h.call(&other_agent(), "node_config", json!({ "node": "node-b" })).await.unwrap();
    assert_eq!(theirs["bundle"]["skills"].as_array().unwrap().len(), 1);
    let mine = h.config(json!({})).await.unwrap();
    assert_eq!(mine["bundle"]["skills"].as_array().unwrap().len(), 2);
    assert_eq!(mine["assigned_skills"][0]["via"], "agent");

    // Drift of a skills directory against the registry.
    let drift = h
        .ok(&ops(), "skill_registry", json!({ "action": "drift", "params": { "surface_dir": "skills" } }))
        .await;
    assert_eq!(drift["synced"][0]["name"], "review-diff", "{drift}");
}
