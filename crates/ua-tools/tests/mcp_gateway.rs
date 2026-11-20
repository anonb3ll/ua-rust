//! Managed secrets, the MCP server registry and `mcp_gateway` through the
//! governed registry, against a fake downstream MCP server.
//!
//! The fake server is this test binary: run with `--fake-mcp-server` it
//! serves MCP on stdin/stdout. That is why this file has its own harness
//! (`harness = false`): libtest would print to stdout before the server could
//! start. The harness speaks the part of libtest's CLI that `cargo test` and
//! `cargo nextest` use (`--list --format terse`, `--exact`, name filters).
//! The Streamable HTTP tests run the same fake in-process on a loopback port.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const FAKE_FLAG: &str = "--fake-mcp-server";
const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TOKEN: &str = "fake-downstream-T0KEN/with+symbols";

// --- the fake downstream server ----------------------------------------------------

#[derive(Clone)]
struct Fake;

fn text(s: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s)])
}

impl ServerHandler for Fake {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let schema = Arc::new(serde_json::Map::from_iter([("type".to_string(), json!("object"))]));
        let tools = ["echo", "reveal", "write_note", "big", "env", "secret_tool"]
            .iter()
            .map(|n| Tool::new(*n, format!("fake {n}"), schema.clone()))
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let args = Value::Object(request.arguments.unwrap_or_default());
        // Over HTTP the credential arrives as a header; over stdio, in the environment.
        let token = ctx
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.headers.get("authorization"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_start_matches("Bearer ").to_string())
            .or_else(|| std::env::var("FAKE_TOKEN").ok())
            .unwrap_or_default();
        let result = match request.name.as_ref() {
            "echo" => text(format!("echo: {args}")),
            "reveal" => {
                let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(format!("Bearer {token}"));
                let mut r = text(format!("token={token} b64={b64}"));
                r.structured_content = Some(json!({ "token": token }));
                r
            }
            "write_note" => text(format!("noted: {}", args["text"].as_str().unwrap_or(""))),
            "big" => text("x".repeat(300_000)),
            "env" => text(format!(
                "hub_key_visible={} home_set={}",
                std::env::var("UA_MANAGED_SECRET_KEY").is_ok(),
                std::env::var("HOME").is_ok()
            )),
            "secret_tool" => text("this tool is not catalogued"),
            _ => return Err(ErrorData::invalid_params("unknown tool", None)),
        };
        Ok(result.into())
    }
}

fn run_fake_stdio() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        if let Ok(server) = Fake.serve(rmcp::transport::stdio()).await {
            let _ = server.waiting().await;
        }
    });
}

/// The fake over Streamable HTTP on 127.0.0.1; returns its port.
async fn start_http_fake() -> u16 {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(["localhost", "127.0.0.1"])
        .with_legacy_session_mode(true)
        .with_cancellation_token(tokio_util::sync::CancellationToken::new());
    let service = StreamableHttpService::new(|| Ok(Fake), Arc::new(LocalSessionManager::default()), config);
    let app = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    port
}

// --- hub helpers ---------------------------------------------------------------------

fn caller(label: &str, kind: ActorKind, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

/// The approving human.
fn human() -> Caller {
    Caller { enforce_profile: false, ..caller("operator", ActorKind::Human, Profile::Operator) }
}

/// An operator agent: requests registrations, deletes and reviews.
fn ops() -> Caller {
    caller("ops-1", ActorKind::Agent, Profile::Operator)
}

fn dev() -> Caller {
    caller("builder-1", ActorKind::Agent, Profile::Developer)
}

fn steward() -> Caller {
    caller("steward-1", ActorKind::Agent, Profile::Steward)
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::ApprovalRequired { .. } => "approval_required".into(),
        e => e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string()),
    }
}

struct H {
    hub: Hub,
    reg: Registry,
}

impl H {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(f: impl FnOnce(&mut Config)) -> Self {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        cfg.managed_secret_key = Some(KEY.to_string().into());
        f(&mut cfg);
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry() }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.call(who, tool, args.clone()).await.unwrap_or_else(|e| panic!("{tool}({args}) failed: {e:?}"))
    }

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> UaError {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => panic!("{tool}({args}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    /// Call, approve the parked request as the human, and call again.
    async fn approved(&self, who: &Caller, tool: &str, args: Value) -> Value {
        let parked = self.err(who, tool, args.clone()).await;
        let UaError::ApprovalRequired { approval_id, .. } = parked else {
            panic!("{tool} should park for approval, got {parked:?}")
        };
        self.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
        self.ok(who, tool, args).await
    }

    fn events(&self, channel: &str) -> Vec<Value> {
        self.hub
            .db()
            .read(|c| {
                let mut stmt = c.prepare("SELECT payload FROM event_log WHERE channel = ?1 ORDER BY seq")?;
                let rows = stmt.query_map([channel], |r| r.get::<_, String>(0))?;
                Ok(rows.map(|r| serde_json::from_str(&r.unwrap()).unwrap()).collect())
            })
            .unwrap()
    }

    fn all_text(&self) -> String {
        self.hub
            .db()
            .read(|c| {
                let mut out = String::new();
                for sql in [
                    "SELECT payload FROM event_log",
                    "SELECT payload FROM approvals",
                    "SELECT fingerprint || consumer FROM managed_secrets",
                ] {
                    let mut stmt = c.prepare(sql)?;
                    for r in stmt.query_map([], |r| r.get::<_, String>(0))? {
                        out.push_str(&r?);
                        out.push('\n');
                    }
                }
                Ok(out)
            })
            .unwrap()
    }

    async fn set_secret(&self, name: &str, consumer: &str, value: &str) -> Value {
        self.ok(&human(), "managed_secret_set", json!({ "name": name, "consumer": consumer, "value": value }))
            .await
    }

    /// Register the stdio fake as `name` with the usual catalog.
    async fn register_stdio(&self, name: &str, extra: Value) -> Value {
        let mut server = stdio_spec();
        if let (Some(s), Some(e)) = (server.as_object_mut(), extra.as_object()) {
            s.extend(e.clone());
        }
        self.approved(&ops(), "mcp_server_register", json!({ "name": name, "server": server })).await
    }
}

fn stdio_spec() -> Value {
    json!({
        "transport": "stdio",
        "command": std::env::current_exe().unwrap().to_string_lossy(),
        "args": [FAKE_FLAG],
        "secrets": [{ "secret": "fake-token", "inject": "env:FAKE_TOKEN" }],
        "tools": { "echo": "read", "reveal": "read", "big": "read", "env": "read", "write_note": "write" },
    })
}

fn content_text(v: &Value) -> String {
    v["content"].as_array().unwrap().iter().filter_map(|b| b["text"].as_str()).collect::<Vec<_>>().join("\n")
}

// --- tests ---------------------------------------------------------------------------

async fn secrets_are_write_only_encrypted_and_operator_only() {
    let h = H::new();
    let set = h.set_secret("fake-token", "mcp:fake", TOKEN).await;
    assert_eq!(set["stored"], true);
    assert_eq!(set["replaced"], false);
    assert!(set["fingerprint"].as_str().unwrap().len() == 32);
    assert!(!set.to_string().contains(TOKEN), "the value is never returned");

    let list = h.ok(&ops(), "managed_secret_list", json!({})).await;
    assert_eq!(list["count"], 1);
    assert_eq!(list["secrets"][0]["consumer"], "mcp:fake");
    assert_eq!(list["secrets"][0]["key_current"], true);
    assert!(!list.to_string().contains(TOKEN));

    // At rest the row holds ciphertext only.
    let raw: Vec<u8> = h
        .hub
        .db()
        .read(|c| Ok(c.query_row("SELECT ciphertext FROM managed_secrets", [], |r| r.get(0))?))
        .unwrap();
    assert!(!raw.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
    assert!(!h.all_text().contains(TOKEN), "no ledger event, approval or metadata holds the value");
    assert_eq!(
        h.events("managed_secret.set")[0],
        json!({ "name": "fake-token", "consumer": "mcp:fake", "replaced": false })
    );

    // Who may write.
    let e =
        h.err(&dev(), "managed_secret_set", json!({ "name": "x", "consumer": "mcp:x", "value": "v" })).await;
    assert_eq!(reason(&e), "profile_denied");
    let cos = caller("boss", ActorKind::Agent, Profile::ChiefOfStaff);
    let e =
        h.err(&cos, "managed_secret_set", json!({ "name": "x", "consumer": "mcp:x", "value": "v" })).await;
    assert_eq!(reason(&e), "operator_only");
    let anon = Caller::local("someone", Transport::Stdio);
    let e =
        h.err(&anon, "managed_secret_set", json!({ "name": "x", "consumer": "mcp:x", "value": "v" })).await;
    assert_eq!(reason(&e), "identity_required");
    let e = h.err(&human(), "managed_secret_set", json!({ "name": "x", "value": "v" })).await;
    assert_eq!(reason(&e), "invalid_argument", "there is no default consumer");
    let e = h
        .err(
            &human(),
            "managed_secret_set",
            json!({ "name": "fake-token", "consumer": "zulip", "value": "v" }),
        )
        .await;
    assert_eq!(reason(&e), "secret_consumer_change");

    // An operator agent may set; rotating replaces and changes the fingerprint.
    let again = h
        .ok(
            &ops(),
            "managed_secret_set",
            json!({ "name": "fake-token", "consumer": "mcp:fake", "value": "new" }),
        )
        .await;
    assert_eq!(again["replaced"], true);
    assert_ne!(again["fingerprint"], set["fingerprint"]);

    // Delete always needs a human approval, bound to the current value.
    let deleted = h.approved(&ops(), "managed_secret_delete", json!({ "name": "fake-token" })).await;
    assert_eq!(deleted["deleted"], true);
    assert_eq!(h.ok(&ops(), "managed_secret_list", json!({})).await["count"], 0);
    let e = h.err(&ops(), "managed_secret_delete", json!({ "name": "fake-token" })).await;
    assert_eq!(reason(&e), "not_found");

    // No key, no writes.
    let nokey = H::with(|c| c.managed_secret_key = None);
    let e = nokey
        .err(&human(), "managed_secret_set", json!({ "name": "x", "consumer": "mcp:x", "value": "v" }))
        .await;
    assert_eq!(reason(&e), "secret_key_unset");
}

async fn an_approved_gate_on_managed_secret_set_binds_the_fingerprint_not_the_value() {
    let h = H::with(|c| c.approval_tools = vec!["managed_secret_set".into()]);
    let args = json!({ "name": "gated", "consumer": "mcp:fake", "value": TOKEN });
    let set = h.approved(&ops(), "managed_secret_set", args).await;
    assert_eq!(set["stored"], true);
    assert!(!h.all_text().contains(TOKEN), "the approval row holds no value");
}

async fn registration_needs_an_operator_and_a_human_approval() {
    let h = H::new();
    let args = json!({ "name": "fake", "server": stdio_spec() });
    assert_eq!(reason(&h.err(&dev(), "mcp_server_register", args.clone()).await), "profile_denied");
    // A bad spec is refused before anyone is asked.
    let mut bad = stdio_spec();
    bad["command"] = json!("relative/path");
    let e = h.err(&ops(), "mcp_server_register", json!({ "name": "fake", "server": bad })).await;
    assert_eq!(reason(&e), "invalid_argument");
    let pending = h.ok(&human(), "approval_pending", json!({})).await;
    assert_eq!(pending["pending"].as_array().unwrap().len(), 0);

    let reg = h.approved(&ops(), "mcp_server_register", args.clone()).await;
    assert_eq!(reg["server"]["status"], "active");
    assert_eq!(reg["server"]["consumer"], "mcp:fake");
    assert_eq!(reg["server"]["secrets"][0]["stored"], false);
    assert_eq!(reg["server"]["write_tools"], json!(["write_note"]));
    let e = h.err(&ops(), "mcp_server_register", args).await;
    assert_eq!(reason(&e), "server_registered");

    let list = h.ok(&dev(), "mcp_server_list", json!({})).await;
    assert_eq!(list["count"], 1);
    assert_eq!(h.events("agent.mcp_server")[0]["op"], "registered");
}

async fn reads_run_and_secrets_are_injected_and_redacted() {
    let h = H::new();
    h.set_secret("fake-token", "mcp:fake", TOKEN).await;
    h.register_stdio("fake", json!({})).await;

    let r = h
        .ok(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "echo", "arguments": { "q": "hello" } }))
        .await;
    assert_eq!(r["access"], "read");
    assert_eq!(r["is_error"], false);
    assert_eq!(r["untrusted"], true);
    assert_eq!(r["trust"]["level"], "untrusted");
    assert!(content_text(&r).contains("hello"), "{r}");

    // The child got the token by reference; nothing it echoes reaches the caller.
    let r = h.ok(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "reveal" })).await;
    let shown = r.to_string();
    assert!(!shown.contains(TOKEN), "{shown}");
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(format!("Bearer {TOKEN}"));
    assert!(!shown.contains(&b64), "{shown}");
    assert!(content_text(&r).starts_with("token=[redacted] b64=[redacted]"), "{r}");
    assert_eq!(r["structured_content"]["token"], "[redacted]");

    // The child never sees the hub's environment.
    let r = h.ok(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "env" })).await;
    assert!(content_text(&r).contains("hub_key_visible=false"), "{r}");

    // One ledger event per call: names, sizes and outcome, never arguments.
    let events = h.events("agent.mcp_gateway.call");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["outcome"], "ok");
    assert_eq!(events[0]["tool"], "echo");
    assert_eq!(events[0]["caller"], "builder-1");
    assert!(events[0]["args_bytes"].as_u64().unwrap() > 0);
    assert!(events[0]["result_bytes"].as_u64().unwrap() > 0);
    assert!(!h.all_text().contains("hello"), "arguments are not ledgered");
    assert!(!h.all_text().contains(TOKEN));

    // Live listing: catalogued tools with their schemas, the rest only counted.
    let l = h.ok(&dev(), "mcp_gateway", json!({ "action": "list", "server": "fake", "live": true })).await;
    let tools = l["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 5);
    assert!(tools.iter().all(|t| t["present"] == true), "{l}");
    assert_eq!(l["uncatalogued_count"], 1);
    assert!(!l.to_string().contains("secret_tool"));
    let w = tools.iter().find(|t| t["name"] == "write_note").unwrap();
    assert_eq!(w["access"], "write");
    assert_eq!(w["description"], "fake write_note");
}

async fn writes_need_a_one_time_approval_bound_to_the_arguments() {
    let h = H::new();
    h.set_secret("fake-token", "mcp:fake", TOKEN).await;
    h.register_stdio("fake", json!({})).await;
    let args = json!({ "server": "fake", "tool": "write_note", "arguments": { "text": "first" } });
    let parked = h.err(&dev(), "mcp_gateway", args.clone()).await;
    let UaError::ApprovalRequired { approval_id, tool } = parked else { panic!("expected an approval") };
    assert_eq!(tool, "mcp_gateway_write");
    // The pass is bound to the exact arguments.
    let other = json!({ "server": "fake", "tool": "write_note", "arguments": { "text": "second" } });
    assert_eq!(reason(&h.err(&dev(), "mcp_gateway", other).await), "approval_required");
    // The requester cannot approve its own write.
    let e = h.err(&dev(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    assert_eq!(reason(&e), "profile_denied");
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let r = h.ok(&dev(), "mcp_gateway", args.clone()).await;
    assert_eq!(content_text(&r), "noted: first");
    assert_eq!(r["access"], "write");
    // One-time: the same call parks again.
    assert_eq!(reason(&h.err(&dev(), "mcp_gateway", args).await), "approval_required");
    let outcomes: Vec<String> = h
        .events("agent.mcp_gateway.call")
        .iter()
        .map(|e| e["outcome"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(outcomes, ["approval_pending", "approval_pending", "ok", "approval_pending"]);
    let ok = &h.events("agent.mcp_gateway.call")[2];
    assert_eq!(ok["approval_id"], approval_id);
    // Anonymous callers cannot write at all.
    let anon = Caller::local("someone", Transport::Stdio);
    let e = h
        .err(
            &anon,
            "mcp_gateway",
            json!({ "server": "fake", "tool": "write_note", "arguments": { "text": "x" } }),
        )
        .await;
    assert_eq!(reason(&e), "identity_required");
}

async fn uncatalogued_tools_and_unknown_servers_are_refused() {
    let h = H::new();
    h.set_secret("fake-token", "mcp:fake", TOKEN).await;
    h.register_stdio("fake", json!({})).await;
    let e = h.err(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "secret_tool" })).await;
    assert_eq!(reason(&e), "tool_not_catalogued");
    let e = h.err(&dev(), "mcp_gateway", json!({ "server": "nope", "tool": "echo" })).await;
    assert_eq!(reason(&e), "not_found");
    let l = h.ok(&dev(), "mcp_gateway", json!({ "action": "list", "server": "fake" })).await;
    assert_eq!(l["tools"].as_array().unwrap().len(), 5);
    assert_eq!(l["live"], false);
    let outcomes: Vec<Value> =
        h.events("agent.mcp_gateway.call").iter().map(|e| e["outcome"].clone()).collect();
    assert_eq!(outcomes, [json!("tool_not_catalogued"), json!("not_found"), json!("ok")]);
}

async fn read_profiles_and_missing_secrets_refuse_reads() {
    let h = H::new();
    h.register_stdio("fake", json!({ "read_profiles": ["steward"] })).await;
    let e = h.err(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "echo" })).await;
    assert_eq!(reason(&e), "read_profile_denied");
    // The steward may read, but no secret is stored for the server yet.
    let e = h.err(&steward(), "mcp_gateway", json!({ "server": "fake", "tool": "echo" })).await;
    assert_eq!(reason(&e), "secret_unavailable");
    // A secret bound to another consumer is not handed over.
    h.set_secret("fake-token", "mcp:other", TOKEN).await;
    let e = h.err(&steward(), "mcp_gateway", json!({ "server": "fake", "tool": "echo" })).await;
    assert_eq!(reason(&e), "secret_unavailable");
}

async fn revoked_and_unreviewed_servers_are_refused() {
    let past = "2020-01-01";
    let h = H::with(|c| {
        let mut stale = stdio_spec();
        stale["review_expires_at"] = json!(past);
        c.mcp_servers.insert("stale".into(), stale);
        c.mcp_servers.insert("unreviewed".into(), stdio_spec());
        c.mcp_servers.insert("broken".into(), json!({ "transport": "stdio", "tools": {} }));
    });
    h.set_secret("fake-token", "mcp:fake", TOKEN).await;
    h.set_secret("stale-token", "mcp:stale", TOKEN).await;
    h.register_stdio("fake", json!({})).await;
    let echo = |s: &str| json!({ "server": s, "tool": "echo" });
    h.ok(&dev(), "mcp_gateway", echo("fake")).await;

    let revoked = h.approved(&ops(), "mcp_server_revoke", json!({ "name": "fake" })).await;
    assert_eq!(revoked["server"]["status"], "revoked");
    assert_eq!(reason(&h.err(&dev(), "mcp_gateway", echo("fake")).await), "server_revoked");
    let list = h.ok(&dev(), "mcp_server_list", json!({})).await;
    assert!(list["servers"].as_array().unwrap().iter().all(|s| s["name"] != "fake"));

    assert_eq!(reason(&h.err(&dev(), "mcp_gateway", echo("stale")).await), "review_expired");
    assert_eq!(reason(&h.err(&dev(), "mcp_gateway", echo("unreviewed")).await), "review_required");
    assert_eq!(reason(&h.err(&dev(), "mcp_gateway", echo("broken")).await), "server_misconfigured");

    // A config entry can be reviewed (approval-gated) and is then usable.
    let mut stale = stdio_spec();
    stale["secrets"] = json!([{ "secret": "stale-token", "inject": "env:FAKE_TOKEN" }]);
    let h2 = H::with(|c| {
        stale["review_expires_at"] = json!(past);
        c.mcp_servers.insert("stale".into(), stale);
    });
    h2.set_secret("stale-token", "mcp:stale", TOKEN).await;
    assert_eq!(reason(&h2.err(&dev(), "mcp_gateway", echo("stale")).await), "review_expired");
    let reviewed =
        h2.approved(&ops(), "mcp_server_review", json!({ "name": "stale", "review_days": 7 })).await;
    assert_eq!(reviewed["server"]["status"], "active");
    h2.ok(&dev(), "mcp_gateway", echo("stale")).await;
    // Registering over a config name is refused.
    let e = h2.err(&ops(), "mcp_server_register", json!({ "name": "stale", "server": stdio_spec() })).await;
    assert_eq!(reason(&e), "server_in_config");
}

async fn big_results_are_capped_and_marked() {
    let h = H::new();
    h.set_secret("fake-token", "mcp:fake", TOKEN).await;
    h.register_stdio("fake", json!({})).await;
    let r = h.ok(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "big" })).await;
    assert_eq!(r["truncated"], true);
    assert!(content_text(&r).len() <= 256 * 1024);
    assert_eq!(h.events("agent.mcp_gateway.call")[0]["outcome"], "ok_truncated");
}

async fn streamable_http_is_pinned_to_its_registered_loopback_origin() {
    let port = start_http_fake().await;
    let h = H::new();
    h.set_secret("http-token", "mcp:web", TOKEN).await;
    let server = |scope: &str| {
        json!({
            "transport": "streamable_http",
            "url": format!("http://localhost:{port}/mcp"),
            "address_scope": scope,
            "secrets": [{ "secret": "http-token", "inject": "bearer" }],
            "tools": { "echo": "read", "reveal": "read" },
        })
    };
    // Loopback is refused unless it is registered as loopback.
    let e = h.err(&ops(), "mcp_server_register", json!({ "name": "web", "server": server("public") })).await;
    assert_eq!(reason(&e), "invalid_argument");
    let e = h.err(&ops(), "mcp_server_register", json!({ "name": "web", "server": server("private") })).await;
    assert_eq!(reason(&e), "invalid_argument");
    h.approved(&ops(), "mcp_server_register", json!({ "name": "web", "server": server("loopback") })).await;

    let r = h
        .ok(
            &dev(),
            "mcp_gateway",
            json!({ "server": "web", "tool": "echo", "arguments": { "q": "over http" } }),
        )
        .await;
    assert!(content_text(&r).contains("over http"), "{r}");
    // The bearer reached the server and was scrubbed on the way back.
    let r = h.ok(&dev(), "mcp_gateway", json!({ "server": "web", "tool": "reveal" })).await;
    assert!(content_text(&r).starts_with("token=[redacted]"), "{r}");
    assert!(!r.to_string().contains(TOKEN));

    // A config entry whose literal address is outside its scope never connects.
    let h2 = H::with(|c| {
        let mut s = server("private");
        s["url"] = json!(format!("http://127.0.0.1:{port}/mcp"));
        s["review_expires_at"] = json!("2999-01-01");
        c.mcp_servers.insert("web".into(), s);
    });
    let e = h2.err(&dev(), "mcp_gateway", json!({ "server": "web", "tool": "echo" })).await;
    assert_eq!(reason(&e), "server_misconfigured");
}

async fn unreachable_servers_fail_with_fixed_messages() {
    let h = H::with(|c| {
        c.mcp_servers.insert(
            "gone".into(),
            json!({
                "transport": "stdio",
                "command": "/nonexistent/mcp-server",
                "tools": { "echo": "read" },
                "review_expires_at": "2999-01-01",
            }),
        );
    });
    let e = h.err(&dev(), "mcp_gateway", json!({ "server": "gone", "tool": "echo" })).await;
    assert_eq!(reason(&e), "spawn_failed");
}

// --- harness -----------------------------------------------------------------------

type Test = fn() -> Pin<Box<dyn Future<Output = ()>>>;

macro_rules! tests {
    ($($name:ident),* $(,)?) => {
        &[$((stringify!($name), || Box::pin($name()) as Pin<Box<dyn Future<Output = ()>>>)),*]
    };
}

const TESTS: &[(&str, Test)] = tests![
    secrets_are_write_only_encrypted_and_operator_only,
    an_approved_gate_on_managed_secret_set_binds_the_fingerprint_not_the_value,
    registration_needs_an_operator_and_a_human_approval,
    reads_run_and_secrets_are_injected_and_redacted,
    writes_need_a_one_time_approval_bound_to_the_arguments,
    uncatalogued_tools_and_unknown_servers_are_refused,
    read_profiles_and_missing_secrets_refuse_reads,
    revoked_and_unreviewed_servers_are_refused,
    big_results_are_capped_and_marked,
    streamable_http_is_pinned_to_its_registered_loopback_origin,
    unreachable_servers_fail_with_fixed_messages,
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == FAKE_FLAG) {
        return run_fake_stdio();
    }
    // libtest flags that take a value.
    const VALUED: &[&str] =
        &["--format", "--test-threads", "--color", "--logfile", "--skip", "-Z", "--shuffle-seed"];
    let (mut filters, mut skips) = (Vec::new(), Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--skip" {
            skips.extend(it.next().cloned());
        } else if VALUED.contains(&a.as_str()) {
            it.next();
        } else if !a.starts_with('-') {
            filters.push(a.clone());
        }
    }
    let flag = |f: &str| args.iter().any(|a| a == f);
    // Every test here runs by default; none is ignored.
    if flag("--list") {
        if !flag("--ignored") {
            for (name, _) in TESTS {
                println!("{name}: test");
            }
        }
        return;
    }
    let exact = flag("--exact");
    let selected: Vec<&(&str, Test)> = TESTS
        .iter()
        .filter(|(n, _)| {
            (filters.is_empty()
                || filters.iter().any(|f| if exact { n == f } else { n.contains(f.as_str()) }))
                && !skips.iter().any(|s| n.contains(s.as_str()))
        })
        .filter(|_| !flag("--ignored"))
        .collect();
    println!("\nrunning {} tests", selected.len());
    let mut failed = Vec::new();
    for (name, test) in selected.iter().copied() {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rt.block_on(test()))).is_ok();
        println!("test {name} ... {}", if ok { "ok" } else { "FAILED" });
        if !ok {
            failed.push(*name);
        }
    }
    println!(
        "\ntest result: {}. {} passed; {} failed",
        if failed.is_empty() { "ok" } else { "FAILED" },
        selected.len() - failed.len(),
        failed.len()
    );
    if !failed.is_empty() {
        println!("failures: {failed:?}");
        std::process::exit(101);
    }
}
