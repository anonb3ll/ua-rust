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
        let tools = ["echo", "reveal", "reflect", "split", "write_note", "big", "env", "secret_tool"]
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
            // The credential in the shapes a careless or hostile server echoes it.
            "reflect" => {
                use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
                let pct: String = token
                    .bytes()
                    .map(|b| {
                        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                            (b as char).to_string()
                        } else {
                            format!("%{b:02x}")
                        }
                    })
                    .collect();
                let spaced = format!("{} {} {}", &token[..9], &token[9..21], &token[21..]);
                text(format!(
                    "basic0=Basic {} basic1=Basic {} basic2=Basic {} url={} url_pad={} HEX={} pct={pct}                      part={} spaced={spaced} wrapped={}",
                    STANDARD.encode(format!("ab:{token}")),
                    STANDARD.encode(format!("abc:{token}")),
                    STANDARD.encode(format!("a:{token}")),
                    URL_SAFE_NO_PAD.encode(format!("x{token}")),
                    URL_SAFE.encode(&token),
                    hex::encode(&token).to_ascii_uppercase(),
                    &token[..token.len() * 2 / 3],
                    STANDARD
                        .encode(&token)
                        .as_bytes()
                        .chunks(8)
                        .map(|c| String::from_utf8_lossy(c))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ))
            }
            // The credential split over two blocks, each part too short to redact cleanly alone.
            "split" => CallToolResult::success(vec![
                ContentBlock::text(format!("first {}", &token[..10])),
                ContentBlock::text(format!("{} last", &token[10..])),
            ]),
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
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

/// The approving human.
fn human() -> Caller {
    Caller { enforce_profile: false, ..caller("operator", ActorKind::Human, Profile::Operator) }
}

/// An operator agent: requests registrations, deletes and reviews.
/// A second human operator (secret and registry admin is human-only).
fn ops() -> Caller {
    caller("ops-1", ActorKind::Human, Profile::Operator)
}

fn dev() -> Caller {
    caller("builder-1", ActorKind::Agent, Profile::Developer)
}

fn reviewer() -> Caller {
    caller("reviewer-1", ActorKind::Agent, Profile::Reviewer)
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
        // Secret and registry admin is by identity: ops-1 is a second human
        // (an operator); fleet-bot is a lifecycle operator only.
        cfg.human_identities.push("ops-1".into());
        cfg.lifecycle_operators = Some(vec!["operator".into(), "fleet-bot".into()]);
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
        "tools": {
            "echo": "read", "reveal": "read", "reflect": "read", "split": "read", "big": "read", "env": "read",
            "write_note": "write",
        },
        "read_profiles": ["developer"],
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
        json!({ "name": "fake-token", "consumer": "mcp:fake", "replaced": false, "approval_id": null })
    );

    // Who may write.
    let e =
        h.err(&dev(), "managed_secret_set", json!({ "name": "x", "consumer": "mcp:x", "value": "v" })).await;
    assert_eq!(reason(&e), "profile_denied");
    let cos = caller("boss", ActorKind::Agent, Profile::Coordinator);
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

    // An operator identity may set; replacing needs a human approval bound to
    // the new value's fingerprint, and changes the fingerprint.
    let again = h
        .approved(
            &ops(),
            "managed_secret_set",
            json!({ "name": "fake-token", "consumer": "mcp:fake", "value": "new" }),
        )
        .await;
    assert_eq!(again["replaced"], true);
    assert!(again["approval_id"].is_i64());
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
    // A replacement takes the registry's one approval, not a second one.
    let args = json!({ "name": "gated", "consumer": "mcp:fake", "value": "rotated-value" });
    assert_eq!(h.approved(&ops(), "managed_secret_set", args).await["replaced"], true);
}

async fn replacing_a_secret_needs_an_approval_bound_to_the_new_value() {
    let h = H::new();
    let set = |v: &str| json!({ "name": "fake-token", "consumer": "mcp:fake", "value": v });
    let first = h.ok(&ops(), "managed_secret_set", set(TOKEN)).await;
    assert_eq!(first["replaced"], false, "a first set needs no approval");
    // A replacement parks; the approval shows the new fingerprint, never the value.
    let parked = h.err(&ops(), "managed_secret_set", set("swapped-value-1")).await;
    let UaError::ApprovalRequired { approval_id, tool } = parked else { panic!("expected an approval") };
    assert_eq!(tool, "managed_secret_set");
    let pending = h.ok(&human(), "approval_pending", json!({})).await.to_string();
    assert!(pending.contains("fingerprint") && !pending.contains("swapped-value-1"), "{pending}");
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    // The pass is bound to that value: another value parks again.
    let e = h.err(&ops(), "managed_secret_set", set("swapped-value-2")).await;
    assert_eq!(reason(&e), "approval_required");
    let replaced = h.ok(&ops(), "managed_secret_set", set("swapped-value-1")).await;
    assert_eq!(replaced["replaced"], true);
    assert_eq!(replaced["approval_id"], approval_id);
    assert_ne!(replaced["fingerprint"], first["fingerprint"]);
    // Nothing stored changed while parked.
    let list = h.ok(&ops(), "managed_secret_list", json!({})).await;
    assert_eq!(list["secrets"][0]["fingerprint"], replaced["fingerprint"]);
}

async fn secret_admin_is_an_identity_not_a_profile() {
    // A coordinator agent may activate the operator profile (it ranks lower)...
    let h = H::with(|c| {
        c.profiles.insert("boss".into(), "coordinator".into());
    });
    let boss = caller("boss", ActorKind::Agent, Profile::Coordinator);
    let r = h.ok(&boss, "profile_activate", json!({ "profile": "operator" })).await;
    assert_eq!(r["profile"], "operator");
    // ...but that makes it neither a secret nor a registry admin.
    let as_operator = caller("boss", ActorKind::Agent, Profile::Operator);
    let e = h
        .err(&as_operator, "managed_secret_set", json!({ "name": "x", "consumer": "mcp:x", "value": "v" }))
        .await;
    assert_eq!(reason(&e), "operator_only");
    let e =
        h.err(&as_operator, "mcp_server_register", json!({ "name": "fake", "server": stdio_spec() })).await;
    assert_eq!(reason(&e), "operator_only");
    // A human is, whatever its profile.
    let ops_dev = caller("ops-1", ActorKind::Human, Profile::Coordinator);
    h.ok(&ops_dev, "managed_secret_set", json!({ "name": "x", "consumer": "mcp:x", "value": "v" })).await;
    // An unattended routine running under that human's label is not.
    let routine = caller("ops-1", ActorKind::Agent, Profile::Coordinator);
    let e = h
        .err(&routine, "managed_secret_set", json!({ "name": "z", "consumer": "mcp:x", "value": "v" }))
        .await;
    assert_eq!(reason(&e), "operator_only");
    // A lifecycle operator is not: secret and registry admin is human-only.
    let fleet = caller("fleet-bot", ActorKind::Agent, Profile::Coordinator);
    let e =
        h.err(&fleet, "managed_secret_set", json!({ "name": "y", "consumer": "mcp:x", "value": "v" })).await;
    assert_eq!(reason(&e), "operator_only");
    let e = h.err(&fleet, "mcp_server_register", json!({ "name": "fake2", "server": stdio_spec() })).await;
    assert_eq!(reason(&e), "operator_only");
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
    assert_eq!(tools.len(), 7);
    assert!(tools.iter().all(|t| t["present"] == true), "{l}");
    assert_eq!(l["uncatalogued_count"], 1);
    assert!(!l.to_string().contains("secret_tool"));
    let w = tools.iter().find(|t| t["name"] == "write_note").unwrap();
    assert_eq!(w["access"], "write");
    assert_eq!(w["description"], "fake write_note");
}

/// No 12-byte window of the token, nor of its hex, survives in `text`.
fn assert_no_token(text: &str) {
    let lower = text.to_ascii_lowercase();
    for w in TOKEN.as_bytes().windows(12) {
        let w = std::str::from_utf8(w).unwrap();
        assert!(!text.contains(w), "{w:?} survived in {text}");
    }
    let hex = hex::encode(TOKEN);
    for w in hex.as_bytes().windows(24) {
        assert!(!lower.contains(std::str::from_utf8(w).unwrap()), "hex survived in {text}");
    }
}

async fn encoded_partial_and_split_echoes_are_redacted_or_withheld() {
    let h = H::new();
    h.set_secret("fake-token", "mcp:fake", TOKEN).await;
    h.register_stdio("fake", json!({})).await;
    let r = h.ok(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "reflect" })).await;
    assert_eq!(r["is_error"], false, "{r}");
    let shown = content_text(&r);
    assert_no_token(&shown);
    let joined: String = shown.split_whitespace().collect();
    assert_no_token(&joined);
    // Each echo was replaced, not dropped with its label.
    for label in [
        "basic0=Basic",
        "basic1=Basic",
        "basic2=Basic",
        "url=",
        "url_pad=",
        "HEX=",
        "pct=",
        "part=",
        "spaced=",
    ] {
        assert!(shown.contains(label), "{label} missing in {shown}");
    }
    assert!(shown.matches("[redacted]").count() >= 9, "{shown}");
    // Base64 cores: what is left around a redaction is a few characters, never the value.
    for enc in [
        base64::engine::general_purpose::STANDARD.encode(format!("ab:{TOKEN}")),
        base64::engine::general_purpose::STANDARD.encode(format!("abc:{TOKEN}")),
        base64::engine::general_purpose::STANDARD.encode(format!("a:{TOKEN}")),
        base64::engine::general_purpose::URL_SAFE.encode(TOKEN),
    ] {
        assert!(!joined.contains(&enc[8..20]), "{enc} survived in {shown}");
    }

    // Split across two blocks, the parts cannot be redacted cleanly: withheld.
    let r = h.ok(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "split" })).await;
    assert_eq!(r["is_error"], true, "{r}");
    assert_eq!(r["withheld"], true, "{r}");
    assert!(content_text(&r).contains("withheld"), "{r}");
    assert!(!r.to_string().contains(&TOKEN[..10]) && !r.to_string().contains(&TOKEN[10..]), "{r}");
    let outcomes: Vec<Value> =
        h.events("agent.mcp_gateway.call").iter().map(|e| e["outcome"].clone()).collect();
    assert_eq!(outcomes, [json!("ok"), json!("withheld")]);
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
    // Nor read from a server that injects credentials, whatever read_profiles says.
    let e = h.err(&anon, "mcp_gateway", json!({ "server": "fake", "tool": "echo" })).await;
    assert_eq!(reason(&e), "identity_required");
    let e = h.err(&anon, "mcp_gateway", json!({ "action": "list", "server": "fake", "live": true })).await;
    assert_eq!(reason(&e), "identity_required");
}

async fn empty_read_profiles_mean_humans_and_operators_only() {
    let h = H::new();
    h.set_secret("open-token", "mcp:open", TOKEN).await;
    let secrets = json!([{ "secret": "open-token", "inject": "env:FAKE_TOKEN" }]);
    h.register_stdio("open", json!({ "read_profiles": [], "secrets": secrets })).await;
    let echo = json!({ "server": "open", "tool": "echo" });
    assert_eq!(reason(&h.err(&dev(), "mcp_gateway", echo.clone()).await), "read_profile_denied");
    assert_eq!(reason(&h.err(&reviewer(), "mcp_gateway", echo.clone()).await), "read_profile_denied");
    let anon = Caller::local("someone", Transport::Stdio);
    assert_eq!(reason(&h.err(&anon, "mcp_gateway", echo.clone()).await), "identity_required");
    // A human reads; an unattended routine under a human's label does not.
    let routine = caller("ops-1", ActorKind::Agent, Profile::Developer);
    assert_eq!(reason(&h.err(&routine, "mcp_gateway", echo.clone()).await), "read_profile_denied");
    h.ok(&caller("ops-1", ActorKind::Human, Profile::Developer), "mcp_gateway", echo.clone()).await;
    h.ok(&human(), "mcp_gateway", echo).await;
}

async fn a_write_approval_binds_the_injected_credential() {
    let h = H::new();
    h.set_secret("fake-token", "mcp:fake", TOKEN).await;
    h.register_stdio("fake", json!({})).await;
    let args = json!({ "server": "fake", "tool": "write_note", "arguments": { "text": "bound" } });
    let UaError::ApprovalRequired { approval_id, .. } = h.err(&dev(), "mcp_gateway", args.clone()).await
    else {
        panic!("expected an approval")
    };
    // The approval shows the credential's fingerprint, never its value.
    let fp = h.ok(&ops(), "managed_secret_list", json!({})).await["secrets"][0]["fingerprint"].clone();
    let pending = h.ok(&human(), "approval_pending", json!({})).await.to_string();
    assert!(pending.contains(fp.as_str().unwrap()) && !pending.contains(TOKEN), "{pending}");
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    // The credential is swapped after the approval: the pass no longer applies.
    let swap =
        json!({ "name": "fake-token", "consumer": "mcp:fake", "value": "attacker-chosen-token-value" });
    h.approved(&ops(), "managed_secret_set", swap).await;
    let e = h.err(&dev(), "mcp_gateway", args).await;
    assert_eq!(reason(&e), "approval_required");
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
    assert_eq!(l["tools"].as_array().unwrap().len(), 7);
    assert_eq!(l["live"], false);
    let outcomes: Vec<Value> =
        h.events("agent.mcp_gateway.call").iter().map(|e| e["outcome"].clone()).collect();
    assert_eq!(outcomes, [json!("tool_not_catalogued"), json!("not_found"), json!("ok")]);
}

async fn read_profiles_and_missing_secrets_refuse_reads() {
    let h = H::new();
    h.register_stdio("fake", json!({ "read_profiles": ["reviewer"] })).await;
    let e = h.err(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "echo" })).await;
    assert_eq!(reason(&e), "read_profile_denied");
    // The reviewer may read, but no secret is stored for the server yet.
    let e = h.err(&reviewer(), "mcp_gateway", json!({ "server": "fake", "tool": "echo" })).await;
    assert_eq!(reason(&e), "secret_unavailable");
    // A secret bound to another consumer is not handed over.
    h.set_secret("fake-token", "mcp:other", TOKEN).await;
    let e = h.err(&reviewer(), "mcp_gateway", json!({ "server": "fake", "tool": "echo" })).await;
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
    assert_eq!(revoked["orphaned_secrets"], json!(["fake-token"]));
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

async fn revoking_a_server_orphans_its_secrets() {
    let h = H::new();
    h.set_secret("fake-token", "mcp:fake", TOKEN).await;
    h.set_secret("unrelated", "mcp:other", "other-value").await;
    h.register_stdio("fake", json!({})).await;
    h.ok(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "echo" })).await;
    // The revocation's approval names the secrets it will delete.
    let UaError::ApprovalRequired { approval_id, .. } =
        h.err(&ops(), "mcp_server_revoke", json!({ "name": "fake" })).await
    else {
        panic!("expected an approval")
    };
    let pending = h.ok(&human(), "approval_pending", json!({})).await.to_string();
    assert!(pending.contains("orphaned_secrets") && pending.contains("fake-token"), "{pending}");
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let revoked = h.ok(&ops(), "mcp_server_revoke", json!({ "name": "fake" })).await;
    assert_eq!(revoked["orphaned_secrets"], json!(["fake-token"]));
    let list = h.ok(&ops(), "managed_secret_list", json!({})).await;
    assert_eq!(list["count"], 1, "only the other consumer's secret is left: {list}");
    assert_eq!(list["secrets"][0]["name"], "unrelated");
    let deleted = h.events("managed_secret.deleted");
    assert_eq!(deleted[0]["reason"], "mcp_server_revoked");
    assert_eq!(deleted[0]["approval_id"], approval_id);

    // The name registered again at another spec inherits no credential.
    let mut other = stdio_spec();
    other["args"] = json!([FAKE_FLAG, "--elsewhere"]);
    h.approved(&ops(), "mcp_server_register", json!({ "name": "fake", "server": other })).await;
    let e = h.err(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "echo" })).await;
    assert_eq!(reason(&e), "secret_unavailable");
    // It works once the operator sets the credential for the new registration.
    h.set_secret("fake-token", "mcp:fake", TOKEN).await;
    h.ok(&dev(), "mcp_gateway", json!({ "server": "fake", "tool": "echo" })).await;
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
            "read_profiles": ["developer"],
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
                "read_profiles": ["developer"],
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
    replacing_a_secret_needs_an_approval_bound_to_the_new_value,
    secret_admin_is_an_identity_not_a_profile,
    registration_needs_an_operator_and_a_human_approval,
    reads_run_and_secrets_are_injected_and_redacted,
    encoded_partial_and_split_echoes_are_redacted_or_withheld,
    writes_need_a_one_time_approval_bound_to_the_arguments,
    empty_read_profiles_mean_humans_and_operators_only,
    a_write_approval_binds_the_injected_credential,
    uncatalogued_tools_and_unknown_servers_are_refused,
    read_profiles_and_missing_secrets_refuse_reads,
    revoked_and_unreviewed_servers_are_refused,
    revoking_a_server_orphans_its_secrets,
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
