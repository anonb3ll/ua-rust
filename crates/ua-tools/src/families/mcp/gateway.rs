//! `mcp_gateway`: call a tool on a registered downstream MCP server.
//!
//! The caller names a registered server and one of its catalogued tools;
//! never a URL, a command or a credential. In order, a call:
//!
//! 1. resolves the server (registry or config) and refuses it when it is
//!    revoked, past its review window, or misconfigured;
//! 2. refuses a tool the registration does not classify;
//! 3. refuses another organization's caller on every server, stdio or
//!    Streamable HTTP, secrets or not: each is the hub's process, network
//!    position or credential (a static `list` reads only the registration
//!    and is not refused);
//!    for a read, refuses an anonymous caller when the server injects secrets
//!    and checks the caller against `read_profiles` (empty: humans and
//!    configured operator identities); for a write, needs an authenticated
//!    caller who passes the prod-action checks;
//! 4. runs the policy file under `mcp_gateway.<server>.<tool>`, so a rule on
//!    one downstream tool holds however the gateway is reached;
//! 5. takes one of the server's [`MAX_CONCURRENT_PER_SERVER`] call slots (a
//!    busy server refuses rather than queues, and never spends an approval);
//! 6. decrypts the server's managed secrets (consumer `mcp:<server>`), so a
//!    missing secret also fails before an approval is spent;
//! 7. for a write (or a policy `require_approval`), consumes a one-time human
//!    approval bound to the server, tool, exact arguments, spec hash and the
//!    keyed fingerprint of every injected secret (so a credential swapped
//!    after the approval needs a new one), then injects the secrets by
//!    reference: a bearer or header for HTTP, an environment variable for a
//!    stdio child;
//! 8. connects with the rmcp client and calls the tool under the server's
//!    timeout: a stdio child with a cleared environment in its own process
//!    group, killed with its group afterwards; or Streamable HTTP through a
//!    client that ignores proxies, follows no redirect and resolves only the
//!    registered host, inside its address scope;
//! 9. scrubs every injected secret, its encodings and long partial echoes
//!    from the result and from error text (see [`super::redact`]), and
//!    withholds a result that still holds a fragment it cannot redact
//!    cleanly; keeps text blocks only, caps the result at
//!    [`MAX_RESPONSE_BYTES`] and labels it untrusted;
//! 10. writes one `agent.mcp_gateway.call` ledger event whatever happened:
//!     action, server, tool, access, sizes, outcome, latency and any approval
//!     id; never the arguments, the result or a secret.
//!
//! Wire bounds: a stdio line (one JSON-RPC message) is at most
//! [`MAX_WIRE_BYTES`] and a stdio call reads at most [`MAX_WIRE_TOTAL_BYTES`];
//! an HTTP JSON body or SSE event is at most [`MAX_WIRE_BYTES`].

use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, PaginatedRequestParams};
use rmcp::service::{RoleClient, RunningService, ServiceError};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::async_rw::AsyncRwTransport;
use rmcp::transport::common::client_side_sse::NeverRetry;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use ua_core::{ActorKind, Caller, UaError, UaResult};
use ua_store::{EventInput, ledger};

use super::redact::Redactor;
use super::scope::{self, PinnedResolver};
use super::{Access, Inject, Server, TransportKind, check_server_name, resolve};
use crate::approvals::{self, GateOutcome};
use crate::families::dispatch::executor::looks_secret;
use crate::families::injection::mark_untrusted;
use crate::families::managed_secrets::{self, mcp_consumer};
use crate::policy::{self, Verdict};
use crate::registry::{Registry, ToolCtx, tool};

/// Ledger channel: one event per gateway call.
pub const CALL_CHANNEL: &str = "agent.mcp_gateway.call";
/// The approval-queue name of a downstream write. Distinct from the tool's
/// own name, so a pass approves one downstream write, not any gateway call.
pub const APPROVAL_TOOL: &str = "mcp_gateway_write";
pub const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_WIRE_BYTES: usize = 1024 * 1024;
pub const MAX_WIRE_TOTAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CONCURRENT_PER_SERVER: usize = 4;
const MAX_LIST_PAGES: usize = 20;
const MAX_DESCRIPTION_CHARS: usize = 2000;
const MAX_ERROR_CHARS: usize = 500;
const WITHHELD: &str = "the downstream result held part of an injected credential that could not be redacted \
                        cleanly; it was withheld";
/// Parent environment a stdio child may inherit (when it does not look secret).
const CHILD_ENV: &[&str] =
    &["PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ", "XDG_RUNTIME_DIR"];

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GatewayArgs {
    /// `call` (default): run one catalogued tool. `list`: the server's
    /// catalogued tools and their read/write class.
    pub action: Option<String>,
    /// A registered server name (see mcp_server_list).
    pub server: String,
    /// call: the downstream tool name.
    pub tool: Option<String>,
    /// call: the downstream tool's arguments (a JSON object, at most 64 KB).
    pub arguments: Option<Map<String, Value>>,
    /// list: also ask the server for each catalogued tool's description and
    /// input schema. Counts as a read.
    #[serde(default)]
    pub live: bool,
}

/// What the ledger event records about one call.
#[derive(Default)]
struct Trace {
    action: &'static str,
    server: String,
    tool: Option<String>,
    access: Option<Access>,
    args_bytes: usize,
    result_bytes: Option<usize>,
    approval_id: Option<i64>,
    truncated: bool,
    downstream_error: bool,
    withheld: bool,
}

fn fail(code: &str, msg: impl Into<String>) -> UaError {
    UaError::conflict_code(code, msg)
}

fn outcome_of(res: &UaResult<Value>, t: &Trace) -> String {
    match res {
        Ok(_) if t.withheld => "withheld".into(),
        Ok(_) if t.downstream_error => "downstream_error".into(),
        Ok(_) if t.truncated => "ok_truncated".into(),
        Ok(_) => "ok".into(),
        Err(UaError::ApprovalRequired { .. }) => "approval_pending".into(),
        Err(e) => e.reason_code().unwrap_or(e.code()).to_string(),
    }
}

async fn mcp_gateway(ctx: ToolCtx, a: GatewayArgs) -> UaResult<Value> {
    let started = Instant::now();
    let mut t = Trace { action: "call", server: a.server.chars().take(64).collect(), ..Default::default() };
    let res = execute(&ctx, a, &mut t).await;
    let outcome = outcome_of(&res, &t);
    let payload = json!({
        "action": t.action,
        "server": t.server,
        "tool": t.tool,
        "access": t.access.map(Access::as_str),
        "caller": ctx.caller.label,
        "args_bytes": t.args_bytes,
        "result_bytes": t.result_bytes,
        "outcome": outcome,
        "approval_id": t.approval_id,
        "latency_ms": started.elapsed().as_millis() as u64,
    });
    let by = ctx.caller.label.clone();
    let recorded = ctx
        .hub
        .db()
        .write_async(move |tx| {
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, CALL_CHANNEL, payload).by(by))?;
            Ok(())
        })
        .await;
    if let Err(e) = recorded {
        tracing::warn!(error = %e, "could not record an mcp_gateway call");
    }
    res
}

async fn execute(ctx: &ToolCtx, a: GatewayArgs, t: &mut Trace) -> UaResult<Value> {
    t.action = match crate::routes::action_of("mcp_gateway", a.action.as_deref())? {
        "call" => "call",
        "list" => "list",
        other => return Err(crate::routes::unhandled("mcp_gateway", other)),
    };
    check_server_name(&a.server)?;
    let (cfg, name) = (ctx.hub.cfg().clone(), a.server.clone());
    let server = ctx.hub.db().read_async(move |c| resolve(c, &cfg, &name)).await?;
    server.usable()?;
    if t.action == "call" || a.live {
        require_hub_org_for_server(ctx, &server)?;
    }
    if t.action == "list" {
        return list(ctx, &server, a.live, t).await;
    }
    let tool =
        a.tool.filter(|s| !s.is_empty()).ok_or_else(|| UaError::invalid("action call needs a tool"))?;
    t.tool = Some(tool.chars().take(128).collect());
    let access = *server.spec.tools.get(&tool).ok_or_else(|| {
        UaError::denied(
            "tool_not_catalogued",
            format!(
                "tool {:?} is not catalogued for MCP server {:?}; catalogued: {}",
                t.tool.as_deref().unwrap_or(""),
                server.name,
                server.spec.tools.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        )
    })?;
    t.access = Some(access);
    let arguments = a.arguments.unwrap_or_default();
    t.args_bytes = serde_json::to_string(&arguments).map(|s| s.len()).unwrap_or(0);
    if t.args_bytes > MAX_ARGUMENT_BYTES {
        return Err(UaError::invalid(format!("arguments exceed {MAX_ARGUMENT_BYTES} bytes")));
    }
    match access {
        Access::Read => check_reader(ctx, &server)?,
        Access::Write => check_writer(ctx, &ctx.caller)?,
    }
    let policy_name = format!("mcp_gateway.{}.{}", server.name, tool);
    let mut gate_args = json!({
        "server": server.name, "tool": tool, "access": access.as_str(),
        "arguments": Value::Object(arguments.clone()), "spec_sha256": server.spec_sha256,
    });
    let policy_gated = check_policy(ctx, &policy_name, &gate_args).await?;
    let _slot = try_slot(&server.name)?;
    // Before the approval: a call bound to fail must not spend a pass.
    let (secrets, fingerprints) = load_secrets(ctx, &server).await?;
    let forms = redactor(&secrets);
    // The approval binds the credentials as well: a secret replaced after the
    // human approved the call needs a fresh approval.
    gate_args["secrets"] = json!(fingerprints);
    if access == Access::Write || policy_gated {
        let gate_tool = if access == Access::Write { APPROVAL_TOOL.to_string() } else { policy_name };
        t.approval_id = Some(approval(ctx, &gate_tool, gate_args).await?);
    }
    let call = async {
        let mut session = open(&server, &secrets).await?;
        let params = CallToolRequestParams::new(tool.clone()).with_arguments(arguments);
        let res = session.svc.peer().call_tool(params).await;
        session.close().await;
        res.map_err(|e| service_failure(e, &session.too_large, &forms))
    };
    let result = match tokio::time::timeout(server.spec.timeout(), call).await {
        Ok(r) => r?,
        Err(_) => return Err(timeout_failure(&server)),
    };
    let raw = serde_json::to_value(&result).unwrap_or(Value::Null);
    t.downstream_error = result.is_error.unwrap_or(false);
    let mut out = json!({
        "server": server.name,
        "tool": tool,
        "access": access.as_str(),
        "is_error": t.downstream_error,
        "content": text_blocks(&raw),
    });
    if let Some(sc) = raw.get("structuredContent").filter(|v| !v.is_null()) {
        out["structured_content"] = sc.clone();
    }
    // Redact before capping, so a cut can never leave part of a credential.
    // The text blocks are read in order: a value split across them is a leak
    // no per-block redaction removes cleanly.
    let texts: Vec<String> = out["content"]
        .as_array()
        .map(|a| a.iter().filter_map(|b| b["text"].as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let split = forms.crosses(&texts.iter().map(String::as_str).collect::<Vec<_>>());
    if forms.scrub_value(&mut out) || split {
        t.withheld = true;
        out = json!({
            "server": server.name,
            "tool": tool,
            "access": access.as_str(),
            "is_error": true,
            "withheld": true,
            "content": [{ "type": "text", "text": WITHHELD }],
        });
    }
    t.truncated = cap(&mut out);
    finish(&mut out, &server.name, t);
    Ok(out)
}

/// The untrusted label and the recorded size.
fn finish(out: &mut Value, server: &str, t: &mut Trace) {
    out["untrusted"] = json!(true);
    if t.truncated {
        out["truncated"] = json!(true);
    }
    mark_untrusted(out, "mcp_gateway", Some(server));
    t.result_bytes = serde_json::to_string(out).map(|s| s.len()).ok();
}

async fn list(ctx: &ToolCtx, server: &Server, live: bool, t: &mut Trace) -> UaResult<Value> {
    let mut rows: Vec<Value> = server
        .spec
        .tools
        .iter()
        .map(|(name, access)| json!({ "name": name, "access": access.as_str() }))
        .collect();
    let mut out = json!({ "server": server.name, "status": server.status(), "live": live });
    if live {
        t.access = Some(Access::Read);
        check_reader(ctx, server)?;
        let _slot = try_slot(&server.name)?;
        let (secrets, _) = load_secrets(ctx, server).await?;
        let forms = redactor(&secrets);
        let fetch = async {
            let mut session = open(server, &secrets).await?;
            let res = list_pages(&session.svc).await;
            session.close().await;
            res.map_err(|e| service_failure(e, &session.too_large, &forms))
        };
        let downstream = match tokio::time::timeout(server.spec.timeout(), fetch).await {
            Ok(r) => r?,
            Err(_) => return Err(timeout_failure(server)),
        };
        let mut uncatalogued = 0usize;
        let mut found: HashMap<String, Value> = HashMap::new();
        for tool in downstream {
            if server.spec.tools.contains_key(tool.name.as_ref()) {
                let description: String =
                    tool.description.as_deref().unwrap_or("").chars().take(MAX_DESCRIPTION_CHARS).collect();
                found.insert(
                    tool.name.to_string(),
                    json!({ "description": description, "input_schema": Value::Object((*tool.input_schema).clone()) }),
                );
            } else {
                uncatalogued += 1;
            }
        }
        for row in &mut rows {
            let name = row["name"].as_str().unwrap_or("").to_string();
            match found.remove(&name) {
                Some(extra) => {
                    row["present"] = json!(true);
                    row["description"] = extra["description"].clone();
                    row["input_schema"] = extra["input_schema"].clone();
                }
                None => row["present"] = json!(false),
            }
        }
        out["uncatalogued_count"] = json!(uncatalogued);
        out["tools"] = json!(rows);
        if forms.scrub_value(&mut out) {
            t.withheld = true;
            return Err(fail("result_withheld", WITHHELD));
        }
        t.truncated = cap(&mut out);
    } else {
        out["tools"] = json!(rows);
    }
    finish(&mut out, &server.name, t);
    Ok(out)
}

async fn list_pages(svc: &RunningService<RoleClient, ()>) -> Result<Vec<rmcp::model::Tool>, ServiceError> {
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_LIST_PAGES {
        let params = cursor.take().map(|c| PaginatedRequestParams::default().with_cursor(Some(c)));
        let page = svc.peer().list_tools(params).await?;
        tools.extend(page.tools);
        match page.next_cursor {
            Some(c) if !c.is_empty() => cursor = Some(c),
            _ => break,
        }
    }
    Ok(tools)
}

// --- checks ----------------------------------------------------------------------

fn check_reader(ctx: &ToolCtx, server: &Server) -> UaResult<()> {
    let caller = &ctx.caller;
    if server.spec.reads_allowed(ctx.hub.cfg(), caller) {
        return Ok(());
    }
    if caller.kind == ActorKind::Anonymous && !server.spec.secrets.is_empty() {
        return Err(UaError::denied(
            "identity_required",
            format!(
                "MCP server {:?} uses managed credentials; reading from it needs an authenticated caller",
                server.name
            ),
        ));
    }
    let allowed = if server.spec.read_profiles.is_empty() {
        "operators, that is verified humans (read_profiles is empty)".to_string()
    } else {
        server.spec.read_profiles.join(", ")
    };
    Err(UaError::denied(
        "read_profile_denied",
        format!(
            "{} (profile {}) may not read from MCP server {:?}; allowed: {allowed}",
            caller.label, caller.profile, server.name
        ),
    ))
}

fn check_writer(ctx: &ToolCtx, caller: &Caller) -> UaResult<()> {
    if !matches!(caller.kind, ActorKind::Agent | ActorKind::Human) {
        return Err(UaError::denied(
            "identity_required",
            "a downstream write needs an authenticated caller; authenticate first",
        ));
    }
    policy::check_prod_action(ctx.hub.cfg(), caller, APPROVAL_TOOL).map_err(|r| r.error)
}

/// The policy file under the canonical downstream name. `true` when a rule
/// requires an approval.
async fn check_policy(ctx: &ToolCtx, name: &str, args: &Value) -> UaResult<bool> {
    let Some(path) = ctx.hub.cfg().policy_file.clone() else { return Ok(false) };
    let p = policy::load(&path).map_err(|reason| {
        UaError::denied("policy_unavailable", format!("policy gate failed closed: {reason}"))
    })?;
    let (caller, name, args) = (ctx.caller.clone(), name.to_string(), args.clone());
    let verdict =
        ctx.hub.db().read_async(move |c| Ok(policy::evaluate(c, &p, &caller, &name, &args))).await?;
    match verdict {
        Ok(Verdict::Allow) => Ok(false),
        Ok(Verdict::RequireApproval(_)) => Ok(true),
        Err(refusal) => Err(refusal.error),
    }
}

/// Consume a one-time pass for `payload`, or park the request.
async fn approval(ctx: &ToolCtx, gate_tool: &str, payload: Value) -> UaResult<i64> {
    let (hub, caller, gt) = (ctx.hub.clone(), ctx.caller.clone(), gate_tool.to_string());
    let outcome =
        ctx.hub.db().write_async(move |tx| approvals::gate(tx, hub.cfg(), &caller, &gt, &payload)).await?;
    match outcome {
        GateOutcome::Pass { approval_id } => Ok(approval_id),
        GateOutcome::Pending { approval_id } => {
            Err(UaError::ApprovalRequired { tool: gate_tool.to_string(), approval_id })
        }
        GateOutcome::Denied { approval_id, reason } => Err(UaError::denied(
            "approval_denied",
            format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
        )),
    }
}

static SLOTS: LazyLock<Mutex<HashMap<String, Arc<Semaphore>>>> = LazyLock::new(Default::default);

fn try_slot(server: &str) -> UaResult<OwnedSemaphorePermit> {
    let sem = {
        let mut slots = SLOTS.lock().map_err(|_| UaError::internal("gateway slots poisoned"))?;
        slots
            .entry(server.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_CONCURRENT_PER_SERVER)))
            .clone()
    };
    sem.try_acquire_owned().map_err(|_| {
        UaError::denied(
            "server_busy",
            format!("MCP server {server:?} is at its concurrent call limit; retry shortly"),
        )
    })
}

// --- secrets ----------------------------------------------------------------------

/// Every downstream server is the hub's, the default organization's: a
/// stdio server is a process the hub spawns on its own host, with the hub's
/// filesystem and network; a Streamable HTTP server is reached from the
/// hub's network position (loopback, tailnet and private ranges a server's
/// `address_scope` admits), secrets or not; and an injected credential is
/// the default organization's managed secret. Another organization's caller
/// is therefore refused every `call` and live `list`, on every server,
/// before the policy check, the slot, any approval, any secret read and any
/// spawn or connection, until servers are per organization. A static `list`
/// reads only the registration, which `mcp_server_list` already shows, and
/// is not refused.
fn require_hub_org_for_server(ctx: &ToolCtx, server: &Server) -> UaResult<()> {
    if ctx.caller.org_id == super::HUB_SECRETS_ORG {
        return Ok(());
    }
    Err(UaError::denied(
        "org_unsupported",
        format!(
            "MCP server {:?} is the hub's: it runs as a process on the hub or is reached from the hub's \
             network, with the hub's credentials, and serves the default organization only; nothing was \
             read, started or sent",
            server.name
        ),
    ))
}

/// The injected secrets, and each one's keyed fingerprint by name.
type Loaded = (Vec<(Inject, SecretString)>, BTreeMap<String, String>);

async fn load_secrets(ctx: &ToolCtx, server: &Server) -> UaResult<Loaded> {
    let (cfg, name, refs) = (ctx.hub.cfg().clone(), server.name.clone(), server.spec.secrets.clone());
    ctx.hub
        .db()
        .read_async(move |c| {
            let consumer = mcp_consumer(&name);
            let (mut out, mut fingerprints) = (Vec::new(), BTreeMap::new());
            for r in refs {
                let inject = r.parse()?;
                let loaded =
                    managed_secrets::load_for_consumer(c, &cfg, super::HUB_SECRETS_ORG, &r.secret, &consumer);
                let (value, fp) = loaded.map_err(|e| {
                    UaError::denied(
                        "secret_unavailable",
                        format!(
                            "the hub has no usable credential {:?} (consumer {consumer:?}) for MCP server {name:?}: {}",
                            r.secret,
                            e.reason_code().unwrap_or(e.code())
                        ),
                    )
                })?;
                if value.expose_secret().contains(['\0', '\r', '\n']) {
                    return Err(UaError::denied(
                        "secret_unusable",
                        format!("managed secret {:?} holds a line break or NUL and cannot be injected", r.secret),
                    ));
                }
                fingerprints.insert(r.secret.clone(), fp);
                out.push((inject, value));
            }
            Ok((out, fingerprints))
        })
        .await
}

fn redactor(secrets: &[(Inject, SecretString)]) -> Redactor {
    Redactor::new(secrets.iter().map(|(_, s)| s.expose_secret()))
}

// --- result shaping ---------------------------------------------------------------

/// Text blocks as `{type: "text", text}`; anything else as `{type, omitted: true}`.
fn text_blocks(raw: &Value) -> Value {
    let blocks = raw.get("content").and_then(Value::as_array).cloned().unwrap_or_default();
    Value::Array(
        blocks
            .iter()
            .map(|b| match b.get("type").and_then(Value::as_str) {
                Some("text") => {
                    json!({ "type": "text", "text": b.get("text").and_then(Value::as_str).unwrap_or("") })
                }
                other => json!({ "type": other.unwrap_or("unknown"), "omitted": true }),
            })
            .collect(),
    )
}

/// Cap content plus structured content at [`MAX_RESPONSE_BYTES`]: past it,
/// the text is joined and cut on a character boundary. `true` when cut.
fn cap(out: &mut Value) -> bool {
    let size = |v: &Value| serde_json::to_string(v).map(|s| s.len()).unwrap_or(usize::MAX);
    let total = size(&out["content"]) + out.get("structured_content").map(size).unwrap_or(0);
    let total = total + out.get("tools").map(size).unwrap_or(0);
    if total <= MAX_RESPONSE_BYTES {
        return false;
    }
    if let Some(tools) = out.get_mut("tools").and_then(Value::as_array_mut) {
        for row in tools.iter_mut() {
            if let Some(m) = row.as_object_mut() {
                m.remove("input_schema");
            }
        }
        return true;
    }
    if let Some(m) = out.as_object_mut() {
        m.remove("structured_content");
    }
    let joined: String = out["content"]
        .as_array()
        .map(|a| {
            a.iter().filter_map(|b| b.get("text").and_then(Value::as_str)).collect::<Vec<_>>().join("\n")
        })
        .unwrap_or_default();
    let mut end = MAX_RESPONSE_BYTES.min(joined.len());
    while !joined.is_char_boundary(end) {
        end -= 1;
    }
    out["content"] = json!([{ "type": "text", "text": &joined[..end] }]);
    true
}

// --- connections -----------------------------------------------------------------

/// An open client session and, for stdio, the child it owns.
struct Session {
    svc: RunningService<RoleClient, ()>,
    _child: Option<ChildGuard>,
    too_large: Arc<AtomicBool>,
}

impl Session {
    /// End the session; the child and its process group go with the guard.
    async fn close(&mut self) {
        let _ = tokio::time::timeout(Duration::from_millis(500), self.svc.close()).await;
    }
}

/// Kills a stdio child's whole process group when dropped (a finished call,
/// a timeout, or an error), so nothing it forked outlives the call.
struct ChildGuard {
    child: tokio::process::Child,
    #[cfg_attr(not(unix), allow(dead_code))]
    pgid: Option<u32>,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pgid) = self.pgid
            && let Ok(pgid) = i32::try_from(pgid)
            && pgid > 1
        {
            // SAFETY: killpg only sends a signal; the group is the child's own.
            unsafe {
                libc::killpg(pgid, libc::SIGKILL);
            }
        }
        let _ = self.child.start_kill();
    }
}

/// Counts bytes from a stdio child: at most [`MAX_WIRE_BYTES`] per line and
/// [`MAX_WIRE_TOTAL_BYTES`] per call, then an error that ends the session.
struct CappedReader<R> {
    inner: R,
    total: usize,
    line: usize,
    too_large: Arc<AtomicBool>,
}

impl<R: AsyncRead + Unpin> AsyncRead for CappedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let fresh = buf.filled()[before..].to_vec();
            self.total += fresh.len();
            for b in fresh {
                self.line = if b == b'\n' { 0 } else { self.line + 1 };
                if self.line > MAX_WIRE_BYTES {
                    break;
                }
            }
            if self.total > MAX_WIRE_TOTAL_BYTES || self.line > MAX_WIRE_BYTES {
                self.too_large.store(true, Ordering::SeqCst);
                return Poll::Ready(Err(std::io::Error::other("downstream output too large")));
            }
        }
        res
    }
}

fn install_crypto_provider() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

async fn open(server: &Server, secrets: &[(Inject, SecretString)]) -> UaResult<Session> {
    match server.spec.transport {
        TransportKind::Stdio => open_stdio(server, secrets).await,
        TransportKind::StreamableHttp => open_http(server, secrets).await,
    }
}

async fn open_stdio(server: &Server, secrets: &[(Inject, SecretString)]) -> UaResult<Session> {
    let spec = &server.spec;
    let mut cmd = tokio::process::Command::new(spec.command.as_deref().unwrap_or(""));
    cmd.args(&spec.args).env_clear();
    for k in CHILD_ENV {
        if let Ok(v) = std::env::var(k)
            && !looks_secret(k)
        {
            cmd.env(k, v);
        }
    }
    cmd.envs(&spec.env);
    for (inject, value) in secrets {
        if let Inject::Env(name) = inject {
            cmd.env(name, value.expose_secret());
        }
    }
    cmd.current_dir(spec.cwd.as_deref().map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd
        .spawn()
        .map_err(|_| fail("spawn_failed", "the downstream MCP server process could not be started"))?;
    let pgid = child.id();
    let (Some(stdout), Some(stdin)) = (child.stdout.take(), child.stdin.take()) else {
        return Err(fail("spawn_failed", "the downstream MCP server process has no pipes"));
    };
    let guard = ChildGuard { child, pgid };
    let too_large = Arc::new(AtomicBool::new(false));
    let reader = CappedReader { inner: stdout, total: 0, line: 0, too_large: too_large.clone() };
    let transport = AsyncRwTransport::new_client(reader, stdin).with_max_line_length(MAX_WIRE_BYTES + 1);
    let svc = ().serve(transport).await.map_err(|_| connect_failure(&too_large))?;
    Ok(Session { svc, _child: Some(guard), too_large })
}

async fn open_http(server: &Server, secrets: &[(Inject, SecretString)]) -> UaResult<Session> {
    let ep = server.spec.endpoint()?;
    let refused = |why: String| fail("address_refused", format!("MCP server {:?}: {why}", server.name));
    match ep.literal {
        Some(ip) if !scope::allowed(ip, ep.scope) => {
            return Err(refused(format!("{ip} is outside its registered {} scope", ep.scope.as_str())));
        }
        Some(_) => {}
        // Fail early with a clear reason; the resolver repeats the check on
        // the addresses the connection actually uses.
        None => {
            scope::resolve_in_scope(&ep.host, ep.scope)
                .await
                .map_err(|e| refused(e.trim_start_matches("address_refused: ").to_string()))?;
        }
    }
    install_crypto_provider();
    let client = reqwest::Client::builder()
        .user_agent(concat!("ua-rust-mcp-gateway/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .timeout(server.spec.timeout())
        .dns_resolver(PinnedResolver { host: ep.host.clone(), scope: ep.scope })
        .build()
        .map_err(|_| UaError::internal("cannot build the MCP gateway HTTP client"))?;
    let mut config = StreamableHttpClientTransportConfig::with_uri(ep.url.as_str().to_string())
        .max_json_response_size(MAX_WIRE_BYTES)
        .max_sse_event_size(MAX_WIRE_BYTES)
        .max_error_response_size(4096);
    config.retry_config = Arc::new(NeverRetry::default());
    let mut headers = HashMap::new();
    for (inject, value) in secrets {
        match inject {
            Inject::Bearer => config = config.auth_header(value.expose_secret().to_string()),
            Inject::Header(name) => {
                let n = reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                    fail("secret_unusable", format!("header {name:?} is not a valid header name"))
                })?;
                let mut v = reqwest::header::HeaderValue::from_str(value.expose_secret()).map_err(|_| {
                    fail(
                        "secret_unusable",
                        format!("the secret for header {name:?} is not a valid header value"),
                    )
                })?;
                v.set_sensitive(true);
                headers.insert(n, v);
            }
            Inject::Env(_) => {}
        }
    }
    let config = config.custom_headers(headers);
    let transport = StreamableHttpClientTransport::with_client(client, config);
    let too_large = Arc::new(AtomicBool::new(false));
    let svc = ().serve(transport).await.map_err(|_| connect_failure(&too_large))?;
    Ok(Session { svc, _child: None, too_large })
}

// --- failures (fixed, secret-free messages) ----------------------------------------

fn connect_failure(too_large: &AtomicBool) -> UaError {
    if too_large.load(Ordering::SeqCst) {
        return too_large_failure();
    }
    fail("connect_failed", "could not open an MCP session with the downstream server")
}

fn too_large_failure() -> UaError {
    fail(
        "response_too_large",
        format!(
            "the downstream response is too large (over {MAX_WIRE_BYTES} bytes per message or \
             {MAX_WIRE_TOTAL_BYTES} per call); refused"
        ),
    )
}

fn timeout_failure(server: &Server) -> UaError {
    fail(
        "downstream_timeout",
        format!(
            "the call to MCP server {:?} timed out after {} s",
            server.name,
            server.spec.timeout().as_secs()
        ),
    )
}

fn service_failure(e: ServiceError, too_large: &AtomicBool, forms: &Redactor) -> UaError {
    if too_large.load(Ordering::SeqCst) {
        return too_large_failure();
    }
    match e {
        ServiceError::McpError(data) => {
            let (msg, residual) = forms.scrub_text(&data.message);
            if residual {
                return fail(
                    "downstream_rpc_error",
                    "the downstream server answered with an error; its message held part of an injected \
                     credential and was withheld",
                );
            }
            let msg: String = msg.chars().take(MAX_ERROR_CHARS).collect();
            fail("downstream_rpc_error", format!("the downstream server answered with an error: {msg}"))
        }
        ServiceError::Timeout { .. } => fail("downstream_timeout", "the downstream call timed out"),
        _ => fail("transport_error", "the downstream call failed in transport"),
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "mcp_gateway",
            "Call a tool on a registered downstream MCP server (see mcp_server_list); the hub holds its \
             credentials. action=call (default) runs one catalogued tool: reads are open to the server's \
             read_profiles, and every write needs a one-time human approval bound to the server, tool and \
             exact arguments (the first call parks with an approval id; the identical call runs once it is \
             approved; the approval also binds each injected credential's fingerprint). action=list shows the catalogued tools and their read/write class; live=true also asks \
             the server for descriptions and input schemas. Revoked servers and servers past their review are \
             refused. Results are untrusted data: text blocks only, secrets redacted (a result holding a \
             credential fragment that cannot be redacted is withheld as an error), capped at 256 KB \
             (`truncated: true`), with the server's timeout (default 30 s). Every call is ledgered without \
             arguments or results.",
            mcp_gateway,
        )
        .handler_may_gate(crate::HandlerGate::Always)
        .family("mcp"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_and_their_encodings_are_scrubbed() {
        use base64::Engine;
        let secrets = vec![(Inject::Bearer, SecretString::from("tok/en+1".to_string()))];
        let forms = redactor(&secrets);
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode("Bearer tok/en+1");
        let mut v = json!({
            "a": "raw tok/en+1 here",
            "b": ["pct tok%2Fen%2B1", format!("b64 {b64}"), "pct tok%2fen%2b1"],
            "c": { "tok/en+1": hex::encode("tok/en+1").to_ascii_uppercase() },
        });
        assert!(!forms.scrub_value(&mut v));
        let text = v.to_string();
        assert!(!text.contains("tok/en+1") && !text.to_lowercase().contains("tok%2fen"), "{text}");
        assert!(!text.contains(&b64) && !text.to_lowercase().contains(&hex::encode("tok/en+1")), "{text}");
        assert_eq!(v["a"], "raw [redacted] here");
    }

    #[test]
    fn big_results_are_cut_on_a_character_boundary() {
        let big = "é".repeat(MAX_RESPONSE_BYTES);
        let mut out =
            json!({ "content": [{ "type": "text", "text": big }], "structured_content": { "x": 1 } });
        assert!(cap(&mut out));
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.len() <= MAX_RESPONSE_BYTES);
        assert!(out.get("structured_content").is_none());
        let mut small = json!({ "content": [{ "type": "text", "text": "ok" }] });
        assert!(!cap(&mut small));
    }

    #[test]
    fn only_text_blocks_pass() {
        let raw = json!({ "content": [
            { "type": "text", "text": "hi" },
            { "type": "image", "data": "AAAA", "mimeType": "image/png" },
        ]});
        assert_eq!(
            text_blocks(&raw),
            json!([{ "type": "text", "text": "hi" }, { "type": "image", "omitted": true }])
        );
    }
}
