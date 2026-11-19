//! MCP adapter on the official `rmcp` SDK.
//!
//! Tool listing and calls are implemented by hand (not with the macro
//! router) so the list is filtered per caller profile and every call goes
//! through the governed registry.

use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use ua_core::Caller;
use ua_core::identity::Transport;
use ua_tools::ToolDef;

use crate::AppState;
use crate::auth::{AuthIdentity, LOCAL_LABEL, caller_for, session_key};

/// One MCP server instance. For stdio, `fixed_caller` is the local caller.
#[derive(Clone)]
pub struct UaMcp {
    state: AppState,
    fixed_caller: Option<Arc<Caller>>,
}

impl UaMcp {
    pub fn new(state: AppState) -> Self {
        Self { state, fixed_caller: None }
    }

    pub fn stdio(state: AppState, label: Option<String>) -> Self {
        let label = label.unwrap_or_else(|| LOCAL_LABEL.to_string());
        let caller = Caller::local(label, Transport::Stdio);
        Self { state, fixed_caller: Some(Arc::new(caller)) }
    }

    fn caller(&self, ctx: &RequestContext<RoleServer>) -> Caller {
        if let Some(c) = &self.fixed_caller {
            return (**c).clone();
        }
        let parts = ctx.extensions.get::<axum::http::request::Parts>();
        let id = parts.and_then(|p| p.extensions.get::<AuthIdentity>().cloned()).unwrap_or(AuthIdentity {
            label: LOCAL_LABEL.into(),
            kind: ua_core::ActorKind::Anonymous,
            verified: false,
        });
        let key = parts.and_then(|p| session_key(&p.headers));
        caller_for(&self.state, &id, key, Transport::Mcp)
    }
}

pub fn to_mcp_tool(def: &ToolDef) -> Tool {
    let schema = match &def.input_schema {
        Value::Object(m) => m.clone(),
        _ => serde_json::Map::new(),
    };
    let mut tool = Tool::new(def.name, def.description, Arc::new(schema));
    tool.annotations = Some(ToolAnnotations::new().read_only(def.read_only).destructive(def.always_gated));
    tool
}

impl ServerHandler for UaMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ua-rust", env!("CARGO_PKG_VERSION")))
            .with_instructions(crate::INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let caller = self.caller(&ctx);
        let tools = self.state.registry.visible_to(&caller).map(to_mcp_tool).collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let caller = self.caller(&ctx);
        let args = request.arguments.map(Value::Object).unwrap_or(Value::Null);
        let result = self.state.registry.call(&self.state.hub, &caller, &request.name, args).await;
        Ok(match result {
            Ok(v) => CallToolResult::structured(v),
            Err(e) => CallToolResult::structured_error(e.to_json()),
        }
        .into())
    }
}

/// The Streamable HTTP service mounted at `/mcp`.
pub fn http_service(
    state: AppState,
    ct: CancellationToken,
) -> StreamableHttpService<UaMcp, LocalSessionManager> {
    let hosts = state.hub.cfg().allowed_hosts.clone();
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(hosts)
        .with_legacy_session_mode(true)
        .with_cancellation_token(ct);
    StreamableHttpService::new(move || Ok(UaMcp::new(state.clone())), Default::default(), config)
}

/// Serve MCP over stdin/stdout until the client disconnects.
pub async fn serve_stdio(state: AppState, label: Option<String>) -> anyhow::Result<()> {
    let server = UaMcp::stdio(state, label).serve(rmcp::transport::stdio()).await?;
    server.waiting().await?;
    Ok(())
}
