//! Tool definitions, the registry and the governed call wrapper.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use ua_core::{Caller, UaError, UaResult};
use ua_store::{EventInput, ledger};

use crate::approvals::{self, GateOutcome};
use crate::hub::Hub;

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
    handler: Handler,
}

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
    /// caller's session enforces it; legacy aliases are then hidden too.
    pub fn visible_to<'a>(&'a self, caller: &'a Caller) -> impl Iterator<Item = &'a ToolDef> + 'a {
        self.tools.values().filter(move |t| {
            !caller.enforce_profile
                || (caller.profile.allows_tool(t.name) && !ua_core::Profile::is_legacy_alias(t.name))
        })
    }

    /// The governed call path. See the crate docs for the order of checks.
    pub async fn call(&self, hub: &Hub, caller: &Caller, name: &str, args: Value) -> UaResult<Value> {
        let Some(def) = self.tools.get(name) else {
            return Err(UaError::not_found(format!("unknown tool {name:?}")));
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

        let gated = def.always_gated || hub.cfg().approval_tools.iter().any(|t| t == name);
        if gated {
            let (h, c, n, a) = (hub.clone(), caller.clone(), name.to_string(), args.clone());
            let outcome = hub.db().write_async(move |tx| approvals::gate(tx, h.cfg(), &c, &n, &a)).await?;
            match outcome {
                GateOutcome::Pass { .. } => {}
                GateOutcome::Pending { approval_id } => {
                    return Err(UaError::ApprovalRequired { tool: name.to_string(), approval_id });
                }
                GateOutcome::Denied { approval_id, reason } => {
                    let err = UaError::denied(
                        "approval_denied",
                        format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                    );
                    record_decision(hub, caller, name, &err).await;
                    return Err(err);
                }
            }
        }

        let ctx = ToolCtx { hub: hub.clone(), caller: caller.clone() };
        (def.handler)(ctx, args).await
    }
}

async fn record_decision(hub: &Hub, caller: &Caller, tool: &str, err: &UaError) {
    let reason_code = match err {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    };
    let payload = json!({
        "tool": tool,
        "decision": "deny",
        "reason_code": reason_code,
        "reason": err.to_string(),
        "profile": caller.profile.as_str(),
    });
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
