//! The authority of one request made with a session credential (`uas_…`).
//!
//! A session credential is minted for one claimed ACP node item (see
//! `families::node_queue::credentials`). The HTTP adapter verifies it on
//! every request and runs the request's registry calls inside
//! [`scope`], so [`Registry::call`](crate::Registry::call) and
//! [`Registry::visible_to`](crate::Registry::visible_to) see the grant
//! through [`current`]. The caller's profile is `acp-session` as well, so
//! a call outside a scope is still held to that profile's tool list.
//!
//! The grant narrows, never widens: a tool must be in `tools`, and
//! `task_comment` may only `append` to or `list` the credential's own task.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;

use serde_json::Value;
use ua_core::{UaError, UaResult};

/// What a verified session credential may do on this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionGrant {
    /// The effective tool set: the `acp-session` list, intersected with the
    /// subject's own profile and the credential's stored list.
    pub tools: BTreeSet<String>,
    /// The public handle of the credential (16 hex characters).
    pub credential_id: String,
    /// The node work item the credential is bound to.
    pub item_id: String,
    /// The item's task, when it has one.
    pub task_id: Option<i64>,
}

tokio::task_local! {
    static GRANT: Arc<SessionGrant>;
}

/// Run `f` with `grant` bound (or unbound, for `None`).
pub async fn scope<F: Future>(grant: Option<Arc<SessionGrant>>, f: F) -> F::Output {
    match grant {
        Some(g) => GRANT.scope(g, f).await,
        None => f.await,
    }
}

/// The grant bound to the running request, if any.
pub fn current() -> Option<Arc<SessionGrant>> {
    GRANT.try_with(Arc::clone).ok()
}

impl SessionGrant {
    /// Whether the grant exposes `tool` at all.
    pub fn allows_tool(&self, tool: &str) -> bool {
        self.tools.contains(tool)
    }

    /// Refuse a call outside the grant. Runs before the profile check.
    pub fn check(&self, tool: &str, args: &Value) -> UaResult<()> {
        if !self.allows_tool(tool) {
            return Err(UaError::denied(
                "profile_denied",
                format!("tool {tool} is not available to a session credential"),
            ));
        }
        if tool == "task_comment" {
            let action = args.get("action").and_then(Value::as_str).unwrap_or("").trim().to_ascii_lowercase();
            let task = args.get("params").and_then(|p| p.get("task_id")).and_then(Value::as_i64);
            let scoped =
                matches!(action.as_str(), "append" | "list") && task.is_some() && task == self.task_id;
            if !scoped {
                return Err(UaError::denied(
                    "session_task_scope",
                    "a session credential may only append to or list the comments of its own task",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn grant(task_id: Option<i64>) -> SessionGrant {
        SessionGrant {
            tools: ["task_comment", "task_list"].iter().map(|s| s.to_string()).collect(),
            credential_id: "0123456789abcdef".into(),
            item_id: "nd-0123456789abcdef".into(),
            task_id,
        }
    }

    #[test]
    fn a_grant_narrows_tools_and_comments() {
        let g = grant(Some(7));
        assert!(g.check("task_list", &json!({})).is_ok());
        assert_eq!(g.check("task_add", &json!({})).unwrap_err().reason_code(), Some("profile_denied"));
        let own = json!({ "action": "append", "params": { "task_id": 7, "body": "x" } });
        assert!(g.check("task_comment", &own).is_ok());
        for bad in [
            json!({ "action": "append", "params": { "task_id": 8, "body": "x" } }),
            json!({ "action": "get", "params": { "comment_id": 1 } }),
            json!({ "action": "list" }),
        ] {
            assert_eq!(g.check("task_comment", &bad).unwrap_err().reason_code(), Some("session_task_scope"));
        }
        // An item without a task comments nowhere.
        assert!(grant(None).check("task_comment", &json!({ "action": "list", "params": {} })).is_err());
    }

    #[tokio::test]
    async fn the_grant_is_visible_only_inside_its_scope() {
        assert!(current().is_none());
        let seen =
            scope(Some(Arc::new(grant(None))), async { current().map(|g| g.credential_id.clone()) }).await;
        assert_eq!(seen.as_deref(), Some("0123456789abcdef"));
        assert!(current().is_none());
    }
}
