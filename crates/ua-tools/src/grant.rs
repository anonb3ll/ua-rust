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
//! The grant narrows, never widens: a tool must be in `tools` and have its
//! own rule in [`SessionGrant::narrow`]; `task_comment` may only `append` to
//! or `list` the credential's own task; `session_packet`, `evidence_report`
//! and `task_list` read that task only. A caller under the `acp-session` profile
//! with no grant bound is refused every tool.

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

    /// Refuse a call outside the grant and pin the task-reading tools to the
    /// credential's task. Runs before the profile check; returns the
    /// arguments the call proceeds with.
    ///
    /// - `task_comment`: only `append` or `list`, only on the grant's task.
    /// - `session_packet`: `task_id` is the grant's task (filled in when
    ///   omitted, refused when another); `session_id` is refused.
    /// - `evidence_report`: `task_id` as above; `project_id` (a subtree) is
    ///   refused.
    /// - `task_list` is confined to the grant's task by the tool itself
    ///   (see [`pinned_task`]).
    /// - `profile_status` passes unchanged.
    /// - Any other tool is refused (`session_tool_unscoped`), even when the
    ///   grant lists it: each tool needs its own rule here.
    ///
    /// A grant without a task refuses all three task-reading tools.
    pub fn narrow(&self, tool: &str, mut args: Value) -> UaResult<Value> {
        if !self.allows_tool(tool) {
            return Err(UaError::denied(
                "profile_denied",
                format!("tool {tool} is not available to a session credential"),
            ));
        }
        match tool {
            "task_comment" => {
                let action =
                    args.get("action").and_then(Value::as_str).unwrap_or("").trim().to_ascii_lowercase();
                let task = args.get("params").and_then(|p| p.get("task_id")).and_then(Value::as_i64);
                let scoped =
                    matches!(action.as_str(), "append" | "list") && task.is_some() && task == self.task_id;
                if !scoped {
                    return Err(scope_denied(
                        "a session credential may only append to or list the comments of its own task",
                    ));
                }
            }
            "session_packet" | "evidence_report" => {
                let Some(own) = self.task_id else {
                    return Err(scope_denied(format!("{tool}: this session credential's item has no task")));
                };
                let Some(obj) = args.as_object_mut() else {
                    return Err(UaError::invalid(format!("{tool} arguments must be an object")));
                };
                let widening = if tool == "session_packet" { "session_id" } else { "project_id" };
                if obj.get(widening).is_some_and(|v| !v.is_null()) {
                    return Err(scope_denied(format!(
                        "{tool}: a session credential may not pass {widening}; it reads its own task only"
                    )));
                }
                match obj.get("task_id") {
                    None | Some(Value::Null) => {
                        obj.insert("task_id".into(), Value::from(own));
                    }
                    Some(v) if v.as_i64() == Some(own) => {}
                    Some(_) => {
                        return Err(scope_denied(format!(
                            "{tool}: a session credential may only read its own task ({own})"
                        )));
                    }
                }
            }
            // Confined by the tool itself to the grant's task (see
            // [`pinned_task`]).
            "task_list" => {}
            // Reports only the caller's own identity and profile.
            "profile_status" => {}
            // Every tool needs an arm here saying how the grant confines it.
            // A tool without one is refused, so adding a name to the
            // `acp-session` list cannot by itself widen a credential.
            _ => {
                return Err(UaError::denied(
                    "session_tool_unscoped",
                    format!("tool {tool} has no session-credential scope rule"),
                ));
            }
        }
        Ok(args)
    }
}

fn scope_denied(msg: impl Into<String>) -> UaError {
    UaError::denied("session_task_scope", msg)
}

/// The task a running session-credential request is confined to: `None`
/// outside a grant, `Some(None)` for a grant whose item has no task (it
/// reads no task at all).
pub fn pinned_task() -> Option<Option<i64>> {
    current().map(|g| g.task_id)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn grant(task_id: Option<i64>) -> SessionGrant {
        SessionGrant {
            tools: ["task_comment", "task_list", "session_packet", "evidence_report"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            credential_id: "0123456789abcdef".into(),
            item_id: "nd-0123456789abcdef".into(),
            task_id,
        }
    }

    #[test]
    fn a_grant_narrows_tools_and_comments() {
        let g = grant(Some(7));
        assert!(g.narrow("task_list", json!({})).is_ok());
        assert_eq!(g.narrow("task_add", json!({})).unwrap_err().reason_code(), Some("profile_denied"));
        let own = json!({ "action": "append", "params": { "task_id": 7, "body": "x" } });
        assert_eq!(g.narrow("task_comment", own.clone()).unwrap(), own);
        for bad in [
            json!({ "action": "append", "params": { "task_id": 8, "body": "x" } }),
            json!({ "action": "get", "params": { "comment_id": 1 } }),
            json!({ "action": "list" }),
        ] {
            assert_eq!(g.narrow("task_comment", bad).unwrap_err().reason_code(), Some("session_task_scope"));
        }
        // An item without a task comments nowhere.
        assert!(grant(None).narrow("task_comment", json!({ "action": "list", "params": {} })).is_err());
    }

    #[test]
    fn task_reads_are_pinned_to_the_grants_task() {
        let g = grant(Some(7));
        for tool in ["session_packet", "evidence_report"] {
            assert_eq!(g.narrow(tool, json!({})).unwrap(), json!({ "task_id": 7 }), "{tool}");
            assert_eq!(g.narrow(tool, json!({ "task_id": null })).unwrap(), json!({ "task_id": 7 }));
            assert_eq!(g.narrow(tool, json!({ "task_id": 7 })).unwrap(), json!({ "task_id": 7 }));
            let err = g.narrow(tool, json!({ "task_id": 8 })).unwrap_err();
            assert_eq!(err.reason_code(), Some("session_task_scope"), "{tool}");
            let err = grant(None).narrow(tool, json!({})).unwrap_err();
            assert_eq!(err.reason_code(), Some("session_task_scope"), "{tool}");
        }
        let err = g.narrow("session_packet", json!({ "session_id": "s-1" })).unwrap_err();
        assert_eq!(err.reason_code(), Some("session_task_scope"));
        let err = g.narrow("evidence_report", json!({ "project_id": 1 })).unwrap_err();
        assert_eq!(err.reason_code(), Some("session_task_scope"));
        // Narrowing filters stay.
        assert_eq!(
            g.narrow("evidence_report", json!({ "since": "2026-01-01" })).unwrap(),
            json!({ "since": "2026-01-01", "task_id": 7 })
        );
    }

    /// Every tool the `acp-session` profile lists has its own arm in
    /// [`SessionGrant::narrow`]; a tool without one is refused there.
    #[test]
    fn every_acp_session_tool_has_a_narrowing_rule() {
        let (_, acp) = ua_core::Profile::tool_lists()
            .into_iter()
            .find(|(name, _)| *name == "ACP_SESSION_ALLOWED_TOOLS")
            .expect("the acp-session list");
        let g = SessionGrant { tools: acp.clone(), ..grant(Some(7)) };
        for tool in acp {
            let args = json!({ "action": "list", "params": { "task_id": 7 } });
            if let Err(e) = g.narrow(tool, args) {
                assert_ne!(e.reason_code(), Some("session_tool_unscoped"), "{tool} has no narrowing rule");
            }
        }
    }

    #[test]
    fn a_granted_tool_without_a_narrowing_rule_is_refused() {
        let mut g = grant(Some(7));
        for tool in ["memory_get", "memory_save", "task_add"] {
            g.tools.insert(tool.to_string());
            let e = g.narrow(tool, json!({})).unwrap_err();
            assert_eq!(e.reason_code(), Some("session_tool_unscoped"), "{tool}");
        }
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
