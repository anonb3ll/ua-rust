//! Plans, delegations, agents with their sessions, and messages. All
//! read-only views over read-only tools.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};

use super::work::MissingPage;
use super::{PageCtx, Ui, clip, int, list, non_empty, render, text};

// ---------------------------------------------------------------------------
// Plans and delegations

#[derive(Debug, Clone)]
pub struct PlanRow {
    pub id: String,
    pub title: String,
    pub status: String,
    pub scope: String,
    pub author: String,
    pub needs_human: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct DelegationRow {
    pub id: i64,
    pub from_agent: String,
    pub to_agent: String,
    pub status: String,
    pub task_id: String,
    pub summary: String,
    pub deadline: String,
    pub overdue: bool,
}

const PLAN_STATUSES: [&str; 5] = ["active", "done", "blocked", "abandoned", "all"];
const DELEGATION_STATUSES: [&str; 6] = ["pending", "in_flight", "completed", "cancelled", "failed", "all"];

#[derive(Debug, Default, Deserialize)]
pub struct PlansQuery {
    pub status: Option<String>,
    pub delegations: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/plans.html")]
pub struct PlansPage {
    pub page: PageCtx,
    pub plans: Result<Vec<PlanRow>, String>,
    pub delegations: Result<Vec<DelegationRow>, String>,
    pub status: String,
    pub delegation_status: String,
    pub plan_statuses: [&'static str; 5],
    pub delegation_statuses: [&'static str; 6],
}

fn truthy(v: &Value, k: &str) -> bool {
    match v.get(k) {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0,
        _ => false,
    }
}

pub async fn plans(ui: Ui, Query(q): Query<PlansQuery>) -> PlansPage {
    let status =
        non_empty(&q.status).filter(|s| PLAN_STATUSES.contains(&s.as_str())).unwrap_or("active".into());
    let dstatus = non_empty(&q.delegations)
        .filter(|s| DELEGATION_STATUSES.contains(&s.as_str()))
        .unwrap_or("all".into());
    let plans = ui.read("plan_list", json!({ "status": status, "limit": 200 })).await.map(|v| {
        list(&v, "plans")
            .iter()
            .map(|p| PlanRow {
                id: text(p, "id"),
                title: text(p, "title"),
                status: text(p, "status"),
                scope: text(p, "scope"),
                author: text(p, "author"),
                needs_human: truthy(p, "needs_human"),
                updated_at: text(p, "updated_at"),
            })
            .collect()
    });
    let delegations = ui.read("delegate_list", json!({ "status": dstatus, "limit": 200 })).await.map(|v| {
        list(&v, "delegations")
            .iter()
            .map(|d| DelegationRow {
                id: int(d, "id"),
                from_agent: text(d, "from_agent"),
                to_agent: text(d, "to_agent"),
                status: text(d, "status"),
                task_id: text(d, "task_id"),
                summary: clip(
                    text(d, "task_spec")
                        .lines()
                        .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
                        .unwrap_or(""),
                    120,
                ),
                deadline: text(d, "deadline"),
                overdue: truthy(d, "overdue"),
            })
            .collect()
    });
    PlansPage {
        page: ui.page("plans", "Plans and delegations", None),
        plans,
        delegations,
        status,
        delegation_status: dstatus,
        plan_statuses: PLAN_STATUSES,
        delegation_statuses: DELEGATION_STATUSES,
    }
}

#[derive(Debug, Clone)]
pub struct StepRow {
    pub idx: i64,
    pub description: String,
    pub status: String,
    pub owner: String,
    pub depends_on: String,
    pub retries: i64,
    pub note: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/plan.html")]
pub struct PlanPage {
    pub page: PageCtx,
    pub plan: PlanRow,
    pub goal: String,
    pub description: String,
    pub steps: Vec<StepRow>,
    pub next_step: String,
    pub checkpoints: usize,
}

pub async fn plan(ui: Ui, Path(id): Path<String>) -> Response {
    let v = match ui.call_read("plan_get", json!({ "plan_id": id })).await {
        Ok(v) => v,
        Err(e) => {
            let status = crate::api::status_for(&e);
            let page = MissingPage {
                page: ui.page("plans", "Plan unavailable", Some(super::describe("plan_get", &e))),
                what: format!("plan {id}"),
                back: "/ui/plans",
            };
            return render(status, page);
        }
    };
    let p = v.get("plan").cloned().unwrap_or(Value::Null);
    let steps = list(&v, "steps")
        .iter()
        .map(|s| StepRow {
            idx: int(s, "step_idx"),
            description: text(s, "description"),
            status: text(s, "status"),
            owner: text(s, "owner"),
            depends_on: list(s, "depends_on").iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "),
            retries: int(s, "retries"),
            note: text(s, "note"),
        })
        .collect();
    let plan = PlanRow {
        id: text(&p, "id"),
        title: text(&p, "title"),
        status: text(&p, "status"),
        scope: text(&p, "scope"),
        author: text(&p, "author"),
        needs_human: truthy(&v, "needs_human") || truthy(&p, "needs_human"),
        updated_at: text(&p, "updated_at"),
    };
    let page = PlanPage {
        page: ui.page("plans", format!("Plan {}", clip(&plan.title, 60)), None),
        goal: text(&p, "goal"),
        description: text(&p, "description"),
        plan,
        steps,
        next_step: text(&v, "next_step_idx"),
        checkpoints: list(&v, "checkpoints").len(),
    };
    render(StatusCode::OK, page)
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/delegation.html")]
pub struct DelegationPage {
    pub page: PageCtx,
    pub id: i64,
    pub fields: Vec<(String, String)>,
    pub spec: String,
    pub task_id: String,
}

pub async fn delegation(ui: Ui, Path(id): Path<i64>) -> Response {
    let v = match ui.call_read("delegation_manage", json!({ "action": "get", "params": { "id": id } })).await
    {
        Ok(v) => v,
        Err(e) => {
            let status = crate::api::status_for(&e);
            let page = MissingPage {
                page: ui.page(
                    "plans",
                    "Delegation unavailable",
                    Some(super::describe("delegation_manage", &e)),
                ),
                what: format!("delegation {id}"),
                back: "/ui/plans",
            };
            return render(status, page);
        }
    };
    let d = v.get("delegation").cloned().unwrap_or(Value::Null);
    let fields = d
        .as_object()
        .map(|m| {
            m.iter()
                .filter(|(k, _)| k.as_str() != "task_spec")
                .map(|(k, val)| {
                    let shown = match val {
                        Value::String(s) => s.clone(),
                        Value::Null => String::new(),
                        Value::Object(_) | Value::Array(_) => super::pretty(val),
                        other => other.to_string(),
                    };
                    (k.clone(), shown)
                })
                .collect()
        })
        .unwrap_or_default();
    let page = DelegationPage {
        page: ui.page("plans", format!("Delegation {id}"), None),
        id,
        fields,
        spec: text(&d, "task_spec"),
        task_id: text(&d, "task_id"),
    };
    render(StatusCode::OK, page)
}

// ---------------------------------------------------------------------------
// Agents and sessions

#[derive(Debug, Clone)]
pub struct AgentRow {
    pub label: String,
    pub status: String,
    pub kind: String,
    pub host: String,
    pub last_seen: String,
    pub open_sessions: i64,
    pub active_tasks: i64,
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub agent: String,
    pub kind: String,
    pub status: String,
    pub live: bool,
    pub task_id: String,
    pub task_title: String,
    pub branch: String,
    pub last_heartbeat_at: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/agents.html")]
pub struct AgentsPage {
    pub page: PageCtx,
    pub agents: Result<Vec<AgentRow>, String>,
    pub sessions: Result<Vec<SessionRow>, String>,
}

pub async fn agents(ui: Ui) -> AgentsPage {
    let agents = ui.read("agent_list", json!({})).await.map(|v| {
        list(&v, "agents")
            .iter()
            .map(|a| AgentRow {
                label: text(a, "label"),
                status: text(a, "status"),
                kind: text(a, "kind"),
                host: text(a, "host"),
                last_seen: text(a, "last_seen"),
                open_sessions: int(a, "open_sessions"),
                active_tasks: int(a, "active_tasks"),
            })
            .collect()
    });
    let sessions = ui.read("session_list", json!({ "status": "open", "limit": 200 })).await.map(|v| {
        list(&v, "sessions")
            .iter()
            .map(|s| SessionRow {
                id: text(s, "id"),
                agent: text(s, "agent"),
                kind: text(s, "kind"),
                status: text(s, "status"),
                live: truthy(s, "live"),
                task_id: text(s, "task_id"),
                task_title: text(s, "task_title"),
                branch: text(s, "branch"),
                last_heartbeat_at: text(s, "last_heartbeat_at"),
            })
            .collect()
    });
    AgentsPage { page: ui.page("agents", "Agents and sessions", None), agents, sessions }
}

// ---------------------------------------------------------------------------
// Messages

#[derive(Debug, Clone)]
pub struct MessageRow {
    pub seq: i64,
    pub created_at: String,
    pub from_agent: String,
    pub to: String,
    pub act: String,
    pub preview: String,
    pub body: String,
    pub read: bool,
    pub task_id: String,
    pub trust: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct MessagesQuery {
    pub agent: Option<String>,
    pub unread: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/messages.html")]
pub struct MessagesPage {
    pub page: PageCtx,
    pub messages: Result<Vec<MessageRow>, String>,
    pub agent: String,
    pub unread: bool,
    pub unread_count: String,
}

pub async fn messages(ui: Ui, Query(q): Query<MessagesQuery>) -> MessagesPage {
    let agent = non_empty(&q.agent);
    let unread = q.unread.as_deref() == Some("1");
    let mut args = json!({ "limit": 200 });
    if let Some(a) = &agent {
        args["to_agent"] = json!(a);
    }
    if unread {
        args["unread_only"] = json!(true);
    }
    let mut unread_count = String::new();
    let messages = ui.read("message_list", args).await.map(|v| {
        unread_count = text(&v, "unread");
        let mut rows: Vec<MessageRow> = list(&v, "messages")
            .iter()
            .map(|m| {
                let body = text(m, "body");
                let to = match text(m, "to_session") {
                    s if s.is_empty() => text(m, "to_agent"),
                    s => format!("{} (session {})", text(m, "to_agent"), s),
                };
                MessageRow {
                    seq: int(m, "seq"),
                    created_at: text(m, "created_at"),
                    from_agent: text(m, "from_agent"),
                    to,
                    act: text(m, "act"),
                    preview: clip(body.lines().next().unwrap_or(""), 100),
                    body,
                    read: !text(m, "read_at").is_empty(),
                    task_id: text(m, "task_id"),
                    trust: m.get("trust").map(|t| text(t, "level")).unwrap_or_default(),
                }
            })
            .collect();
        rows.reverse();
        rows
    });
    MessagesPage {
        page: ui.page("messages", "Messages", None),
        messages,
        agent: agent.unwrap_or_default(),
        unread,
        unread_count,
    }
}
