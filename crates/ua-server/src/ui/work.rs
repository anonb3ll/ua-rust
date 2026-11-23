//! Work: the task board, task detail and task writes.

use std::collections::BTreeSet;

use askama::Template;
use askama_web::WebTemplate;
use axum::Form;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};

use super::{Outcome, PageCtx, Ui, clip, int, list, non_empty, outcome, redirect, render, text};

pub const STATUSES: [(&str, &str); 6] = [
    ("open", "Backlog"),
    ("doing", "Doing"),
    ("waiting_review", "In review"),
    ("blocked", "Blocked"),
    ("done", "Done"),
    ("cancelled", "Cancelled"),
];
pub const PRIORITIES: [&str; 3] = ["high", "med", "low"];

#[derive(Debug, Clone)]
pub struct TaskCard {
    pub id: i64,
    pub title: String,
    pub priority: String,
    pub project: String,
    pub lane: String,
    pub claimed_by: String,
    pub urgency: String,
}

impl TaskCard {
    fn from(v: &Value) -> Self {
        Self {
            id: int(v, "id"),
            title: text(v, "title"),
            priority: text(v, "priority"),
            project: text(v, "project"),
            lane: text(v, "lane"),
            claimed_by: text(v, "claimed_by"),
            urgency: text(v, "urgency"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Column {
    pub status: &'static str,
    pub label: &'static str,
    pub cards: Vec<TaskCard>,
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct BoardQuery {
    pub project: Option<String>,
    pub priority: Option<String>,
    pub q: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/work.html")]
pub struct BoardPage {
    pub page: PageCtx,
    pub columns: Vec<Column>,
    pub projects: Vec<String>,
    pub project: String,
    pub priority: String,
    pub q: String,
    pub search: bool,
    pub priorities: [&'static str; 3],
}

fn filters(q: &BoardQuery) -> Map<String, Value> {
    let mut m = Map::new();
    if let Some(p) = non_empty(&q.project) {
        m.insert("project".into(), json!(p));
    }
    if let Some(p) = non_empty(&q.priority).filter(|p| PRIORITIES.contains(&p.as_str())) {
        m.insert("priority".into(), json!(p));
    }
    m
}

async fn build_board(ui: &Ui, q: &BoardQuery, error: Option<String>) -> BoardPage {
    let base = filters(q);
    let search = non_empty(&q.q);
    let mut columns: Vec<Column> = STATUSES
        .iter()
        .map(|(status, label)| Column { status, label, cards: Vec::new(), truncated: false, error: None })
        .collect();
    if let Some(query) = &search {
        let mut args = base.clone();
        args.insert("status".into(), json!("all"));
        args.insert("query".into(), json!(query));
        args.insert("limit".into(), json!(100));
        args.insert("fields".into(), json!("compact"));
        match ui.read("task_list", Value::Object(args)).await {
            Ok(v) => {
                for t in list(&v, "tasks") {
                    let status = text(t, "status");
                    if let Some(c) = columns.iter_mut().find(|c| c.status == status) {
                        c.cards.push(TaskCard::from(t));
                    }
                }
            }
            Err(e) => columns.iter_mut().for_each(|c| c.error = Some(e.clone())),
        }
    } else {
        for c in columns.iter_mut() {
            let limit = match c.status {
                "done" => 50,
                "cancelled" => 20,
                _ => 200,
            };
            let mut args = base.clone();
            args.insert("status".into(), json!(c.status));
            args.insert("limit".into(), json!(limit));
            args.insert("fields".into(), json!("compact"));
            match ui.read("task_list", Value::Object(args)).await {
                Ok(v) => {
                    c.cards = list(&v, "tasks").iter().map(TaskCard::from).collect();
                    c.truncated = v.get("truncated").and_then(Value::as_bool).unwrap_or(false);
                }
                Err(e) => c.error = Some(e),
            }
        }
    }
    let mut projects: BTreeSet<String> =
        columns.iter().flat_map(|c| c.cards.iter().map(|t| t.project.clone())).collect();
    projects.extend(non_empty(&q.project));
    projects.insert("default".into());
    BoardPage {
        page: ui.page("work", "Work", error),
        columns,
        projects: projects.into_iter().collect(),
        project: non_empty(&q.project).unwrap_or_default(),
        priority: non_empty(&q.priority).unwrap_or_default(),
        q: search.clone().unwrap_or_default(),
        search: search.is_some(),
        priorities: PRIORITIES,
    }
}

pub async fn board(ui: Ui, Query(q): Query<BoardQuery>) -> BoardPage {
    build_board(&ui, &q, None).await
}

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    pub title: String,
    pub notes: Option<String>,
    pub priority: Option<String>,
    pub project: Option<String>,
    pub lane: Option<String>,
    pub parent_id: Option<String>,
}

pub async fn create(ui: Ui, Form(f): Form<CreateForm>) -> Response {
    let mut args = json!({ "title": f.title.trim() });
    for (k, v) in [("notes", &f.notes), ("priority", &f.priority), ("project", &f.project), ("lane", &f.lane)]
    {
        if let Some(v) = non_empty(v) {
            args[k] = json!(v);
        }
    }
    if let Some(p) = non_empty(&f.parent_id) {
        match p.parse::<i64>() {
            Ok(id) => args["parent_id"] = json!(id),
            Err(_) => {
                let page =
                    build_board(&ui, &BoardQuery::default(), Some("parent id must be a number".into())).await;
                return render(StatusCode::BAD_REQUEST, page);
            }
        }
    }
    match outcome("task_add", ui.call("task_add", args).await) {
        Outcome::Done(v) => redirect(&format!("/ui/tasks/{}", int(&v, "id")), "task_created", None),
        Outcome::Parked(a) => redirect("/ui/work", "parked", Some(a)),
        Outcome::Failed(status, msg) => {
            render(status, build_board(&ui, &BoardQuery::default(), Some(msg)).await)
        }
    }
}

// ---------------------------------------------------------------------------
// Detail

#[derive(Debug, Clone, Default)]
pub struct TaskDetail {
    pub id: i64,
    pub title: String,
    pub notes: String,
    pub status: String,
    pub priority: String,
    pub project: String,
    pub domain: String,
    pub lane: String,
    pub claimed_by: String,
    pub lock_expires_at: String,
    pub parent_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: String,
    pub due_at: String,
    pub evidence_ref: String,
    pub branch: String,
    pub worktree_path: String,
    pub next_owner: String,
    pub waiting_on: String,
    pub untrusted: bool,
}

#[derive(Debug, Clone)]
pub struct CommentView {
    pub id: i64,
    pub author: String,
    pub created_at: String,
    pub body: String,
    pub reply_to: String,
}

#[derive(Debug, Clone)]
pub struct DepView {
    pub id: i64,
    pub other: i64,
    pub created_by: String,
}

pub struct Deps {
    pub waits_on: Vec<DepView>,
    pub blocks: Vec<DepView>,
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/task.html")]
pub struct TaskPage {
    pub page: PageCtx,
    pub task: TaskDetail,
    pub comments: Result<Vec<CommentView>, String>,
    pub deps: Result<Deps, String>,
    pub statuses: [(&'static str, &'static str); 6],
    pub priorities: [&'static str; 3],
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/missing.html")]
pub struct MissingPage {
    pub page: PageCtx,
    pub what: String,
    pub back: &'static str,
}

fn row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    use rusqlite::types::ValueRef;
    let stmt = row.as_ref();
    let mut out = Map::new();
    for i in 0..stmt.column_count() {
        let v = match row.get_ref(i)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(n) => json!(n),
            ValueRef::Real(f) => json!(f),
            ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(_) => Value::Null,
        };
        out.insert(stmt.column_name(i)?.to_string(), v);
    }
    Ok(Value::Object(out))
}

/// One task row. There is no single-task read tool yet, so this is a
/// read-only query gated on the caller's `task_list` access.
/// The columns the detail page reads ([`detail_of`]); `org_id` is never
/// one of them.
const DETAIL_COLUMNS: &str = "id, title, notes, status, priority, project, domain, lane, claimed_by, \
     lock_expires_at, parent_id, created_at, updated_at, completed_at, due_at, evidence_ref, branch, \
     worktree_path, next_owner, waiting_on, untrusted";

async fn load_task(ui: &Ui, id: i64) -> UaResult<Option<Value>> {
    if !ui.may("task_list") {
        return Err(UaError::denied(
            "profile_denied",
            format!("task_list is not available to profile {}", ui.caller.profile),
        ));
    }
    // The viewer's organization's task only; another organization's task
    // answers as a missing one.
    let org = ui.caller.org_id.clone();
    ui.state
        .hub
        .db()
        .read_async(move |c| {
            use rusqlite::OptionalExtension;
            Ok(c.query_row(
                &format!("SELECT {DETAIL_COLUMNS} FROM tasks WHERE org_id = ?1 AND id = ?2"),
                rusqlite::params![org, id],
                row_value,
            )
            .optional()?)
        })
        .await
}

fn detail_of(v: &Value) -> TaskDetail {
    TaskDetail {
        id: int(v, "id"),
        title: text(v, "title"),
        notes: text(v, "notes"),
        status: text(v, "status"),
        priority: text(v, "priority"),
        project: text(v, "project"),
        domain: text(v, "domain"),
        lane: text(v, "lane"),
        claimed_by: text(v, "claimed_by"),
        lock_expires_at: text(v, "lock_expires_at"),
        parent_id: text(v, "parent_id"),
        created_at: text(v, "created_at"),
        updated_at: text(v, "updated_at"),
        completed_at: text(v, "completed_at"),
        due_at: text(v, "due_at"),
        evidence_ref: text(v, "evidence_ref"),
        branch: text(v, "branch"),
        worktree_path: text(v, "worktree_path"),
        next_owner: text(v, "next_owner"),
        waiting_on: text(v, "waiting_on"),
        untrusted: int(v, "untrusted") != 0,
    }
}

async fn build_detail(ui: &Ui, id: i64, error: Option<String>) -> Response {
    let row = match load_task(ui, id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            let page = MissingPage {
                page: ui.page("work", "Not found", error),
                what: format!("task {id}"),
                back: "/ui/work",
            };
            return render(StatusCode::NOT_FOUND, page);
        }
        Err(e) => {
            let page = MissingPage {
                page: ui.page("work", "Unavailable", Some(super::describe("task_list", &e))),
                what: format!("task {id}"),
                back: "/ui/work",
            };
            return render(crate::api::status_for(&e), page);
        }
    };
    let comments =
        ui.read("task_comment", json!({ "action": "list", "params": { "task_id": id } })).await.map(|v| {
            list(&v, "comments")
                .iter()
                .map(|c| CommentView {
                    id: int(c, "id"),
                    author: text(c, "author"),
                    created_at: text(c, "created_at"),
                    body: text(c, "body"),
                    reply_to: text(c, "parent_comment_id"),
                })
                .collect()
        });
    let deps = ui.read("dependency_list", json!({ "limit": 2000 })).await.map(|v| {
        let edges = list(&v, "dependencies");
        Deps {
            waits_on: edges
                .iter()
                .filter(|e| int(e, "task_id") == id)
                .map(|e| DepView {
                    id: int(e, "id"),
                    other: int(e, "depends_on_task_id"),
                    created_by: text(e, "created_by"),
                })
                .collect(),
            blocks: edges
                .iter()
                .filter(|e| int(e, "depends_on_task_id") == id)
                .map(|e| DepView {
                    id: int(e, "id"),
                    other: int(e, "task_id"),
                    created_by: text(e, "created_by"),
                })
                .collect(),
        }
    });
    let task = detail_of(&row);
    let title = format!("#{} {}", task.id, clip(&task.title, 60));
    let page = TaskPage {
        page: ui.page("work", title, error),
        task,
        comments,
        deps,
        statuses: STATUSES,
        priorities: PRIORITIES,
    };
    render(if page.page.error.is_some() { StatusCode::UNPROCESSABLE_ENTITY } else { StatusCode::OK }, page)
}

pub async fn detail(ui: Ui, Path(id): Path<i64>) -> Response {
    build_detail(&ui, id, None).await
}

/// Finish a task write: redirect on success, re-render with the error.
async fn finish(ui: &Ui, id: i64, tool: &str, r: UaResult<Value>, flash: &str) -> Response {
    let back = format!("/ui/tasks/{id}");
    match outcome(tool, r) {
        Outcome::Done(_) => redirect(&back, flash, None),
        Outcome::Parked(a) => redirect(&back, "parked", Some(a)),
        Outcome::Failed(status, msg) => {
            let mut resp = build_detail(ui, id, Some(msg)).await;
            if resp.status() == StatusCode::UNPROCESSABLE_ENTITY {
                *resp.status_mut() = status;
            }
            resp
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateForm {
    pub title: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub project: Option<String>,
    pub lane: Option<String>,
    pub due_at: Option<String>,
    pub evidence_ref: Option<String>,
}

pub async fn update(ui: Ui, Path(id): Path<i64>, Form(f): Form<UpdateForm>) -> Response {
    let current = match load_task(&ui, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return build_detail(&ui, id, None).await,
        Err(e) => return finish(&ui, id, "task_update", Err(e), "").await,
    };
    let mut args = json!({ "id": id });
    let fields = [
        ("title", &f.title),
        ("status", &f.status),
        ("priority", &f.priority),
        ("project", &f.project),
        ("lane", &f.lane),
        ("due_at", &f.due_at),
        ("evidence_ref", &f.evidence_ref),
    ];
    for (k, v) in fields {
        if let Some(v) = non_empty(v)
            && v != text(&current, k)
        {
            args[k] = json!(v);
        }
    }
    if args.as_object().is_some_and(|m| m.len() == 1) {
        return redirect(&format!("/ui/tasks/{id}"), "task_updated", None);
    }
    let r = ui.call("task_update", args).await;
    finish(&ui, id, "task_update", r, "task_updated").await
}

#[derive(Debug, Deserialize)]
pub struct NoteForm {
    pub append_note: String,
}

pub async fn note(ui: Ui, Path(id): Path<i64>, Form(f): Form<NoteForm>) -> Response {
    let r = ui.call("task_update", json!({ "id": id, "append_note": f.append_note })).await;
    finish(&ui, id, "task_update", r, "note_added").await
}

#[derive(Debug, Deserialize)]
pub struct CommentForm {
    pub body: String,
}

pub async fn comment(ui: Ui, Path(id): Path<i64>, Form(f): Form<CommentForm>) -> Response {
    let r = ui
        .call("task_comment", json!({ "action": "append", "params": { "task_id": id, "body": f.body } }))
        .await;
    finish(&ui, id, "task_comment", r, "comment_added").await
}

#[derive(Debug, Deserialize)]
pub struct DepForm {
    pub depends_on_task_id: String,
}

pub async fn dependency_add(ui: Ui, Path(id): Path<i64>, Form(f): Form<DepForm>) -> Response {
    let Ok(other) = f.depends_on_task_id.trim().trim_start_matches('#').parse::<i64>() else {
        return finish(&ui, id, "dependency_add", Err(UaError::invalid("task id must be a number")), "")
            .await;
    };
    let r = ui.call("dependency_add", json!({ "task_id": id, "depends_on_task_id": other })).await;
    finish(&ui, id, "dependency_add", r, "dependency_added").await
}

pub async fn dependency_remove(ui: Ui, Path((id, dep)): Path<(i64, i64)>) -> Response {
    let r = ui.call("dependency_remove", json!({ "dependency_id": dep })).await;
    finish(&ui, id, "dependency_remove", r, "dependency_removed").await
}
