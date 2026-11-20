//! Memory: search and read notes.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};

use super::work::MissingPage;
use super::{PageCtx, Ui, list, non_empty, render, text};

#[derive(Debug, Clone)]
pub struct NoteRow {
    pub id: String,
    pub title: String,
    pub snippet: String,
    pub tags: Vec<String>,
    pub author: String,
    pub updated_at: String,
}

fn tags(v: &Value) -> Vec<String> {
    list(v, "tags").iter().filter_map(|t| t.as_str().map(str::to_string)).collect()
}

#[derive(Debug, Default, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    pub tag: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/memory.html")]
pub struct MemoryPage {
    pub page: PageCtx,
    pub q: String,
    pub tag: String,
    pub notes: Result<Vec<NoteRow>, String>,
    pub mode: String,
}

pub async fn search(ui: Ui, Query(sq): Query<SearchQuery>) -> MemoryPage {
    let q = non_empty(&sq.q);
    let tag = non_empty(&sq.tag);
    let (tool, args) = match &q {
        Some(query) => {
            let mut a = json!({ "query": query, "limit": 50 });
            if let Some(t) = &tag {
                a["tags"] = json!([t]);
            }
            ("memory_search", a)
        }
        None => {
            let mut a = json!({ "limit": 50 });
            if let Some(t) = &tag {
                a["tag"] = json!(t);
            }
            ("memory_list", a)
        }
    };
    let key = if q.is_some() { "results" } else { "items" };
    let notes = ui.read(tool, args).await.map(|v| {
        list(&v, key)
            .iter()
            .map(|n| NoteRow {
                id: text(n, "id"),
                title: text(n, "title"),
                snippet: text(n, "snippet"),
                tags: tags(n),
                author: text(n, "author"),
                updated_at: text(n, "updated_at"),
            })
            .collect()
    });
    MemoryPage {
        page: ui.page("memory", "Memory", None),
        mode: if q.is_some() { "Search results".into() } else { "Recent notes".into() },
        q: q.unwrap_or_default(),
        tag: tag.unwrap_or_default(),
        notes,
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/memory_note.html")]
pub struct NotePage {
    pub page: PageCtx,
    pub note: NoteRow,
    pub content: String,
    pub revision: String,
    pub created_at: String,
    pub superseded_by: String,
    pub source_host: String,
}

pub async fn note(ui: Ui, Path(id): Path<String>) -> Response {
    let v = match ui.call_read("memory_get", json!({ "id": id, "count_access": false })).await {
        Ok(v) => v,
        Err(e) => {
            let status = crate::api::status_for(&e);
            let page = MissingPage {
                page: ui.page("memory", "Note unavailable", Some(super::describe("memory_get", &e))),
                what: format!("note {id}"),
                back: "/ui/memory",
            };
            return render(status, page);
        }
    };
    let note = NoteRow {
        id: text(&v, "id"),
        title: text(&v, "title"),
        snippet: String::new(),
        tags: tags(&v),
        author: text(&v, "author"),
        updated_at: text(&v, "updated_at"),
    };
    let page = NotePage {
        page: ui.page("memory", note.title.clone(), None),
        content: text(&v, "content"),
        revision: text(&v, "revision"),
        created_at: text(&v, "created_at"),
        superseded_by: text(&v, "superseded_by"),
        source_host: text(&v, "source_host"),
        note,
    };
    render(StatusCode::OK, page)
}
