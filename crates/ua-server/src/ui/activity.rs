//! Activity: the ledger as a live feed, with the hash-chain check.
//!
//! The page backfills recent events through `event_log_query`, then the
//! htmx SSE extension appends rendered rows from `/ui/activity/stream`, which
//! subscribes to the same broadcast as `/api/events/stream` but sends HTML
//! fragments (event name `ledger`) instead of JSON.

use std::convert::Infallible;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures::Stream;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_store::ledger::Event;

use super::{PageCtx, Ui, clip, int, list, non_empty, redact, text};

/// Backfill window and page size.
const BACKFILL_SCAN: i64 = 500;
const BACKFILL_SHOW: usize = 50;

#[derive(Debug, Clone)]
pub struct EventRow {
    pub seq: i64,
    pub channel: String,
    pub originator: String,
    pub created_at: String,
    pub payload: String,
}

impl EventRow {
    fn from_value(v: &Value) -> Self {
        Self {
            seq: int(v, "seq"),
            channel: text(v, "channel"),
            originator: text(v, "originator"),
            created_at: text(v, "created_at"),
            payload: payload_text(v.get("payload").unwrap_or(&Value::Null)),
        }
    }

    fn from_event(ev: &Event) -> Self {
        Self {
            seq: ev.seq,
            channel: ev.channel.clone(),
            originator: ev.originator.clone().unwrap_or_default(),
            created_at: ev.created_at.clone(),
            payload: payload_text(&ev.payload),
        }
    }
}

fn payload_text(v: &Value) -> String {
    clip(&serde_json::to_string(&redact(v)).unwrap_or_default(), 400)
}

#[derive(Template)]
#[template(path = "ui/event_row.html")]
struct EventRowTpl<'a> {
    e: &'a EventRow,
}

#[derive(Debug, Default, Deserialize)]
pub struct ActivityQuery {
    pub channel_prefix: Option<String>,
}

pub struct ChainStatus {
    pub ok: bool,
    pub checked: String,
    pub first_bad_seq: String,
    pub reason: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "ui/activity.html")]
pub struct ActivityPage {
    pub page: PageCtx,
    pub prefix: String,
    pub stream_url: String,
    pub events: Result<Vec<EventRow>, String>,
    pub chain: Result<ChainStatus, String>,
    pub presets: [&'static str; 7],
}

const PRESETS: [&str; 7] =
    ["agent.task.", "agent.approval.", "agent.message.", "agent.memory.", "agent.plan.", "agent.delegation.", "agent.gateway."];

fn clean_prefix(p: &Option<String>) -> String {
    non_empty(p).map(|s| s.chars().filter(|c| !c.is_control()).take(120).collect()).unwrap_or_default()
}

pub async fn page(ui: Ui, Query(q): Query<ActivityQuery>) -> ActivityPage {
    let prefix = clean_prefix(&q.channel_prefix);
    let events = backfill(&ui, &prefix).await;
    let chain = ui.read("event_log_verify", json!({})).await.map(|v| ChainStatus {
        ok: v.get("ok").and_then(Value::as_bool).unwrap_or(false),
        checked: text(&v, "checked"),
        first_bad_seq: text(&v, "first_bad_seq"),
        reason: text(&v, "reason"),
    });
    let stream_url = if prefix.is_empty() {
        "/ui/activity/stream".to_string()
    } else {
        format!("/ui/activity/stream?channel_prefix={}", urlencode(&prefix))
    };
    ActivityPage { page: ui.page("activity", "Activity", None), prefix, stream_url, events, chain, presets: PRESETS }
}

fn urlencode(s: &str) -> String {
    serde_urlencoded::to_string([("", s)]).map(|e| e.trim_start_matches('=').to_string()).unwrap_or_default()
}

/// The newest events, newest first. The ledger's highest sequence number
/// has no tool, so it is a read-only query gated on `event_log_query`.
async fn backfill(ui: &Ui, prefix: &str) -> Result<Vec<EventRow>, String> {
    if !ui.may("event_log_query") {
        return Err(format!("event_log_query is not available to your profile ({})", ui.caller.profile));
    }
    let max: i64 = ui
        .state
        .hub
        .db()
        .read_async(|c| Ok(c.query_row("SELECT COALESCE(MAX(seq), 0) FROM event_log", [], |r| r.get(0))?))
        .await
        .map_err(|e| e.to_string())?;
    let mut args = json!({ "after_seq": (max - BACKFILL_SCAN).max(0), "limit": BACKFILL_SCAN });
    if !prefix.is_empty() {
        args["channel_prefix"] = json!(prefix);
    }
    let v = ui.read("event_log_query", args).await?;
    let mut rows: Vec<EventRow> = list(&v, "events").iter().map(EventRow::from_value).collect();
    rows.reverse();
    rows.truncate(BACKFILL_SHOW);
    Ok(rows)
}

/// Rendered ledger rows as server-sent events named `ledger`.
pub async fn stream(ui: Ui, Query(q): Query<ActivityQuery>) -> Response {
    if !ui.may("event_log_query") {
        return (StatusCode::FORBIDDEN, "event_log_query is not available to your profile").into_response();
    }
    let prefix = clean_prefix(&q.channel_prefix);
    let rx = ui.state.hub.db().subscribe();
    Sse::new(rows(rx, prefix)).keep_alive(KeepAlive::default()).into_response()
}

fn rows(
    rx: tokio::sync::broadcast::Receiver<Event>,
    prefix: String,
) -> impl Stream<Item = Result<SseEvent, Infallible>> {
    futures::stream::unfold((rx, prefix), |(mut rx, prefix)| async move {
        loop {
            match rx.recv().await {
                Ok(ev) if ev.channel.starts_with(&prefix) => {
                    let row = EventRow::from_event(&ev);
                    let html = EventRowTpl { e: &row }.render().unwrap_or_default().replace(['\n', '\r'], " ");
                    let sse = SseEvent::default().event("ledger").id(ev.seq.to_string()).data(html);
                    return Some((Ok(sse), (rx, prefix)));
                }
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    })
}
