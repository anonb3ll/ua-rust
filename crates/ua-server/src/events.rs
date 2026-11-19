//! Scoped live ledger streams, shared by `/api/events/stream` (JSON) and
//! `/ui/activity/stream` (rendered rows).
//!
//! A stream is opened with one governed `event_log_query` call as the
//! caller, so the profile, policy and decision row apply exactly as they do
//! to the tool. Every row it then sends, live or backfilled, passes the same
//! [`EventScope`] the tool applies.
//!
//! Nothing is dropped silently:
//! - A reconnect with `Last-Event-ID: <seq>` first replays the scoped rows
//!   after that seq from the ledger.
//! - When the broadcast receiver lags (a slow client), the stream backfills
//!   from the ledger after the last row it saw.
//! - When a backfill cannot be complete (the ledger read failed, or more rows
//!   matched than one page holds), the stream sends a [`StreamItem::Gap`]
//!   naming the range that may be missing.
//!
//! Ledger writes are broadcast after their commit, outside the writer lock,
//! so two writers can broadcast slightly out of seq order. The stream
//! therefore remembers the seqs it has delivered rather than only the
//! highest one.

use std::collections::{BTreeSet, VecDeque};

use axum::http::HeaderMap;
use futures::Stream;
use tokio::sync::broadcast::{self, error::RecvError};
use ua_core::{Caller, UaResult};
use ua_store::ledger::Event;
use ua_tools::Hub;
use ua_tools::families::events::EventScope;

use crate::AppState;

/// Rows one backfill reads at most.
pub const BACKFILL_PAGE: usize = 1000;
/// Delivered seqs remembered for de-duplication; older ones become the floor.
const SEEN_CAP: usize = 4096;
/// How far below the highest delivered seq a lag backfill starts, to cover
/// rows broadcast out of order.
const REORDER_SLACK: i64 = 64;

/// One item of a scoped stream.
#[derive(Debug, Clone)]
pub enum StreamItem {
    Event(Box<Event>),
    /// Scoped rows with `after_seq < seq < until_seq` (or any seq after
    /// `after_seq` when `until_seq` is `None`) may be missing.
    Gap {
        after_seq: i64,
        until_seq: Option<i64>,
        reason: &'static str,
    },
}

impl StreamItem {
    /// The JSON body of a gap item.
    pub fn gap_json(after_seq: i64, until_seq: Option<i64>, reason: &str) -> serde_json::Value {
        serde_json::json!({ "gap": true, "after_seq": after_seq, "until_seq": until_seq, "reason": reason })
    }
}

/// The resume point a reconnecting client sent: `Last-Event-ID` (a ledger
/// seq), else an explicit `after_seq` query value.
pub fn resume_point(headers: &HeaderMap, after_seq: Option<i64>) -> Option<i64> {
    headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok())
        .or(after_seq)
        .map(|n| n.max(0))
}

struct Cursor {
    hub: Hub,
    scope: EventScope,
    rx: broadcast::Receiver<Event>,
    /// Every seq at or below this was delivered or predates the stream.
    floor: i64,
    seen: BTreeSet<i64>,
    max_seen: i64,
    queue: VecDeque<StreamItem>,
}

impl Cursor {
    /// Record `seq` as handled; false when it already was.
    fn accept(&mut self, seq: i64) -> bool {
        if seq <= self.floor || !self.seen.insert(seq) {
            return false;
        }
        self.max_seen = self.max_seen.max(seq);
        while self.seen.len() > SEEN_CAP {
            if let Some(s) = self.seen.pop_first() {
                self.floor = self.floor.max(s);
            }
        }
        true
    }

    /// Queue the scoped rows after `after` that were not delivered yet.
    async fn backfill(&mut self, after: i64) {
        let scope = self.scope.clone();
        let read = self.hub.db().read_async(move |c| scope.read_after(c, after, BACKFILL_PAGE)).await;
        match read {
            Ok(rows) => {
                // A full page holds the newest matching rows; older ones
                // between `after` and the first row may be missing.
                if rows.len() >= BACKFILL_PAGE
                    && let Some(first) = rows.first()
                {
                    self.queue.push_back(StreamItem::Gap {
                        after_seq: after,
                        until_seq: Some(first.seq),
                        reason: "backfill_limit",
                    });
                }
                for row in rows {
                    if self.accept(row.seq) {
                        self.queue.push_back(StreamItem::Event(Box::new(row)));
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "event stream backfill failed");
                self.queue.push_back(StreamItem::Gap {
                    after_seq: after,
                    until_seq: None,
                    reason: "backfill_failed",
                });
            }
        }
    }

    async fn next(mut self) -> Option<(StreamItem, Self)> {
        loop {
            if let Some(item) = self.queue.pop_front() {
                return Some((item, self));
            }
            match self.rx.recv().await {
                Ok(ev) => {
                    if self.accept(ev.seq) && self.scope.matches(&ev) {
                        return Some((StreamItem::Event(Box::new(ev)), self));
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    let after = self.floor.max(self.max_seen - REORDER_SLACK);
                    self.backfill(after).await;
                }
                Err(RecvError::Closed) => return None,
            }
        }
    }
}

/// Open a scoped stream for `caller`.
///
/// Fails with the governed call's error (profile, policy, approval) when the
/// caller may not run `event_log_query` with this scope. `resume_after`
/// replays the scoped rows after that seq first; without it the stream
/// starts at the ledger's current end.
pub async fn open(
    state: &AppState,
    caller: &Caller,
    scope: EventScope,
    resume_after: Option<i64>,
) -> UaResult<impl Stream<Item = StreamItem> + Send + 'static> {
    state.registry.call(&state.hub, caller, "event_log_query", scope.admission_args()).await?;
    // Subscribe before reading the end of the ledger, so no row commits in
    // between unseen.
    let rx = state.hub.db().subscribe();
    let end: i64 = state
        .hub
        .db()
        .read_async(|c| Ok(c.query_row("SELECT COALESCE(MAX(seq), 0) FROM event_log", [], |r| r.get(0))?))
        .await?;
    let start = resume_after.map_or(end, |n| n.min(end));
    let mut cursor = Cursor {
        hub: state.hub.clone(),
        scope,
        rx,
        floor: start,
        seen: BTreeSet::new(),
        max_seen: start,
        queue: VecDeque::new(),
    };
    if resume_after.is_some() && start < end {
        cursor.backfill(start).await;
    }
    Ok(futures::stream::unfold(cursor, Cursor::next))
}
