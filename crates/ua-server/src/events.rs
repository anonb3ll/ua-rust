//! Scoped live ledger streams, shared by `/api/events/stream` (JSON) and
//! `/ui/activity/stream` (rendered rows).
//!
//! A stream is opened with one governed `event_log_query` call as the
//! caller, so the profile, policy and decision row apply exactly as they do
//! to the tool. Every row it then sends, live or backfilled, passes the same
//! [`EventScope`] the tool applies.
//!
//! The caller stays authorized only while it would still be let in: every
//! [`RECHECK_EVERY`], and at once when a token-revoked, logout,
//! session-ended or profile-changed event is broadcast, the stream checks
//! that the credential it was opened with still resolves to the same
//! identity and that its profile (after any policy overlay) still allows
//! `event_log_query`. When it does not, the stream ends.
//!
//! Nothing is dropped silently:
//! - A reconnect with `Last-Event-ID: <seq>` first replays the scoped rows
//!   after that seq from the ledger.
//! - When the broadcast receiver lags (a slow client), the stream backfills
//!   from the ledger after the last row it saw.
//! - A backfill pages forward until a short page. When it stops early (the
//!   ledger read failed, or more than [`BACKFILL_CAP`] rows matched), the
//!   stream sends a [`StreamItem::Gap`] from the last row it read up to the
//!   next live row (or open-ended when the stream closes first).
//!
//! Ledger writes are broadcast after their commit, outside the writer lock,
//! so two writers can broadcast slightly out of seq order. The stream
//! therefore remembers the seqs it has delivered rather than only the
//! highest one.

use std::collections::{BTreeSet, VecDeque};
use std::time::Duration;

use axum::http::{HeaderMap, header};
use futures::Stream;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time::{Interval, MissedTickBehavior};
use ua_core::identity::Transport;
use ua_core::{ActorKind, Caller, UaResult};
use ua_store::ledger::Event;
use ua_tools::families::events::EventScope;

use crate::AppState;
use crate::auth::{AuthIdentity, caller_for, resolve_bearer};

/// Rows one backfill page reads.
pub const BACKFILL_PAGE: usize = 1000;
/// Rows one backfill reads in all before it reports the rest as a gap.
pub const BACKFILL_CAP: usize = 5000;
/// How often an open stream re-checks its caller.
pub const RECHECK_EVERY: Duration = Duration::from_secs(60);
/// Delivered seqs remembered for de-duplication; older ones become the floor.
const SEEN_CAP: usize = 4096;
/// How far below the highest delivered seq a lag backfill starts, to cover
/// rows broadcast out of order.
const REORDER_SLACK: i64 = 64;
/// Ledger channels after which an open stream re-checks its caller at once.
const AUTH_CHANNELS: &[&str] = &[
    "agent.token.revoked",
    "agent.token.rotated",
    "agent.oauth.token_revoked",
    "agent.ui.logout",
    "agent.session.ended",
    "agent.profile.changed",
];

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

/// The credential a stream was opened with.
enum Credential {
    Bearer(SecretString),
    /// Only the request's `Cookie` headers.
    Cookie(HeaderMap),
    /// A local anonymous caller (authentication not enforced).
    Unverified,
}

/// What a stream needs to re-check its caller later: the credential, the
/// identity it resolved to and the request context of the profile.
pub struct StreamAuth {
    credential: Credential,
    label: String,
    kind: ActorKind,
    path: &'static str,
    session_key: Option<String>,
    transport: Transport,
}

impl StreamAuth {
    /// Capture the credential of the request that `caller` was built from.
    /// A bearer takes precedence over a session cookie, as in
    /// [`crate::auth::authenticate`].
    pub fn from_request(headers: &HeaderMap, caller: &Caller, path: &'static str) -> Self {
        let bearer = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim);
        let credential = if !caller.enforce_profile {
            Credential::Unverified
        } else if let Some(t) = bearer {
            Credential::Bearer(SecretString::from(t.to_string()))
        } else {
            let mut cookies = HeaderMap::new();
            for v in headers.get_all(header::COOKIE) {
                cookies.append(header::COOKIE, v.clone());
            }
            Credential::Cookie(cookies)
        };
        Self {
            credential,
            label: caller.label.clone(),
            kind: caller.kind,
            path,
            session_key: caller.session_key.clone(),
            transport: caller.transport,
        }
    }

    /// Whether the caller would still be let in: the credential resolves to
    /// the same identity, and its profile, after any policy overlay, allows
    /// `event_log_query`.
    pub fn still_allowed(&self, state: &AppState) -> bool {
        let id = match &self.credential {
            Credential::Unverified => {
                AuthIdentity { label: self.label.clone(), kind: self.kind, verified: false }
            }
            Credential::Bearer(t) => match resolve_bearer(state, t.expose_secret(), self.path) {
                Some(id) => id,
                None => return false,
            },
            Credential::Cookie(h) => match crate::login::session_from_headers(state, h) {
                Some(s) => AuthIdentity { label: s.label, kind: ActorKind::Human, verified: true },
                None => return false,
            },
        };
        if id.label != self.label {
            return false;
        }
        let caller = caller_for(state, &id, self.session_key.clone(), self.transport);
        if !caller.enforce_profile {
            return true;
        }
        let mut profile = caller.profile;
        if let Some(path) = state.hub.cfg().policy_file.as_deref() {
            // Same overlay as the registry; a policy that cannot be loaded
            // refuses, as the registry does.
            let Ok(policy) = ua_tools::policy::load(path) else { return false };
            if caller.kind != ActorKind::Human {
                let code_default = ua_tools::sessions::default_profile(&state.hub, &caller.label);
                let tools = state.registry.all().map(|t| t.name);
                if let Some(overlay) =
                    ua_tools::policy::overlay_profile(&policy, &caller.label, code_default, tools)
                    && profile.rank() > overlay.rank()
                {
                    profile = overlay;
                }
            }
        }
        profile.allows_tool("event_log_query")
    }
}

struct Cursor {
    state: AppState,
    scope: EventScope,
    auth: StreamAuth,
    rx: broadcast::Receiver<Event>,
    recheck: Interval,
    /// Every seq at or below this was delivered or predates the stream.
    floor: i64,
    seen: BTreeSet<i64>,
    max_seen: i64,
    queue: VecDeque<StreamItem>,
    /// A backfill stopped early: scoped rows after this seq may be missing
    /// up to the next live row.
    pending_gap: Option<(i64, &'static str)>,
    closed: bool,
    page: usize,
    cap: usize,
}

impl Cursor {
    fn new(
        state: AppState,
        scope: EventScope,
        auth: StreamAuth,
        rx: broadcast::Receiver<Event>,
        start: i64,
    ) -> Self {
        let mut recheck =
            tokio::time::interval_at(tokio::time::Instant::now() + RECHECK_EVERY, RECHECK_EVERY);
        recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self {
            state,
            scope,
            auth,
            rx,
            recheck,
            floor: start,
            seen: BTreeSet::new(),
            max_seen: start,
            queue: VecDeque::new(),
            pending_gap: None,
            closed: false,
            page: BACKFILL_PAGE,
            cap: BACKFILL_CAP,
        }
    }

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

    /// Queue the scoped rows after `after` that were not delivered yet,
    /// paging forward until a short page. Stopping early (a failed read, or
    /// `cap` rows read) leaves a pending gap after the last row read.
    async fn backfill(&mut self, after: i64) {
        // This backfill starts at or below any earlier pending gap, so it
        // replaces it: it either covers that range or reports a new one.
        self.pending_gap = None;
        let mut pos = after;
        let mut read = 0usize;
        loop {
            let (scope, page) = (self.scope.clone(), self.page);
            let rows = self.state.hub.db().read_async(move |c| scope.read_after(c, pos, page)).await;
            match rows {
                Ok(rows) => {
                    let n = rows.len();
                    for row in rows {
                        pos = pos.max(row.seq);
                        if self.accept(row.seq) {
                            self.queue.push_back(StreamItem::Event(Box::new(row)));
                        }
                    }
                    read += n;
                    if n < page {
                        return;
                    }
                    if read >= self.cap {
                        self.pending_gap = Some((pos, "backfill_limit"));
                        return;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "event stream backfill failed");
                    self.pending_gap = Some((pos, "backfill_failed"));
                    return;
                }
            }
        }
    }

    /// A live row with `seq` arrived: a pending gap ends just before it.
    fn close_gap(&mut self, seq: i64) {
        if let Some((after, reason)) = self.pending_gap
            && seq > after
        {
            self.pending_gap = None;
            if seq > after + 1 {
                self.queue.push_back(StreamItem::Gap { after_seq: after, until_seq: Some(seq), reason });
            }
        }
    }

    async fn next(mut self) -> Option<(StreamItem, Self)> {
        loop {
            if let Some(item) = self.queue.pop_front() {
                return Some((item, self));
            }
            if self.closed {
                return None;
            }
            tokio::select! {
                _ = self.recheck.tick() => {
                    if !self.auth.still_allowed(&self.state) {
                        return None;
                    }
                }
                recv = self.rx.recv() => match recv {
                    Ok(ev) => {
                        if AUTH_CHANNELS.contains(&ev.channel.as_str()) && !self.auth.still_allowed(&self.state) {
                            return None;
                        }
                        self.close_gap(ev.seq);
                        if self.accept(ev.seq) && self.scope.matches(&ev) {
                            self.queue.push_back(StreamItem::Event(Box::new(ev)));
                        }
                    }
                    Err(RecvError::Lagged(_)) => {
                        let after = self.floor.max(self.max_seen - REORDER_SLACK);
                        self.backfill(after).await;
                    }
                    Err(RecvError::Closed) => {
                        if let Some((after_seq, reason)) = self.pending_gap.take() {
                            self.queue.push_back(StreamItem::Gap { after_seq, until_seq: None, reason });
                        }
                        self.closed = true;
                    }
                },
            }
        }
    }
}

/// Open a scoped stream for `caller`.
///
/// Fails with the governed call's error (profile, policy, approval) when the
/// caller may not run `event_log_query` with this scope. `resume_after`
/// replays the scoped rows after that seq first; without it the stream
/// starts at the ledger's current end. `auth` re-checks the caller while the
/// stream is open.
pub async fn open(
    state: &AppState,
    caller: &Caller,
    auth: StreamAuth,
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
    let mut cursor = Cursor::new(state.clone(), scope, auth, rx, start);
    if resume_after.is_some() && start < end {
        cursor.backfill(start).await;
    }
    Ok(futures::stream::unfold(cursor, Cursor::next))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use ua_core::Config;
    use ua_store::{EventInput, ledger};
    use ua_tools::{Hub, builtin_registry};

    use super::*;

    fn state() -> AppState {
        let hub = Hub::in_memory(Config::for_home(std::env::temp_dir())).unwrap();
        AppState { hub, registry: Arc::new(builtin_registry()) }
    }

    fn append(state: &AppState, channel: &str) -> i64 {
        state
            .hub
            .db()
            .write(|tx| ledger::append(tx, EventInput::new(channel, json!({})).by("tester")))
            .unwrap()
            .unwrap()
            .seq
    }

    fn local_auth() -> StreamAuth {
        StreamAuth {
            credential: Credential::Unverified,
            label: "local".into(),
            kind: ActorKind::Anonymous,
            path: "/api/events/stream",
            session_key: None,
            transport: Transport::Http,
        }
    }

    fn cursor(state: &AppState, start: i64) -> Cursor {
        let scope = EventScope { channels: None, channel_prefix: Some("test.keep".into()) };
        let mut c = Cursor::new(state.clone(), scope, local_auth(), state.hub.db().subscribe(), start);
        c.page = 10;
        c.cap = 30;
        c
    }

    /// Drain items until one is the event `last`, or fail after a while.
    async fn drain_until(mut c: Cursor, last: i64) -> Vec<StreamItem> {
        let mut out = Vec::new();
        loop {
            let step = tokio::time::timeout(Duration::from_secs(5), c.next()).await;
            let (item, next) = step.expect("stream stalled").expect("stream ended");
            let done = matches!(&item, StreamItem::Event(e) if e.seq == last);
            out.push(item);
            c = next;
            if done {
                return out;
            }
        }
    }

    /// Every scoped seq up to `last` is delivered once or inside a gap.
    fn assert_covered(items: &[StreamItem], scoped: &[i64]) {
        let mut delivered = BTreeSet::new();
        let mut gaps = Vec::new();
        for item in items {
            match item {
                StreamItem::Event(e) => assert!(delivered.insert(e.seq), "seq {} delivered twice", e.seq),
                StreamItem::Gap { after_seq, until_seq, .. } => {
                    assert!(until_seq.is_none_or(|u| u > after_seq + 1), "empty gap {item:?}");
                    gaps.push((*after_seq, *until_seq));
                }
            }
        }
        for seq in scoped {
            let in_gap = gaps.iter().any(|(a, u)| seq > a && u.is_none_or(|u| *seq < u));
            assert!(delivered.contains(seq) || in_gap, "seq {seq} silently skipped");
        }
    }

    #[tokio::test]
    async fn a_capped_backfill_reports_the_rest_as_a_gap_up_to_the_next_live_row() {
        let state = state();
        let mut scoped = Vec::new();
        for i in 0..100 {
            if i % 3 == 0 {
                append(&state, "test.noise");
            }
            scoped.push(append(&state, "test.keep"));
        }
        let mut c = cursor(&state, 0);
        c.backfill(0).await;
        // 30 rows read (the cap), the rest pending as a gap.
        assert_eq!(c.queue.len(), 30);
        let (after, reason) = c.pending_gap.expect("a pending gap");
        assert_eq!((after, reason), (scoped[29], "backfill_limit"));

        let live = append(&state, "test.keep");
        scoped.push(live);
        let items = drain_until(c, live).await;
        assert_covered(&items, &scoped);
        let gap = items.iter().find_map(|i| match i {
            StreamItem::Gap { after_seq, until_seq, .. } => Some((*after_seq, *until_seq)),
            _ => None,
        });
        assert_eq!(gap, Some((scoped[29], Some(live))));
    }

    #[tokio::test]
    async fn an_uncapped_backfill_pages_forward_to_the_end_without_a_gap() {
        let state = state();
        let mut scoped = Vec::new();
        for i in 0..25 {
            append(&state, "test.noise");
            if i % 2 == 0 {
                scoped.push(append(&state, "test.keep"));
            }
        }
        let mut c = cursor(&state, 0);
        c.backfill(0).await;
        assert!(c.pending_gap.is_none());
        let live = append(&state, "test.keep");
        scoped.push(live);
        let items = drain_until(c, live).await;
        assert!(items.iter().all(|i| matches!(i, StreamItem::Event(_))), "{items:?}");
        assert_eq!(
            items
                .iter()
                .filter_map(|i| if let StreamItem::Event(e) = i { Some(e.seq) } else { None })
                .collect::<Vec<_>>(),
            scoped
        );
    }

    #[tokio::test]
    async fn a_lag_after_a_capped_backfill_closes_the_old_gap() {
        let state = state();
        let mut scoped = Vec::new();
        for _ in 0..40 {
            scoped.push(append(&state, "test.keep"));
        }
        let mut c = cursor(&state, 0);
        c.backfill(0).await;
        assert!(c.pending_gap.is_some());
        // A later backfill from below the gap that reaches the end replaces
        // it: rows after the old gap start are now all queued.
        c.cap = 1000;
        let after = c.floor.max(c.max_seen - REORDER_SLACK);
        c.backfill(after).await;
        assert!(c.pending_gap.is_none());
        let live = append(&state, "test.keep");
        scoped.push(live);
        let items = drain_until(c, live).await;
        assert!(items.iter().all(|i| matches!(i, StreamItem::Event(_))), "{items:?}");
        assert_covered(&items, &scoped);
    }
}
