//! Scoped live ledger streams, shared by `/api/events/stream` (JSON) and
//! `/ui/activity/stream` (rendered rows).
//!
//! A stream is opened with one governed `event_log_query` call as the
//! caller, so the profile, policy and decision row apply exactly as they do
//! to the tool. Live and backfilled rows share the tool's channel filters
//! and event visibility.
//!
//! The caller stays authorized only while it would still be let in: every
//! [`RECHECK_EVERY`], and soon after a token-revoked, logout,
//! session-ended, profile-changed or config-revision event is broadcast, the
//! stream checks that the credential it was opened with still resolves to
//! the same identity and that the same admission `open` ran (profile after
//! any policy overlay, then the policy rules, with the stream's own scope as
//! the arguments) still lets it in. The re-check runs on the blocking pool,
//! since it reads the policy file and the database. When the caller is no
//! longer let in, the stream sends one [`StreamItem::Revoked`] and ends.
//!
//! Auth events come in bursts (a config revision touches every stream), so
//! a stream does not re-check once per event: the first one schedules a
//! re-check [`RECHECK_COALESCE`] later, and the events that arrive until
//! then are covered by it. Each stream runs at most one re-check at a time,
//! and an auth event that arrives while one runs schedules another, so the
//! last change is always checked. Rows that arrive while a re-check is
//! pending are held back until it passes, so nothing is delivered after an
//! auth event before the caller is checked again. A lagged receiver may
//! have dropped auth events, so a lag schedules a re-check too.
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

use std::borrow::Cow;
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use axum::http::{HeaderMap, header};
use futures::Stream;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time::{Interval, MissedTickBehavior};
use ua_core::identity::Transport;
use ua_core::{ActorKind, Caller, UaResult};
use ua_store::ledger::Event;
use ua_tools::families::events::{EventReader, EventScope};
use ua_tools::policy::{self, Policy, RuleKind, Verdict};

use crate::AppState;
use crate::auth::{AuthIdentity, caller_for, resolve_bearer_blocking};

/// Rows one backfill page reads.
pub const BACKFILL_PAGE: usize = 1000;
/// Rows one backfill reads in all before it reports the rest as a gap.
pub const BACKFILL_CAP: usize = 5000;
/// How often an open stream re-checks its caller.
pub const RECHECK_EVERY: Duration = Duration::from_secs(60);
/// How long after an auth event a stream re-checks its caller; further
/// auth events in that window share the one re-check.
pub const RECHECK_COALESCE: Duration = Duration::from_millis(250);
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
    "agent.config.revision",
];
/// The tool whose admission a stream holds.
const TOOL: &str = "event_log_query";

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
    /// The caller is no longer let in; the stream ends after this item.
    /// `reason` is a short code, never a credential.
    Revoked {
        reason: &'static str,
    },
}

impl StreamItem {
    /// The JSON body of a gap item.
    pub fn gap_json(after_seq: i64, until_seq: Option<i64>, reason: &str) -> serde_json::Value {
        serde_json::json!({ "gap": true, "after_seq": after_seq, "until_seq": until_seq, "reason": reason })
    }

    /// The JSON body of a revocation item.
    pub fn revoked_json(reason: &str) -> serde_json::Value {
        serde_json::json!({ "auth_revoked": true, "reason": reason })
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
    /// The organization the credential resolved to.
    org_id: String,
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
            org_id: caller.org_id.clone(),
            path,
            session_key: caller.session_key.clone(),
            transport: caller.transport,
        }
    }

    /// Whether the caller would still be let in: the credential resolves to
    /// the same identity, and [`admit`] still lets it in with this scope.
    /// `admitted_gated` is whether the stream itself was admitted through an
    /// approval; a policy that newly requires one ends the stream.
    /// Blocking: it reads the database and the policy file.
    fn recheck(
        &self,
        state: &AppState,
        scope: &EventScope,
        admitted_gated: bool,
    ) -> Result<(), &'static str> {
        let id = match &self.credential {
            Credential::Unverified => {
                if let Err(e) = crate::auth::check_auth_policy(&state.hub) {
                    tracing::warn!(error = %e, "revoking unauthenticated event stream");
                    return Err("auth_required_multi_org");
                }
                AuthIdentity::in_default(self.label.clone(), self.kind, false)
            }
            Credential::Bearer(t) => {
                resolve_bearer_blocking(state, t.expose_secret(), self.path).ok_or("credential_invalid")?
            }
            Credential::Cookie(h) => match crate::login::session_from_headers_blocking(state, h) {
                Some(s) => AuthIdentity::in_default(s.label, ActorKind::Human, true),
                None => return Err("credential_invalid"),
            },
        };
        if id.label != self.label || id.kind != self.kind || id.org_id != self.org_id {
            return Err("identity_changed");
        }
        let caller = caller_for(state, &id, self.session_key.clone(), self.transport);
        match admit(state, &caller, scope)? {
            Admission::NeedsApproval if !admitted_gated => Err("approval_required"),
            _ => Ok(()),
        }
    }
}

/// How [`admit`] lets a caller in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    Allowed,
    /// The policy sends the call through the approval queue.
    NeedsApproval,
}

/// The admission of [`Registry::call`](ua_tools::Registry::call) for
/// `event_log_query` with the stream's scope as arguments: the profile
/// (after any policy overlay), then the policy rules. A policy file that
/// cannot be loaded refuses, as the registry does.
///
/// Per-call throttles (`rate_limit`, and a `cooldown` that needs no episode)
/// are left out: they limit how often the tool is called, and the stream's
/// own admission was such a call, so counting it again would end every
/// stream under a cooldown. They still apply when a stream is opened.
/// Blocking: it reads the database and the policy file (cached by mtime and
/// size in [`policy::load`]).
fn admit(state: &AppState, caller: &Caller, scope: &EventScope) -> Result<Admission, &'static str> {
    let loaded = state.hub.cfg().policy_file.as_deref().map(policy::load);
    let mut profile = caller.profile;
    if let Some(Ok(p)) = &loaded
        && caller.enforce_profile
        && caller.kind != ActorKind::Human
    {
        let code_default = ua_tools::sessions::default_profile(&state.hub, &caller.org_id, &caller.label);
        let tools = state.registry.all().map(|t| t.name);
        if let Some(overlay) = policy::overlay_profile(p, &caller.label, code_default, tools)
            && profile.rank() > overlay.rank()
        {
            profile = overlay;
        }
    }
    if caller.enforce_profile && !profile.allows_tool(TOOL) {
        return Err("profile_denied");
    }
    let Some(loaded) = loaded else { return Ok(Admission::Allowed) };
    let policy = loaded.map_err(|_| "policy_unavailable")?;
    let policy = without_throttles(&policy);
    let caller = Caller { profile, ..caller.clone() };
    let args = scope.admission_args();
    let verdict = state
        .hub
        .db()
        .read(|c| Ok(policy::evaluate(c, &policy, &caller, TOOL, &args)))
        .map_err(|_| "policy_unavailable")?;
    match verdict {
        Ok(Verdict::Allow) => Ok(Admission::Allowed),
        Ok(Verdict::RequireApproval(_)) => Ok(Admission::NeedsApproval),
        Err(_) => Err("policy_denied"),
    }
}

/// `policy` with its per-call throttles switched off (see [`admit`]). The
/// rules stay in place, so `default_action: deny` counts them as before.
fn without_throttles(policy: &Policy) -> Cow<'_, Policy> {
    let throttle =
        |k: RuleKind, episode: bool| k == RuleKind::RateLimit || (k == RuleKind::Cooldown && !episode);
    if !policy.rules.iter().any(|r| throttle(r.kind, r.require_episode)) {
        return Cow::Borrowed(policy);
    }
    let mut out = policy.clone();
    for r in &mut out.rules {
        if r.kind == RuleKind::RateLimit {
            r.max_calls = None;
        } else if r.kind == RuleKind::Cooldown && !r.require_episode {
            r.cooldown_seconds = None;
        }
    }
    Cow::Owned(out)
}

struct Cursor {
    state: AppState,
    scope: EventScope,
    reader: EventReader,
    auth: Arc<StreamAuth>,
    /// The stream was admitted through an approval.
    admitted_gated: bool,
    rx: broadcast::Receiver<Event>,
    recheck: Interval,
    /// When the re-check an auth event scheduled runs; `None` when none is pending.
    recheck_due: Option<tokio::time::Instant>,
    /// Items that arrived while a re-check was pending, released when it passes.
    held: VecDeque<StreamItem>,
    /// Re-checks run so far.
    rechecks: u64,
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
        admitted_gated: bool,
        rx: broadcast::Receiver<Event>,
        start: i64,
        caller: &Caller,
    ) -> Self {
        let mut recheck =
            tokio::time::interval_at(tokio::time::Instant::now() + RECHECK_EVERY, RECHECK_EVERY);
        recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self {
            reader: EventReader::new(state.hub.cfg(), caller),
            state,
            scope,
            auth: Arc::new(auth),
            admitted_gated,
            rx,
            recheck,
            recheck_due: None,
            held: VecDeque::new(),
            rechecks: 0,
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

    /// Queue `item`, or hold it back while a re-check is pending.
    fn emit(&mut self, item: StreamItem) {
        if self.recheck_due.is_some() {
            self.held.push_back(item);
        } else {
            self.queue.push_back(item);
        }
    }

    /// Schedule a re-check [`RECHECK_COALESCE`] from now, unless one is
    /// already pending (it then covers this request too).
    fn schedule_recheck(&mut self) {
        if self.recheck_due.is_none() {
            self.recheck_due = Some(tokio::time::Instant::now() + RECHECK_COALESCE);
        }
    }

    /// Run a re-check now: release the held items when the caller is still
    /// let in, end the stream when not.
    async fn run_recheck(&mut self) {
        self.recheck_due = None;
        self.recheck.reset();
        match self.still_allowed().await {
            Ok(()) => {
                let held = std::mem::take(&mut self.held);
                self.queue.extend(held);
            }
            Err(reason) => self.revoke(reason),
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
            let (scope, reader, page) = (self.scope.clone(), self.reader.clone(), self.page);
            let rows = self.state.hub.db().read_async(move |c| scope.read_after(c, &reader, pos, page)).await;
            match rows {
                Ok(rows) => {
                    let n = rows.len();
                    for row in rows {
                        pos = pos.max(row.seq);
                        if self.accept(row.seq) {
                            self.emit(StreamItem::Event(Box::new(row)));
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

    /// Re-check the caller on the blocking pool.
    async fn still_allowed(&mut self) -> Result<(), &'static str> {
        self.rechecks += 1;
        let (auth, state, scope, gated) =
            (self.auth.clone(), self.state.clone(), self.scope.clone(), self.admitted_gated);
        tokio::task::spawn_blocking(move || auth.recheck(&state, &scope, gated))
            .await
            .unwrap_or(Err("recheck_failed"))
    }

    /// End the stream with a revocation notice and nothing after it.
    fn revoke(&mut self, reason: &'static str) {
        self.queue.clear();
        self.held.clear();
        self.recheck_due = None;
        self.pending_gap = None;
        self.queue.push_back(StreamItem::Revoked { reason });
        self.closed = true;
    }

    /// A live row with `seq` arrived: a pending gap ends just before it.
    fn close_gap(&mut self, seq: i64) {
        if let Some((after, reason)) = self.pending_gap
            && seq > after
        {
            self.pending_gap = None;
            if seq > after + 1 {
                self.emit(StreamItem::Gap { after_seq: after, until_seq: Some(seq), reason });
            }
        }
    }

    async fn can_see(&self, event: &Event) -> UaResult<bool> {
        if !EventReader::needs_visibility_check(event) {
            return Ok(true);
        }
        let (reader, seq) = (self.reader.clone(), event.seq);
        self.state.hub.db().read_async(move |c| reader.includes(c, seq)).await
    }

    async fn next(mut self) -> Option<(StreamItem, Self)> {
        loop {
            if let Some(item) = self.queue.pop_front() {
                return Some((item, self));
            }
            if self.closed {
                return None;
            }
            let due = self.recheck_due;
            let shutdown = self.state.shutdown.clone();
            tokio::select! {
                // The server is shutting down: end the stream (a client
                // reconnects with Last-Event-ID to the next hub process).
                _ = shutdown.cancelled() => self.closed = true,
                _ = sleep_until_due(due), if due.is_some() => self.run_recheck().await,
                _ = self.recheck.tick() => self.run_recheck().await,
                recv = self.rx.recv() => match recv {
                    Ok(ev) => {
                        if matches!(self.auth.credential, Credential::Unverified)
                            && !self.state.hub.cfg().enforce_auth
                        {
                            let hub = self.state.hub.clone();
                            let allowed = tokio::task::spawn_blocking(move || {
                                crate::auth::check_auth_policy(&hub)
                            })
                            .await
                            .unwrap_or_else(|e| {
                                Err(ua_core::UaError::internal(format!("blocking task failed: {e}")))
                            });
                            if let Err(e) = allowed {
                                tracing::warn!(error = %e, "revoking unauthenticated event stream");
                                self.revoke("auth_required_multi_org");
                                continue;
                            }
                        }
                        if AUTH_CHANNELS.contains(&ev.channel.as_str()) {
                            self.schedule_recheck();
                        }
                        match self.can_see(&ev).await {
                            Ok(true) => {}
                            Ok(false) => continue,
                            Err(e) => {
                                tracing::warn!(error = %e, "event stream visibility check failed");
                                self.revoke("visibility_check_failed");
                                continue;
                            }
                        }
                        self.close_gap(ev.seq);
                        if self.accept(ev.seq) && self.scope.matches(&ev) {
                            self.emit(StreamItem::Event(Box::new(ev)));
                        }
                    }
                    Err(RecvError::Lagged(_)) => {
                        // The dropped events may have included auth events.
                        self.schedule_recheck();
                        let after = self.floor.max(self.max_seen - REORDER_SLACK);
                        self.backfill(after).await;
                    }
                    Err(RecvError::Closed) => {
                        // Settle a pending re-check first, so held rows are
                        // either delivered or dropped with a revocation.
                        if self.recheck_due.is_some() {
                            self.run_recheck().await;
                            if self.closed {
                                continue;
                            }
                        }
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

/// Sleep until `due`; never returns when it is `None`.
async fn sleep_until_due(due: Option<tokio::time::Instant>) {
    match due {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
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
    state.registry.call(&state.hub, caller, TOOL, scope.admission_args()).await?;
    // Whether that admission went through an approval, so a re-check can
    // tell a policy that newly requires one. It changing in between refuses.
    let admitted_gated = {
        let (state, caller, scope) = (state.clone(), caller.clone(), scope.clone());
        tokio::task::spawn_blocking(move || admit(&state, &caller, &scope))
            .await
            .map_err(|e| ua_core::UaError::internal(format!("blocking task failed: {e}")))?
            .map_err(|reason| {
                ua_core::UaError::denied(reason, "the stream's admission changed while it opened")
            })?
            == Admission::NeedsApproval
    };
    // Subscribe before reading the end of the ledger, so no row commits in
    // between unseen.
    let rx = state.hub.db().subscribe();
    let end: i64 = state
        .hub
        .db()
        .read_async(|c| Ok(c.query_row("SELECT COALESCE(MAX(seq), 0) FROM event_log", [], |r| r.get(0))?))
        .await?;
    let start = resume_after.map_or(end, |n| n.min(end));
    let mut cursor = Cursor::new(state.clone(), scope, auth, admitted_gated, rx, start, caller);
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
        AppState::new(hub, Arc::new(builtin_registry()))
    }

    fn append(state: &AppState, channel: &str) -> i64 {
        state
            .hub
            .db()
            .write(|tx| {
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, channel, json!({})).by("tester"))
            })
            .unwrap()
            .unwrap()
            .seq
    }

    fn local_auth() -> StreamAuth {
        StreamAuth {
            credential: Credential::Unverified,
            label: "local".into(),
            kind: ActorKind::Anonymous,
            org_id: ua_core::DEFAULT_ORG.into(),
            path: "/api/events/stream",
            session_key: None,
            transport: Transport::Http,
        }
    }

    fn cursor(state: &AppState, start: i64) -> Cursor {
        let scope = EventScope { channels: None, channel_prefix: Some("test.keep".into()) };
        let caller = Caller::local("local", Transport::Http);
        let mut c = Cursor::new(
            state.clone(),
            scope,
            local_auth(),
            false,
            state.hub.db().subscribe(),
            start,
            &caller,
        );
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
                StreamItem::Revoked { reason } => panic!("unexpected revocation: {reason}"),
            }
        }
        for seq in scoped {
            let in_gap = gaps.iter().any(|(a, u)| seq > a && u.is_none_or(|u| *seq < u));
            assert!(delivered.contains(seq) || in_gap, "seq {seq} silently skipped");
        }
    }

    #[tokio::test]
    async fn a_failed_recheck_sends_one_revocation_and_ends() {
        let state = state();
        let auth = StreamAuth {
            credential: Credential::Bearer(SecretString::from("not-a-known-token".to_string())),
            ..local_auth()
        };
        let scope = EventScope::default();
        let caller = Caller::local("local", Transport::Http);
        let c = Cursor::new(state.clone(), scope, auth, false, state.hub.db().subscribe(), 0, &caller);
        append(&state, "agent.token.revoked");
        append(&state, "test.keep");
        let (item, c) = tokio::time::timeout(Duration::from_secs(5), c.next())
            .await
            .expect("stream stalled")
            .expect("stream ended without a notice");
        assert!(matches!(item, StreamItem::Revoked { reason: "credential_invalid" }), "{item:?}");
        let after = tokio::time::timeout(Duration::from_secs(5), c.next()).await.expect("stream stalled");
        assert!(after.is_none(), "items after the revocation");
    }

    #[tokio::test]
    async fn unverified_recheck_refuses_when_second_org_exists() {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.enforce_auth = false;
        let state = AppState::new(Hub::in_memory(cfg).unwrap(), Arc::new(builtin_registry()));
        let auth = local_auth();
        let scope = EventScope::default();
        assert_eq!(auth.recheck(&state, &scope, false), Ok(()));

        state
            .hub
            .db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO orgs (id, slug, display_name, status, allowed_profiles, created_at) \
                     VALUES ('org-b', 'org-b', 'Org B', 'active', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        assert_eq!(auth.recheck(&state, &scope, false), Err("auth_required_multi_org"));
    }

    /// A state whose policy file is `dir/policy.yaml`, holding `text`.
    fn state_with_policy(dir: &std::path::Path, text: &str) -> (AppState, std::path::PathBuf) {
        let path = dir.join("policy.yaml");
        std::fs::write(&path, text).unwrap();
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.policy_file = Some(path.clone());
        let hub = Hub::in_memory(cfg).unwrap();
        (AppState::new(hub, Arc::new(builtin_registry())), path)
    }

    /// A private directory under the system temp dir, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("ua-events-{}", ulid::Ulid::generate()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const DENY_STREAM: &str = "version: 1\nrules:\n  - name: no-stream\n    type: tool\n    tool: event_log_query\n    action: deny\n";

    /// A burst of auth events shares a few re-checks instead of one each,
    /// and the change at the end of the burst still ends the stream.
    #[tokio::test]
    async fn a_burst_of_auth_events_is_rechecked_once_and_the_last_state_wins() {
        let dir = TempDir::new();
        let (state, path) = state_with_policy(&dir.0, "version: 1\n");
        let c = cursor(&state, 0);
        let consumer = tokio::spawn(c.next());
        const BURST: usize = 40;
        for _ in 0..BURST {
            append(&state, "agent.config.revision");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        std::fs::write(&path, DENY_STREAM).unwrap();
        ua_tools::policy::invalidate(&path);
        append(&state, "agent.config.revision");

        let (item, c) = tokio::time::timeout(Duration::from_secs(5), consumer)
            .await
            .expect("stream stalled")
            .unwrap()
            .expect("stream ended without a notice");
        assert!(matches!(item, StreamItem::Revoked { reason: "policy_denied" }), "{item:?}");
        assert!(c.rechecks < 10, "{} re-checks for {} auth events", c.rechecks, BURST + 1);
        let after = tokio::time::timeout(Duration::from_secs(5), c.next()).await.expect("stream stalled");
        assert!(after.is_none(), "items after the revocation");
    }

    /// Rows that arrive after an auth event wait for its re-check: they are
    /// delivered when it passes, and dropped with the revocation when not.
    #[tokio::test]
    async fn rows_after_an_auth_event_wait_for_the_recheck() {
        let dir = TempDir::new();
        let (state, path) = state_with_policy(&dir.0, "version: 1\n");
        let c = cursor(&state, 0);
        append(&state, "agent.profile.changed");
        let keep = append(&state, "test.keep");
        let started = tokio::time::Instant::now();
        let (item, c) =
            tokio::time::timeout(Duration::from_secs(5), c.next()).await.expect("stream stalled").unwrap();
        assert!(matches!(&item, StreamItem::Event(e) if e.seq == keep), "{item:?}");
        assert!(started.elapsed() >= RECHECK_COALESCE, "delivered before the re-check");
        assert_eq!(c.rechecks, 1);

        // The next change revokes: the row held behind it is never sent.
        std::fs::write(&path, DENY_STREAM).unwrap();
        ua_tools::policy::invalidate(&path);
        append(&state, "agent.config.revision");
        append(&state, "test.keep");
        let (item, c) =
            tokio::time::timeout(Duration::from_secs(5), c.next()).await.expect("stream stalled").unwrap();
        assert!(matches!(item, StreamItem::Revoked { reason: "policy_denied" }), "{item:?}");
        let after = tokio::time::timeout(Duration::from_secs(5), c.next()).await.expect("stream stalled");
        assert!(after.is_none(), "items after the revocation");
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
