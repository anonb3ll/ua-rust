//! `event_log_query` and `event_log_verify`.
//!
//! [`EventScope`] is the channel scoping `event_log_query` applies. The live
//! event streams (`/api/events/stream`, `/ui/activity/stream`) use the same
//! type, so a streamed or backfilled row is exactly a row the tool would
//! have returned to that caller.

use rusqlite::Connection;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::UaResult;
use ua_store::ledger::{self, Event, EventQuery};

use crate::registry::{Registry, ToolCtx, tool};

/// Largest page `event_log_query` returns.
pub const MAX_LIMIT: usize = 1000;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryArgs {
    /// Exact channel names.
    pub channels: Option<Vec<String>>,
    /// Only events created at or after this RFC 3339 time.
    pub since: Option<String>,
    /// 1-1000, default 100.
    pub limit: Option<usize>,
    /// Only events after this sequence number (cursor for polling).
    pub after_seq: Option<i64>,
    /// Channel prefix, e.g. `agent.task.`.
    pub channel_prefix: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyArgs {}

/// Which channels a reader sees: every listed channel (when a list is given)
/// that also starts with the prefix (when one is given).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventScope {
    pub channels: Option<Vec<String>>,
    pub channel_prefix: Option<String>,
}

impl EventScope {
    /// Whether a live event falls in this scope. Same rule as the SQL in
    /// [`ledger::query`]: an empty channel list does not filter.
    pub fn matches(&self, ev: &Event) -> bool {
        let listed = match self.channels.as_ref().filter(|c| !c.is_empty()) {
            Some(chs) => chs.iter().any(|c| *c == ev.channel),
            None => true,
        };
        listed && self.channel_prefix.as_deref().is_none_or(|p| ev.channel.starts_with(p))
    }

    /// The ledger query for this scope.
    pub fn query(&self, after_seq: Option<i64>, since: Option<String>, limit: Option<usize>) -> EventQuery {
        EventQuery {
            channels: self.channels.clone(),
            channel_prefix: self.channel_prefix.clone(),
            since,
            after_seq,
            originator: None,
            limit,
        }
    }

    /// Scoped rows after `after_seq`, at most `limit` (the newest ones when
    /// more match; see [`ledger::query`]).
    pub fn read_after(&self, conn: &Connection, after_seq: i64, limit: usize) -> UaResult<Vec<Event>> {
        ledger::query(conn, &self.query(Some(after_seq), None, Some(limit.clamp(1, MAX_LIMIT))))
    }

    /// `event_log_query` arguments for this scope, for a governed admission
    /// call that reads nothing new.
    pub fn admission_args(&self) -> Value {
        let mut args = json!({ "limit": 1, "after_seq": i64::MAX });
        if let Some(c) = &self.channels {
            args["channels"] = json!(c);
        }
        if let Some(p) = &self.channel_prefix {
            args["channel_prefix"] = json!(p);
        }
        args
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "event_log_query",
            "Read ledger events in commit order with optional channel, time and cursor filters.",
            |ctx: ToolCtx, a: QueryArgs| async move {
                let scope = EventScope { channels: a.channels, channel_prefix: a.channel_prefix };
                let q = scope.query(a.after_seq, a.since, a.limit);
                let events = ctx.hub.db().read_async(move |c| ledger::query(c, &q)).await?;
                let next = events.last().map(|e| e.seq);
                Ok(json!({ "events": events, "count": events.len(), "next_after_seq": next }))
            },
        )
        .family("observability")
        .read_only(),
    );
    r.add(
        tool(
            "event_log_verify",
            "Recompute the ledger hash chain and report the first broken entry, if any.",
            |ctx: ToolCtx, _: VerifyArgs| async move {
                let report = ctx.hub.db().read_async(ledger::verify).await?;
                Ok(serde_json::to_value(report)?)
            },
        )
        .family("observability")
        .read_only(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(channel: &str) -> Event {
        Event {
            seq: 1,
            ulid: String::new(),
            channel: channel.into(),
            payload: Value::Null,
            originator: None,
            episode_id: None,
            causal_parent_id: None,
            created_at: String::new(),
            dedupe_key: None,
            prev_hash: None,
            entry_hash: None,
        }
    }

    #[test]
    fn scope_matches_like_the_query() {
        let all = EventScope::default();
        assert!(all.matches(&ev("agent.task.updated")));
        let prefix = EventScope { channels: None, channel_prefix: Some("agent.task.".into()) };
        assert!(prefix.matches(&ev("agent.task.updated")));
        assert!(!prefix.matches(&ev("agent.memory.saved")));
        let both = EventScope {
            channels: Some(vec!["agent.task.updated".into(), "agent.memory.saved".into()]),
            channel_prefix: Some("agent.task.".into()),
        };
        assert!(both.matches(&ev("agent.task.updated")));
        assert!(!both.matches(&ev("agent.memory.saved")), "list and prefix both apply");
        let empty = EventScope { channels: Some(vec![]), channel_prefix: None };
        assert!(empty.matches(&ev("x")), "an empty list does not filter");
    }
}
