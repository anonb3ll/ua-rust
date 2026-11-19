//! `event_log_query` and `event_log_verify`.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use ua_store::ledger::{self, EventQuery};

use crate::registry::{Registry, ToolCtx, tool};

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

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "event_log_query",
            "Read ledger events in commit order with optional channel, time and cursor filters.",
            |ctx: ToolCtx, a: QueryArgs| async move {
                let q = EventQuery {
                    channels: a.channels,
                    channel_prefix: a.channel_prefix,
                    since: a.since,
                    after_seq: a.after_seq,
                    originator: None,
                    limit: a.limit,
                };
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
