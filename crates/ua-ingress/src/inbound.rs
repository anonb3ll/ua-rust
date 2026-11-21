//! Inbound deliveries: one table that remembers what other systems sent, so
//! a duplicate or a replay is recognised and a delivery whose handling never
//! finished can be told apart from one that did (`docs/ingress.md`).
//!
//! A row is keyed by organization, `source` (`github`, ...), `kind` (what
//! the key is: a delivery id, a body hash, ...) and the key itself. Its
//! state moves:
//!
//! ```text
//! (none) --record--> seen --accept--> accepted --finish--> finished
//!                     |                  |
//!                     +--release--> (none) <--release--+
//!                                        |
//!                     sweep (stale) --> abandoned
//! ```
//!
//! - `seen`: recorded, not taken on. A repeat is a duplicate.
//! - `accepted`: taken on by this process (the row carries the process's
//!   claim). A repeat while the claim is live is a duplicate.
//! - `finished`: handled. A repeat is a duplicate until the row expires.
//! - `abandoned`: was `accepted` under a claim that is gone (the process
//!   stopped) or older than the in-flight bound; the outcome is unknown.
//!
//! What a repeat of a stale `accepted` or an `abandoned` row means is the
//! caller's choice ([`Stale`]): a source whose effects are idempotent
//! (GitHub) takes it on again, so a crash between recording and handling
//! does not lose the delivery; a source whose effects are not (Slack
//! commands) treats it as a duplicate and reports it.
//!
//! Every function takes a [`WriteTx`]: the caller records a delivery in the
//! same transaction as whatever else it writes (its ledger event, for one),
//! and this module opens no connection of its own.

use std::sync::OnceLock;

use rusqlite::{OptionalExtension, params};
use ua_core::{UaError, UaResult};
use ua_store::{Part, Procedure, SchemaPart, WriteTx};

/// The table, its indexes and its constraints. Times are Unix seconds.
pub const SCHEMA: SchemaPart = SchemaPart {
    name: "ingress.inbound.v1",
    sql: "
CREATE TABLE IF NOT EXISTS inbound_deliveries (
    org_id       TEXT NOT NULL,
    source       TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 64),
    kind         TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    delivery_key TEXT NOT NULL CHECK (length(delivery_key) BETWEEN 1 AND 256),
    state        TEXT NOT NULL CHECK (state IN ('seen', 'accepted', 'finished', 'abandoned')),
    received_at  INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    claim        TEXT,
    identity     TEXT,
    detail       TEXT,
    PRIMARY KEY (org_id, source, kind, delivery_key)
);
CREATE INDEX IF NOT EXISTS idx_inbound_deliveries_expiry
    ON inbound_deliveries (source, kind, expires_at);
CREATE INDEX IF NOT EXISTS idx_inbound_deliveries_received
    ON inbound_deliveries (org_id, source, kind, received_at);
",
};

/// The organization triggers for the table (`inbound_deliveries_org_exists`,
/// `inbound_deliveries_org_immutable`). Its `org_id` is `NOT NULL` from the
/// table's first part.
pub const TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.ingress", &["inbound_deliveries"]);

/// The crate's schema parts, in application order. They need
/// `organization.v1.store` applied first.
pub fn schema_parts() -> Vec<Part> {
    vec![SCHEMA.into(), TENANT_PART.into()]
}

/// A delivery's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Seen,
    Accepted,
    Finished,
    Abandoned,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Seen => "seen",
            State::Accepted => "accepted",
            State::Finished => "finished",
            State::Abandoned => "abandoned",
        }
    }

    fn parse(s: &str) -> UaResult<State> {
        Ok(match s {
            "seen" => State::Seen,
            "accepted" => State::Accepted,
            "finished" => State::Finished,
            "abandoned" => State::Abandoned,
            other => return Err(UaError::internal(format!("inbound delivery in unknown state {other:?}"))),
        })
    }
}

/// One delivery's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery<'a> {
    pub org_id: &'a str,
    pub source: &'a str,
    pub kind: &'a str,
    pub key: &'a str,
}

/// What a repeat of a delivery that was taken on but never finished means:
/// one `accepted` under a claim that is gone or past the in-flight bound, or
/// one `abandoned`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stale {
    /// Take it on again (idempotent effects).
    Redeliver,
    /// Treat it as a duplicate.
    Duplicate,
}

/// The rules [`record`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rules {
    /// How long a row is kept after it is recorded, in seconds.
    pub ttl_s: i64,
    /// How long an `accepted` row of this process counts as in flight.
    pub in_flight_s: i64,
    pub stale: Stale,
}

/// What [`record`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sight {
    /// First time: recorded as `seen`.
    First,
    /// A delivery taken on before and never finished, taken on again (only
    /// under [`Stale::Redeliver`]); recorded as `seen` again.
    Redelivered { was: State },
    /// Already known: nothing changed.
    Duplicate { state: State },
}

/// This process's claim on the rows it accepts: a row accepted under another
/// claim was accepted by a process that has since stopped (one hub process
/// writes the database).
pub fn claim() -> &'static str {
    static CLAIM: OnceLock<String> = OnceLock::new();
    CLAIM.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        format!("{}-{nanos}", std::process::id())
    })
}

fn check(d: &Delivery<'_>) -> UaResult<()> {
    let ok = |s: &str, max: usize| (1..=max).contains(&s.len());
    if !ok(d.org_id, 64) || !ok(d.source, 64) || !ok(d.kind, 64) || !ok(d.key, 256) {
        return Err(UaError::invalid("inbound delivery fields must be 1-64 (key 1-256) bytes"));
    }
    Ok(())
}

/// The row's state, claim and last update, if there is one.
fn current(tx: &WriteTx<'_>, d: &Delivery<'_>) -> UaResult<Option<(State, Option<String>, i64)>> {
    let row = tx
        .query_row(
            "SELECT state, claim, updated_at FROM inbound_deliveries \
             WHERE org_id = ?1 AND source = ?2 AND kind = ?3 AND delivery_key = ?4",
            params![d.org_id, d.source, d.kind, d.key],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, i64>(2)?)),
        )
        .optional()?;
    row.map(|(s, c, u)| Ok((State::parse(&s)?, c, u))).transpose()
}

/// Record a delivery at `now`: the first sight, a duplicate, or (under
/// [`Stale::Redeliver`]) a stale one taken on again. Atomic within `tx`.
/// `detail` is free text kept with the row (an event name, a related id).
pub fn record(
    tx: &WriteTx<'_>,
    d: Delivery<'_>,
    now: i64,
    rules: Rules,
    detail: Option<&str>,
) -> UaResult<Sight> {
    check(&d)?;
    let expires = now.saturating_add(rules.ttl_s.max(0));
    let inserted = tx.execute(
        "INSERT INTO inbound_deliveries \
         (org_id, source, kind, delivery_key, state, received_at, updated_at, expires_at, claim, detail) \
         VALUES (?1, ?2, ?3, ?4, 'seen', ?5, ?5, ?6, ?7, ?8) \
         ON CONFLICT (org_id, source, kind, delivery_key) DO NOTHING",
        params![d.org_id, d.source, d.kind, d.key, now, expires, claim(), detail],
    )?;
    if inserted == 1 {
        return Ok(Sight::First);
    }
    let Some((state, row_claim, updated_at)) = current(tx, &d)? else {
        return Err(UaError::internal("inbound delivery vanished inside its transaction"));
    };
    let live = row_claim.as_deref() == Some(claim()) && updated_at >= now.saturating_sub(rules.in_flight_s);
    let stale = match state {
        State::Seen | State::Finished => false,
        State::Accepted => !live,
        State::Abandoned => true,
    };
    if !stale || rules.stale == Stale::Duplicate {
        return Ok(Sight::Duplicate { state });
    }
    tx.execute(
        "UPDATE inbound_deliveries SET state = 'seen', updated_at = ?5, expires_at = ?6, claim = ?7, \
         detail = COALESCE(?8, detail) \
         WHERE org_id = ?1 AND source = ?2 AND kind = ?3 AND delivery_key = ?4",
        params![d.org_id, d.source, d.kind, d.key, now, expires, claim(), detail],
    )?;
    Ok(Sight::Redelivered { was: state })
}

/// Take a `seen` delivery on under this process's claim, with the identity
/// it runs as. `false` when the row is not `seen`.
pub fn accept(tx: &WriteTx<'_>, d: Delivery<'_>, now: i64, identity: Option<&str>) -> UaResult<bool> {
    check(&d)?;
    Ok(tx.execute(
        "UPDATE inbound_deliveries SET state = 'accepted', updated_at = ?5, claim = ?6, \
         identity = COALESCE(?7, identity) \
         WHERE org_id = ?1 AND source = ?2 AND kind = ?3 AND delivery_key = ?4 AND state = 'seen'",
        params![d.org_id, d.source, d.kind, d.key, now, claim(), identity],
    )? == 1)
}

/// Mark a `seen` or `accepted` delivery handled. `false` when it is in
/// neither state.
pub fn finish(tx: &WriteTx<'_>, d: Delivery<'_>, now: i64) -> UaResult<bool> {
    check(&d)?;
    Ok(tx.execute(
        "UPDATE inbound_deliveries SET state = 'finished', updated_at = ?5 \
         WHERE org_id = ?1 AND source = ?2 AND kind = ?3 AND delivery_key = ?4 \
         AND state IN ('seen', 'accepted')",
        params![d.org_id, d.source, d.kind, d.key, now],
    )? == 1)
}

/// Forget a delivery whose handling failed in a way worth retrying, so the
/// sender's next attempt is a first sight. `false` when there was no row.
pub fn release(tx: &WriteTx<'_>, d: Delivery<'_>) -> UaResult<bool> {
    check(&d)?;
    Ok(tx.execute(
        "DELETE FROM inbound_deliveries WHERE org_id = ?1 AND source = ?2 AND kind = ?3 AND delivery_key = ?4",
        params![d.org_id, d.source, d.kind, d.key],
    )? == 1)
}

/// What [`sweep`] applies to one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepRules {
    /// Keep at most this many rows per organization and kind (the newest by
    /// `received_at`); `accepted` rows are never removed this way.
    pub max_per_kind: Option<i64>,
    /// Mark `accepted` rows abandoned when their claim is not this
    /// process's, or they are older than this many seconds.
    pub abandon_after_s: Option<i64>,
}

/// One row the sweep marked abandoned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abandoned {
    pub org_id: String,
    pub kind: String,
    pub key: String,
    pub received_at: i64,
    pub identity: Option<String>,
}

/// What [`sweep`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Swept {
    pub expired: usize,
    pub capped: usize,
    pub abandoned: Vec<Abandoned>,
}

/// Housekeeping for `source` at `now`:
///
/// 1. `accepted` rows whose claim is gone or past `abandon_after_s` become
///    `abandoned` and are returned, so the caller can record them. They are
///    marked rather than released: the sweep cannot know whether their
///    effects happened, and releasing would let a non-idempotent delivery
///    run again unnoticed. A source with idempotent effects gets the
///    redelivery anyway through [`Stale::Redeliver`].
/// 2. Expired rows are deleted, except `accepted` ones (they wait for
///    step 1, however old).
/// 3. Rows past `max_per_kind` are deleted, oldest first, `accepted` ones
///    excepted.
pub fn sweep(tx: &WriteTx<'_>, source: &str, now: i64, rules: SweepRules) -> UaResult<Swept> {
    let mut out = Swept::default();
    if let Some(after) = rules.abandon_after_s {
        let rows: Vec<Abandoned> = {
            let mut stmt = tx.prepare(
                "SELECT org_id, kind, delivery_key, received_at, identity FROM inbound_deliveries \
                 WHERE source = ?1 AND state = 'accepted' AND (claim IS NOT ?2 OR updated_at < ?3) \
                 ORDER BY received_at, kind, delivery_key",
            )?;
            stmt.query_map(params![source, claim(), now.saturating_sub(after)], |r| {
                Ok(Abandoned {
                    org_id: r.get(0)?,
                    kind: r.get(1)?,
                    key: r.get(2)?,
                    received_at: r.get(3)?,
                    identity: r.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?
        };
        for a in &rows {
            tx.execute(
                "UPDATE inbound_deliveries SET state = 'abandoned', updated_at = ?5 \
                 WHERE org_id = ?1 AND source = ?2 AND kind = ?3 AND delivery_key = ?4",
                params![a.org_id, source, a.kind, a.key, now],
            )?;
        }
        out.abandoned = rows;
    }
    out.expired = tx.execute(
        "DELETE FROM inbound_deliveries WHERE source = ?1 AND expires_at <= ?2 AND state != 'accepted'",
        params![source, now],
    )?;
    if let Some(max) = rules.max_per_kind {
        out.capped = tx.execute(
            "DELETE FROM inbound_deliveries WHERE rowid IN ( \
               SELECT rowid FROM ( \
                 SELECT rowid, state, ROW_NUMBER() OVER ( \
                   PARTITION BY org_id, kind ORDER BY received_at DESC, rowid DESC) AS n \
                 FROM inbound_deliveries WHERE source = ?1) \
               WHERE n > ?2 AND state != 'accepted')",
            params![source, max.max(0)],
        )?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
