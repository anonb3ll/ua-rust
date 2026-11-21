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
//! - `accepted`: taken on under a [`Claim`] (this process's prefix and a
//!   number of its own). A repeat while the claim is live is a duplicate.
//! - `finished`: handled. A repeat is a duplicate until the row expires.
//! - `abandoned`: was `accepted` under a claim that is gone (the process
//!   stopped) or older than the in-flight bound; the outcome is unknown.
//!
//! Settling ([`finish`], [`release`]) acts only on a row that still carries
//! the caller's claim, so a slow handler cannot undo the record of a newer
//! owner that took the delivery over; it reports [`Settle::NotMine`]
//! instead.
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
use std::sync::atomic::{AtomicU64, Ordering};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sight {
    /// First time: recorded as `seen` under `claim`.
    First { claim: Claim },
    /// A delivery taken on before and never finished, taken on again (only
    /// under [`Stale::Redeliver`]); recorded as `seen` again under a new
    /// `claim`, so the earlier holder can no longer settle it.
    Redelivered { was: State, claim: Claim },
    /// Already known: nothing changed.
    Duplicate { state: State },
}

impl Sight {
    /// The claim to accept and settle with, unless this is a duplicate.
    pub fn claim(&self) -> Option<&Claim> {
        match self {
            Sight::First { claim } | Sight::Redelivered { claim, .. } => Some(claim),
            Sight::Duplicate { .. } => None,
        }
    }
}

/// One taking-on of a delivery: this process's prefix and a number unique
/// within the process. Every [`record`] that takes a delivery on hands out
/// a new one, so a takeover inside the same process is still a different
/// claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim(String);

impl Claim {
    fn next() -> Claim {
        static N: AtomicU64 = AtomicU64::new(0);
        Claim(format!("{}{}", process_prefix(), N.fetch_add(1, Ordering::Relaxed)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A claim spelled out, for tests that stand in for another holder.
    #[doc(hidden)]
    pub fn from_raw(raw: impl Into<String>) -> Claim {
        Claim(raw.into())
    }
}

/// How [`finish`] or [`release`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settle {
    Settled,
    /// The row no longer carries the caller's claim in a state it may
    /// settle (`state` is what it is now; `None` when there is no row), so
    /// nothing changed.
    NotMine {
        state: Option<State>,
    },
}

/// The prefix of every claim this process hands out: its id and start time,
/// then `:`. A claim without this prefix belongs to a process that has
/// stopped (one hub process writes the database).
pub fn process_prefix() -> &'static str {
    static PREFIX: OnceLock<String> = OnceLock::new();
    PREFIX.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        format!("{}-{nanos}:", std::process::id())
    })
}

fn ours(claim: Option<&str>) -> bool {
    claim.is_some_and(|c| c.starts_with(process_prefix()))
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
    let claim = Claim::next();
    let inserted = tx.execute(
        "INSERT INTO inbound_deliveries \
         (org_id, source, kind, delivery_key, state, received_at, updated_at, expires_at, claim, detail) \
         VALUES (?1, ?2, ?3, ?4, 'seen', ?5, ?5, ?6, ?7, ?8) \
         ON CONFLICT (org_id, source, kind, delivery_key) DO NOTHING",
        params![d.org_id, d.source, d.kind, d.key, now, expires, claim.as_str(), detail],
    )?;
    if inserted == 1 {
        return Ok(Sight::First { claim });
    }
    let Some((state, row_claim, updated_at)) = current(tx, &d)? else {
        return Err(UaError::internal("inbound delivery vanished inside its transaction"));
    };
    let live = ours(row_claim.as_deref()) && updated_at >= now.saturating_sub(rules.in_flight_s);
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
        params![d.org_id, d.source, d.kind, d.key, now, expires, claim.as_str(), detail],
    )?;
    Ok(Sight::Redelivered { was: state, claim })
}

/// Take a `seen` delivery on under `claim` (from [`record`]), with the
/// identity it runs as. `false` when the row is not `seen` under that claim.
pub fn accept(
    tx: &WriteTx<'_>,
    d: Delivery<'_>,
    claim: &Claim,
    now: i64,
    identity: Option<&str>,
) -> UaResult<bool> {
    check(&d)?;
    Ok(tx.execute(
        "UPDATE inbound_deliveries SET state = 'accepted', updated_at = ?5, identity = COALESCE(?7, identity) \
         WHERE org_id = ?1 AND source = ?2 AND kind = ?3 AND delivery_key = ?4 AND state = 'seen' \
         AND claim = ?6",
        params![d.org_id, d.source, d.kind, d.key, now, claim.as_str(), identity],
    )? == 1)
}

fn settled_or_not_mine(tx: &WriteTx<'_>, d: &Delivery<'_>, changed: usize) -> UaResult<Settle> {
    if changed == 1 {
        return Ok(Settle::Settled);
    }
    Ok(Settle::NotMine { state: current(tx, d)?.map(|(s, _, _)| s) })
}

/// Mark a delivery handled: only a row `accepted` (or `abandoned` by the
/// sweep) under `claim`. An abandoned row with the caller's claim is still
/// the caller's: nobody has taken it over (a takeover changes the claim),
/// and the caller's effects are done, so marking it `finished` keeps a later
/// copy from running them again. Anything else is [`Settle::NotMine`].
pub fn finish(tx: &WriteTx<'_>, d: Delivery<'_>, claim: &Claim, now: i64) -> UaResult<Settle> {
    check(&d)?;
    let changed = tx.execute(
        "UPDATE inbound_deliveries SET state = 'finished', updated_at = ?5 \
         WHERE org_id = ?1 AND source = ?2 AND kind = ?3 AND delivery_key = ?4 \
         AND state IN ('accepted', 'abandoned') AND claim = ?6",
        params![d.org_id, d.source, d.kind, d.key, now, claim.as_str()],
    )?;
    settled_or_not_mine(tx, &d, changed)
}

/// Forget a delivery whose handling failed in a way worth retrying, so the
/// sender's next attempt is a first sight: only a row `accepted` under
/// `claim`. A row taken over, finished, abandoned or gone is left as it is
/// ([`Settle::NotMine`]): deleting it could undo a newer owner's record, or
/// the sweep's report that the outcome is unknown.
pub fn release(tx: &WriteTx<'_>, d: Delivery<'_>, claim: &Claim) -> UaResult<Settle> {
    check(&d)?;
    let changed = tx.execute(
        "DELETE FROM inbound_deliveries WHERE org_id = ?1 AND source = ?2 AND kind = ?3 AND delivery_key = ?4 \
         AND state = 'accepted' AND claim = ?5",
        params![d.org_id, d.source, d.kind, d.key, claim.as_str()],
    )?;
    settled_or_not_mine(tx, &d, changed)
}

/// What [`sweep`] applies to one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepRules {
    /// Keep at most this many rows per organization and kind (the newest by
    /// `received_at`); `accepted` rows are never removed this way.
    pub max_per_kind: Option<i64>,
    /// Mark `accepted` rows abandoned when their claim is not one of this
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

/// Housekeeping for `source` in one organization at `now` (rows of other
/// organizations are untouched, so a caller ledgers what it abandoned under
/// the organization it swept):
///
/// 1. `accepted` rows whose claim is gone or past `abandon_after_s` become
///    `abandoned` and are returned, so the caller can record them. They are
///    marked rather than released: the sweep cannot know whether their
///    effects happened, and releasing would let a non-idempotent delivery
///    run again unnoticed. A source with idempotent effects gets the
///    redelivery anyway through [`Stale::Redeliver`].
/// 2. Expired rows (`expires_at` before `now`; a row at its expiry second
///    is kept) are deleted, except `accepted` ones (they wait for step 1,
///    however old).
/// 3. Rows past `max_per_kind` are deleted, oldest first, `accepted` ones
///    excepted.
pub fn sweep(tx: &WriteTx<'_>, org_id: &str, source: &str, now: i64, rules: SweepRules) -> UaResult<Swept> {
    let mut out = Swept::default();
    if let Some(after) = rules.abandon_after_s {
        out.abandoned = abandon(tx, org_id, source, now, Some(now.saturating_sub(after)))?;
    }
    out.expired = tx.execute(
        "DELETE FROM inbound_deliveries WHERE org_id = ?3 AND source = ?1 AND expires_at < ?2 \
         AND state != 'accepted'",
        params![source, now, org_id],
    )?;
    if let Some(max) = rules.max_per_kind {
        out.capped = tx.execute(
            "DELETE FROM inbound_deliveries WHERE rowid IN ( \
               SELECT rowid FROM ( \
                 SELECT rowid, state, ROW_NUMBER() OVER ( \
                   PARTITION BY kind ORDER BY received_at DESC, rowid DESC) AS n \
                 FROM inbound_deliveries WHERE org_id = ?3 AND source = ?1) \
               WHERE n > ?2 AND state != 'accepted')",
            params![source, max.max(0), org_id],
        )?;
    }
    Ok(out)
}

/// Mark `accepted` rows of `source` in `org_id` abandoned and return them:
/// those whose claim is not this process's, or (with `older_than`) whose
/// `updated_at` is before it; with `older_than` `None`, every one.
fn abandon(
    tx: &WriteTx<'_>,
    org_id: &str,
    source: &str,
    now: i64,
    older_than: Option<i64>,
) -> UaResult<Vec<Abandoned>> {
    let rows: Vec<Abandoned> = {
        let mut stmt = tx.prepare(
            "SELECT org_id, kind, delivery_key, received_at, identity FROM inbound_deliveries \
             WHERE org_id = ?4 AND source = ?1 AND state = 'accepted' \
             AND (?3 IS NULL OR claim IS NULL OR substr(claim, 1, length(?2)) != ?2 OR updated_at < ?3) \
             ORDER BY received_at, kind, delivery_key",
        )?;
        stmt.query_map(params![source, process_prefix(), older_than, org_id], |r| {
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
    Ok(rows)
}

/// Mark every `accepted` row of `source` in `org_id` abandoned, whatever
/// its claim or age, and return them. For a sweep that runs before any
/// handler of this process has taken a delivery on (a hub's startup), when
/// every `accepted` row is one whose handler is gone.
pub fn abandon_all_accepted(
    tx: &WriteTx<'_>,
    org_id: &str,
    source: &str,
    now: i64,
) -> UaResult<Vec<Abandoned>> {
    abandon(tx, org_id, source, now, None)
}

/// The claim a delivery is held under, if it has a row with one. For a
/// source that never takes a delivery over ([`Stale::Duplicate`]): its rows
/// keep the claim they were accepted under, so the handler that accepted a
/// row can settle it with the claim the row carries.
pub fn claim_of(tx: &WriteTx<'_>, d: Delivery<'_>) -> UaResult<Option<Claim>> {
    check(&d)?;
    Ok(current(tx, &d)?.and_then(|(_, c, _)| c).map(Claim))
}

#[cfg(test)]
mod tests;
