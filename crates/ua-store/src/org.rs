//! Organization storage: the `orgs` table and its tenancy helpers, and the
//! persistence surface of the organization registry.
//!
//! The schema half is `organization.v1.store`: the `orgs` table, its seed, the
//! ledger's organization columns, and the helper that makes a table
//! tenant-scoped. See `docs/organization.md` (Schema, `organization.v1`). This
//! module adds no tenant column to any table by itself; each crate that owns
//! tenant tables declares its own part with [`tenant_part`].
//!
//! The registry half is [`OrgRead`] and [`OrgWrite`], the database surface
//! `ua-org` uses. The methods take and return plain values; `rusqlite` stays
//! inside this module. A write runs on the caller's [`WriteTx`] so the row and
//! its ledger event commit in one transaction.

use anyhow::{Context, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use ua_core::{DEFAULT_ORG, UaError, UaResult};

use crate::db::WriteTx;
use crate::ledger::{self, EventInput};
use crate::schema::Procedure;

/// `organization.v1.store`: the `orgs` table, the default organization (its
/// `created_at` bound from `ua_core::time::now()`), and the `event_log`
/// columns `org_id` and `hash_v`. Apply it after `ledger.v1`.
///
/// `event_log.hash_v` is 1 on every row this build writes: the existing
/// nine-field hash form. `org_id` is stored but not covered by that hash, so
/// until rows are written with `hash_v = 2` a row's `org_id` can be edited
/// (around the append-only triggers) without `verify()` noticing.
pub const STORE_PART: Procedure =
    Procedure { name: "organization.v1.store", version: 1, standalone: false, run: store, args: &[] };

/// The `orgs` table. Deliberately not `IF NOT EXISTS`: a database that
/// already holds an `orgs` table of any shape refuses the part instead of
/// silently keeping the other shape.
const ORGS_SQL: &str = "
CREATE TABLE orgs (
    id                        TEXT PRIMARY KEY,
    slug                      TEXT NOT NULL UNIQUE,
    display_name              TEXT NOT NULL,
    status                    TEXT NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active','suspended')),
    allowed_profiles          TEXT NOT NULL
        DEFAULT '[\"public\",\"remote-assistant\",\"research\",\"acp-session\",\"reviewer\",\"developer\",\"lead\"]'
        CHECK (json_valid(allowed_profiles) AND json_type(allowed_profiles) = 'array'),
    memory_default_visibility TEXT NOT NULL DEFAULT 'private'
                              CHECK (memory_default_visibility IN ('private','team','org')),
    self_organization         INTEGER NOT NULL DEFAULT 1 CHECK (self_organization IN (0,1)),
    proposal_daily_limit      INTEGER NOT NULL DEFAULT 10 CHECK (proposal_daily_limit > 0),
    memory_consolidator_label TEXT,
    allow_remote_embedder     INTEGER NOT NULL DEFAULT 0 CHECK (allow_remote_embedder IN (0,1)),
    created_at                TEXT NOT NULL
);
CREATE TRIGGER orgs_no_delete BEFORE DELETE ON orgs
BEGIN SELECT RAISE(ABORT, 'organizations are suspended, never deleted'); END;
";

/// Every profile, for the default organization (the table default is the
/// narrower set a new organization starts with).
const DEFAULT_ORG_PROFILES: &str = "[\"public\",\"remote-assistant\",\"remote-vault-curator\",\"research\",\
     \"acp-session\",\"operator\",\"reviewer\",\"developer\",\"lead\",\"coordinator\"]";

const SEED_SQL: &str = "INSERT INTO orgs (id, slug, display_name, status, allowed_profiles, \
     memory_default_visibility, created_at) VALUES (?1, ?1, 'Default organization', 'active', ?2, 'org', ?3)";

/// SQLite permits `ADD COLUMN ... NOT NULL` only with a constant default,
/// which backfills every existing row atomically.
const EVENT_LOG_SQL: &str = "
ALTER TABLE event_log ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE event_log ADD COLUMN hash_v INTEGER NOT NULL DEFAULT 1;
";

fn table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |_| Ok(true))
        .optional()
        .map(|o| o.unwrap_or(false))
}

/// Organization counts read directly from `orgs` (active and suspended alike).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgCounts {
    /// Total rows in `orgs` (including `'default'`, active or suspended).
    pub total: i64,
    /// Rows in `orgs` other than `'default'` (active or suspended).
    pub non_default: i64,
}

impl OrgCounts {
    /// Whether `orgs` holds any organization other than `'default'` (active or
    /// suspended). Unauthenticated (`enforce_auth = false`) mode is strictly a
    /// single-organization mode and must fail closed whenever this is true.
    pub fn has_non_default(self) -> bool {
        self.non_default > 0
    }
}

/// Count organizations stored in `orgs` (active and suspended alike).
///
/// Returns `Ok(None)` only when the `orgs` table does not exist yet (for
/// example, a pre-tenancy database inspected read-only by `ua doctor`).
pub fn org_counts(conn: &Connection) -> UaResult<Option<OrgCounts>> {
    if !table_exists(conn, "orgs")? {
        return Ok(None);
    }
    let (total, non_default): (i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(CASE WHEN id != ?1 THEN 1 ELSE 0 END), 0) FROM orgs",
        [DEFAULT_ORG],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Some(OrgCounts { total, non_default }))
}

fn sql_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn store(conn: &Connection, _: &'static [&'static str]) -> anyhow::Result<String> {
    if table_exists(conn, "orgs")? {
        bail!(
            "an `orgs` table already exists; this part creates it and will not adopt a table of another shape"
        );
    }
    if !table_exists(conn, "event_log")? {
        bail!("event_log does not exist; apply ledger.v1 first");
    }
    conn.execute_batch(ORGS_SQL).context("creating orgs")?;
    let created_at = ua_core::time::now();
    conn.execute(SEED_SQL, (DEFAULT_ORG, DEFAULT_ORG_PROFILES, &created_at))
        .context("seeding the default organization")?;
    conn.execute_batch(EVENT_LOG_SQL).context("adding the event_log organization columns")?;
    let seed = SEED_SQL
        .replacen("?1", &sql_literal(DEFAULT_ORG), 1)
        .replacen("?1", &sql_literal(DEFAULT_ORG), 1)
        .replacen("?2", &sql_literal(DEFAULT_ORG_PROFILES), 1)
        .replacen("?3", &sql_literal(&created_at), 1);
    Ok(format!("{}\n{seed};\n{}", ORGS_SQL.trim(), EVENT_LOG_SQL.trim()))
}

/// A tenant part for the tables of one table family, named
/// `organization.v1.<crate>.<family>` (`organization.v1.ingress` for a crate
/// that is one family). One part per family, not per crate: the checksum
/// covers the table list (below), so a released part can never take another
/// family's tables, and each family is converted in its own part.
///
/// For every listed table it adds `org_id TEXT NOT NULL DEFAULT 'default'`
/// (or, where a nullable `org_id` already exists, fills its `NULL`s with
/// `'default'`; making that column `NOT NULL` needs a table rebuild), then
/// creates the generated `<table>_org_exists` and `<table>_org_immutable`
/// triggers. It needs `organization.v1.store` applied first.
///
/// The part is a [`Procedure`] whose checksum covers the table list, so
/// adding a table to a released part is refused on databases that already
/// ran it: covering another table takes a new part, never an edit of a
/// released one.
pub const fn tenant_part(name: &'static str, tables: &'static [&'static str]) -> Procedure {
    Procedure { name, version: 1, standalone: false, run: tenant_columns, args: tables }
}

fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !s.as_bytes()[0].is_ascii_digit()
        && !s.starts_with("sqlite_")
}

/// The SQL that makes `table` tenant-scoped on this database.
fn tenant_sql(conn: &Connection, table: &str) -> anyhow::Result<Vec<String>> {
    if !is_identifier(table) {
        bail!("{table:?} is not a plain table name");
    }
    if !table_exists(conn, table)? {
        bail!("tenant table {table} does not exist");
    }
    let org_col: Option<bool> = conn
        .query_row("SELECT \"notnull\" FROM pragma_table_info(?1) WHERE name = 'org_id'", [table], |r| {
            r.get::<_, i64>(0).map(|n| n != 0)
        })
        .optional()?;
    let mut out = Vec::new();
    match org_col {
        None => out.push(format!("ALTER TABLE {table} ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';")),
        Some(_) => out.push(format!("UPDATE {table} SET org_id = 'default' WHERE org_id IS NULL;")),
    }
    out.push(format!(
        "CREATE TRIGGER {table}_org_exists BEFORE INSERT ON {table} \
         WHEN NOT EXISTS (SELECT 1 FROM orgs WHERE id = NEW.org_id) \
         BEGIN SELECT RAISE(ABORT, 'unknown organization'); END;"
    ));
    out.push(format!(
        "CREATE TRIGGER {table}_org_immutable BEFORE UPDATE OF org_id ON {table} \
         WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id \
         BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END;"
    ));
    Ok(out)
}

fn tenant_columns(conn: &Connection, tables: &'static [&'static str]) -> anyhow::Result<String> {
    if !table_exists(conn, "orgs")? {
        bail!("orgs does not exist; apply organization.v1.store first");
    }
    if tables.is_empty() {
        bail!("a tenant part must list at least one table");
    }
    let mut all = Vec::new();
    for table in tables {
        for stmt in tenant_sql(conn, table)? {
            conn.execute_batch(&stmt).with_context(|| format!("{table}: {stmt}"))?;
            all.push(stmt);
        }
    }
    Ok(all.join("\n"))
}

// ---------------------------------------------------------------------------
// Organization registry persistence (the registry slice)
// ---------------------------------------------------------------------------
/// One office row. `profiles` is the capability set, stored as a JSON array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficeRow {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub profiles: Vec<String>,
    pub created_at: String,
}

/// A role grant keyed by identity label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRow {
    pub org_id: String,
    pub label: String,
    pub role: String,
    pub added_by: String,
    pub added_at: String,
}

/// An agent seat. `office_slug` is the office's addressable id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatRow {
    pub org_id: String,
    pub label: String,
    pub office_id: String,
    pub office_slug: String,
    pub profile: String,
    pub agent_kind: String,
    pub created_at: String,
}

/// A seat to insert or move. The office slug is resolved by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSeat {
    pub org_id: String,
    pub label: String,
    pub office_id: String,
    pub profile: String,
    pub agent_kind: String,
    pub created_at: String,
}

/// Reads of the registry. Implemented for a borrowed connection and for a
/// write transaction.
pub trait OrgRead {
    fn allowed_profiles(&mut self, org_id: &str) -> UaResult<Vec<String>>;
    fn allow_remote_embedder(&mut self, org_id: &str) -> UaResult<bool>;
    fn offices(&mut self, org_id: &str) -> UaResult<Vec<OfficeRow>>;
    fn roles(&mut self, org_id: &str) -> UaResult<Vec<RoleRow>>;
    fn seats(&mut self, org_id: &str) -> UaResult<Vec<SeatRow>>;
    fn services(&mut self, org_id: &str) -> UaResult<Vec<String>>;
}

/// Writes of the registry, on the caller's transaction.
pub trait OrgWrite: OrgRead {
    fn insert_office(&mut self, row: &OfficeRow) -> UaResult<()>;
    fn insert_role(&mut self, row: &RoleRow) -> UaResult<()>;
    fn update_role(&mut self, row: &RoleRow) -> UaResult<()>;
    fn insert_seat(&mut self, row: &NewSeat) -> UaResult<()>;
    fn update_seat(&mut self, row: &NewSeat) -> UaResult<()>;
    fn insert_service(&mut self, org_id: &str, label: &str) -> UaResult<()>;
    fn set_allow_remote_embedder(&mut self, org_id: &str, allow: bool) -> UaResult<()>;
    fn record(&mut self, channel: &str, payload: Value, originator: &str) -> UaResult<()>;
}

/// A read of the sqlite store.
pub struct SqliteOrg<'a> {
    conn: &'a Connection,
}

impl<'a> SqliteOrg<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }
}

fn decode_profiles(raw: &str) -> UaResult<Vec<String>> {
    serde_json::from_str(raw)
        .map_err(|e| UaError::internal(format!("stored profiles are not a JSON array: {e}")))
}

fn allowed_profiles_sql(c: &Connection, org_id: &str) -> UaResult<Vec<String>> {
    let raw: Option<String> =
        c.query_row("SELECT allowed_profiles FROM orgs WHERE id = ?1", [org_id], |r| r.get(0)).optional()?;
    let Some(raw) = raw else {
        return Err(UaError::not_found(format!("unknown organization {org_id}")));
    };
    decode_profiles(&raw)
}

fn allow_remote_embedder_sql(c: &Connection, org_id: &str) -> UaResult<bool> {
    let raw: Option<i64> = c
        .query_row("SELECT allow_remote_embedder FROM orgs WHERE id = ?1", [org_id], |r| r.get(0))
        .optional()?;
    let Some(raw) = raw else {
        return Err(UaError::not_found(format!("unknown organization {org_id}")));
    };
    Ok(raw != 0)
}

fn offices_sql(c: &Connection, org_id: &str) -> UaResult<Vec<OfficeRow>> {
    let mut stmt = c.prepare(
        "SELECT id, org_id, slug, name, profiles, created_at FROM offices \
         WHERE org_id = ?1 ORDER BY created_at, id",
    )?;
    let rows = stmt.query_map([org_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, org_id, slug, name, profiles, created_at) = row?;
        out.push(OfficeRow { id, org_id, slug, name, profiles: decode_profiles(&profiles)?, created_at });
    }
    Ok(out)
}

fn roles_sql(c: &Connection, org_id: &str) -> UaResult<Vec<RoleRow>> {
    let mut stmt = c.prepare(
        "SELECT org_id, label, role, added_by, added_at FROM org_role_grants \
         WHERE org_id = ?1 ORDER BY label COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([org_id], |r| {
        Ok(RoleRow {
            org_id: r.get(0)?,
            label: r.get(1)?,
            role: r.get(2)?,
            added_by: r.get(3)?,
            added_at: r.get(4)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(UaError::from)
}

fn seats_sql(c: &Connection, org_id: &str) -> UaResult<Vec<SeatRow>> {
    let mut stmt = c.prepare(
        "SELECT s.org_id, s.label, s.office_id, o.slug, s.profile, s.agent_kind, s.created_at \
         FROM org_seats s \
         JOIN offices o ON o.org_id = s.org_id AND o.id = s.office_id \
         WHERE s.org_id = ?1 \
         ORDER BY o.created_at, o.id, s.created_at, s.label COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([org_id], |r| {
        Ok(SeatRow {
            org_id: r.get(0)?,
            label: r.get(1)?,
            office_id: r.get(2)?,
            office_slug: r.get(3)?,
            profile: r.get(4)?,
            agent_kind: r.get(5)?,
            created_at: r.get(6)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(UaError::from)
}

fn services_sql(c: &Connection, org_id: &str) -> UaResult<Vec<String>> {
    let mut stmt = c.prepare(
        "SELECT label FROM org_service_identities WHERE org_id = ?1 ORDER BY label COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([org_id], |r| r.get(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(UaError::from)
}

impl OrgRead for SqliteOrg<'_> {
    fn allowed_profiles(&mut self, org_id: &str) -> UaResult<Vec<String>> {
        allowed_profiles_sql(self.conn, org_id)
    }
    fn allow_remote_embedder(&mut self, org_id: &str) -> UaResult<bool> {
        allow_remote_embedder_sql(self.conn, org_id)
    }
    fn offices(&mut self, org_id: &str) -> UaResult<Vec<OfficeRow>> {
        offices_sql(self.conn, org_id)
    }
    fn roles(&mut self, org_id: &str) -> UaResult<Vec<RoleRow>> {
        roles_sql(self.conn, org_id)
    }
    fn seats(&mut self, org_id: &str) -> UaResult<Vec<SeatRow>> {
        seats_sql(self.conn, org_id)
    }
    fn services(&mut self, org_id: &str) -> UaResult<Vec<String>> {
        services_sql(self.conn, org_id)
    }
}

impl OrgRead for WriteTx<'_> {
    fn allowed_profiles(&mut self, org_id: &str) -> UaResult<Vec<String>> {
        allowed_profiles_sql(self, org_id)
    }
    fn allow_remote_embedder(&mut self, org_id: &str) -> UaResult<bool> {
        allow_remote_embedder_sql(self, org_id)
    }
    fn offices(&mut self, org_id: &str) -> UaResult<Vec<OfficeRow>> {
        offices_sql(self, org_id)
    }
    fn roles(&mut self, org_id: &str) -> UaResult<Vec<RoleRow>> {
        roles_sql(self, org_id)
    }
    fn seats(&mut self, org_id: &str) -> UaResult<Vec<SeatRow>> {
        seats_sql(self, org_id)
    }
    fn services(&mut self, org_id: &str) -> UaResult<Vec<String>> {
        services_sql(self, org_id)
    }
}

impl OrgWrite for WriteTx<'_> {
    fn insert_office(&mut self, row: &OfficeRow) -> UaResult<()> {
        let profiles = serde_json::to_string(&row.profiles)?;
        self.execute(
            "INSERT INTO offices (id, org_id, slug, name, profiles, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![row.id, row.org_id, row.slug, row.name, profiles, row.created_at],
        )?;
        Ok(())
    }

    fn insert_role(&mut self, row: &RoleRow) -> UaResult<()> {
        self.execute(
            "INSERT INTO org_role_grants (org_id, label, role, added_by, added_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![row.org_id, row.label, row.role, row.added_by, row.added_at],
        )?;
        Ok(())
    }

    fn update_role(&mut self, row: &RoleRow) -> UaResult<()> {
        let n = self.execute(
            "UPDATE org_role_grants SET role = ?1, added_by = ?2, added_at = ?3 \
             WHERE org_id = ?4 AND label = ?5 COLLATE NOCASE",
            params![row.role, row.added_by, row.added_at, row.org_id, row.label],
        )?;
        if n == 0 {
            return Err(UaError::not_found(format!("no role grant for {}", row.label)));
        }
        Ok(())
    }

    fn insert_seat(&mut self, row: &NewSeat) -> UaResult<()> {
        self.execute(
            "INSERT INTO org_seats (org_id, label, office_id, profile, agent_kind, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![row.org_id, row.label, row.office_id, row.profile, row.agent_kind, row.created_at],
        )?;
        Ok(())
    }

    fn update_seat(&mut self, row: &NewSeat) -> UaResult<()> {
        let n = self.execute(
            "UPDATE org_seats SET office_id = ?1, profile = ?2, agent_kind = ?3 \
             WHERE org_id = ?4 AND label = ?5 COLLATE NOCASE",
            params![row.office_id, row.profile, row.agent_kind, row.org_id, row.label],
        )?;
        if n == 0 {
            return Err(UaError::not_found(format!("no seat for {}", row.label)));
        }
        Ok(())
    }

    fn insert_service(&mut self, org_id: &str, label: &str) -> UaResult<()> {
        self.execute(
            "INSERT INTO org_service_identities (org_id, label) VALUES (?1, ?2)",
            params![org_id, label],
        )?;
        Ok(())
    }

    fn set_allow_remote_embedder(&mut self, org_id: &str, allow: bool) -> UaResult<()> {
        let n = self.execute(
            "UPDATE orgs SET allow_remote_embedder = ?1 WHERE id = ?2",
            params![i64::from(allow), org_id],
        )?;
        if n == 0 {
            return Err(UaError::not_found(format!("unknown organization {org_id}")));
        }
        Ok(())
    }

    fn record(&mut self, channel: &str, payload: Value, originator: &str) -> UaResult<()> {
        ledger::append(self, EventInput::new(DEFAULT_ORG, channel, payload).by(originator))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{self, EventInput};
    use crate::schema::{Part, SchemaPart, apply};
    use crate::{Db, schema};
    use serde_json::json;

    fn store_db() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(
            &mut conn,
            &[Part::from(ledger::SCHEMA), Part::from(ledger::META_SCHEMA), Part::from(STORE_PART)],
        )
        .unwrap();
        conn
    }

    #[test]
    fn the_store_part_seeds_one_default_organization() {
        let conn = store_db();
        let rows: Vec<(String, String, String, String, String)> = conn
            .prepare("SELECT id, slug, status, memory_default_visibility, created_at FROM orgs")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 1);
        let (id, slug, status, visibility, created_at) = &rows[0];
        assert_eq!(
            (id.as_str(), slug.as_str(), status.as_str(), visibility.as_str()),
            ("default", "default", "active", "org")
        );
        assert!(
            ua_core::time::parse_ts(created_at).is_some() && created_at.ends_with("+00:00"),
            "{created_at}"
        );
        let profiles: String = conn
            .query_row("SELECT allowed_profiles FROM orgs WHERE id = 'default'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(serde_json::from_str::<Vec<String>>(&profiles).unwrap().len(), 10);

        let err = conn.execute("DELETE FROM orgs WHERE id = 'default'", []).unwrap_err().to_string();
        assert!(err.contains("never deleted"), "{err}");

        // The audit record names the bound timestamp.
        let generated: String = conn
            .query_row(
                "SELECT generated_sql FROM schema_procedures WHERE name = 'organization.v1.store'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            generated.contains(created_at.as_str()) && generated.contains("CREATE TABLE orgs"),
            "{generated}"
        );
    }

    #[test]
    fn events_carry_the_default_organization_and_hash_form_1() {
        let db = Db::open_in_memory(&[
            Part::from(ledger::SCHEMA),
            Part::from(ledger::META_SCHEMA),
            Part::from(STORE_PART),
        ])
        .unwrap();
        // `append` names neither column; both take their defaults.
        db.write(|tx| {
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.event", json!({ "i": 1 })))
        })
        .unwrap();
        let (org, hash_v): (String, i64) = db
            .read(|c| {
                Ok(c.query_row("SELECT org_id, hash_v FROM event_log", [], |r| Ok((r.get(0)?, r.get(1)?)))?)
            })
            .unwrap();
        assert_eq!((org.as_str(), hash_v), (DEFAULT_ORG, 1));
        assert!(db.read(ledger::verify).unwrap().ok);
    }

    #[test]
    fn rows_already_in_the_ledger_are_backfilled() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, &[ledger::SCHEMA]).unwrap();
        conn.execute(
            "INSERT INTO event_log (ulid, channel, payload, created_at) \
             VALUES ('01J0000000000000000000000A', 'legacy.event', '{}', '2026-01-01T00:00:00+00:00')",
            [],
        )
        .unwrap();
        apply(&mut conn, &[Part::from(ledger::SCHEMA), Part::from(STORE_PART)]).unwrap();
        let (org, hash_v): (String, i64) = conn
            .query_row("SELECT org_id, hash_v FROM event_log", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!((org.as_str(), hash_v), ("default", 1));
    }

    #[test]
    fn an_existing_orgs_table_of_another_shape_refuses_the_part() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, &[ledger::SCHEMA]).unwrap();
        conn.execute_batch("CREATE TABLE orgs (id TEXT PRIMARY KEY, name TEXT);").unwrap();
        let err =
            apply(&mut conn, &[Part::from(ledger::SCHEMA), Part::from(STORE_PART)]).unwrap_err().to_string();
        assert!(err.contains("organization.v1.store") && err.contains("orgs"), "{err}");
        let recorded: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_parts WHERE name = 'organization.v1.store'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(recorded, 0);
    }

    const DEMO: SchemaPart = SchemaPart {
        name: "org_demo.v1",
        sql: "CREATE TABLE widgets (id INTEGER PRIMARY KEY);
              CREATE TABLE legacy (id INTEGER PRIMARY KEY, org_id TEXT);
              INSERT INTO widgets (id) VALUES (1);
              INSERT INTO legacy (id, org_id) VALUES (1, NULL);",
    };
    const DEMO_TENANT: Procedure = tenant_part("organization.v1.demo", &["widgets", "legacy"]);

    fn tenant_db() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(
            &mut conn,
            &[Part::from(ledger::SCHEMA), Part::from(STORE_PART), Part::from(DEMO), Part::from(DEMO_TENANT)],
        )
        .unwrap();
        conn
    }

    #[test]
    fn a_tenant_part_adds_or_backfills_org_id_and_generates_both_triggers() {
        let conn = tenant_db();
        let notnull: i64 = conn
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('widgets') WHERE name = 'org_id'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(notnull, 1);
        for t in ["widgets", "legacy"] {
            let org: String =
                conn.query_row(&format!("SELECT org_id FROM {t} WHERE id = 1"), [], |r| r.get(0)).unwrap();
            assert_eq!(org, "default", "{t}");
            for suffix in ["org_exists", "org_immutable"] {
                let n: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?1 AND tbl_name = ?2",
                        [format!("{t}_{suffix}"), t.to_string()],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(n, 1, "{t}_{suffix}");
            }
        }
        let generated: String = conn
            .query_row(
                "SELECT generated_sql FROM schema_procedures WHERE name = 'organization.v1.demo'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(generated.contains("ALTER TABLE widgets ADD COLUMN org_id"), "{generated}");
        assert!(
            generated.contains("UPDATE legacy SET org_id = 'default' WHERE org_id IS NULL"),
            "{generated}"
        );
    }

    /// A table added to a released tenant part, without a new name or
    /// version, must be refused on a database that already ran the part,
    /// not silently skipped (fresh databases would get the table, existing
    /// ones would not).
    #[test]
    fn a_tenant_part_whose_table_list_changed_is_refused() {
        let mut conn = tenant_db();
        conn.execute_batch("CREATE TABLE gadgets (id INTEGER PRIMARY KEY);").unwrap();
        const GROWN: Procedure = tenant_part("organization.v1.demo", &["widgets", "legacy", "gadgets"]);
        let err = apply(&mut conn, &[GROWN]).unwrap_err().to_string();
        assert!(
            err.contains("organization.v1.demo") && err.contains("changed after it was applied"),
            "{err}"
        );
        assert!(err.contains(r#"args ["widgets","legacy"]"#), "{err}");
        assert!(err.contains(r#"args ["widgets","legacy","gadgets"]"#), "{err}");
        let gadgets_org: i64 = conn
            .query_row("SELECT COUNT(*) FROM pragma_table_info('gadgets') WHERE name = 'org_id'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(gadgets_org, 0, "nothing ran");
        // The same list again is a no-op.
        assert!(apply(&mut conn, &[DEMO_TENANT]).unwrap().is_empty());
    }

    #[test]
    fn generated_triggers_refuse_an_unknown_organization_and_a_changed_org_id() {
        let conn = tenant_db();
        let err =
            conn.execute("INSERT INTO widgets (id, org_id) VALUES (2, 'nope')", []).unwrap_err().to_string();
        assert!(err.contains("unknown organization"), "{err}");
        conn.execute("INSERT INTO widgets (id) VALUES (3)", []).unwrap();
        for t in ["widgets", "legacy"] {
            let err = conn
                .execute(&format!("UPDATE {t} SET org_id = 'other' WHERE id = 1"), [])
                .unwrap_err()
                .to_string();
            assert!(err.contains("org_id cannot change"), "{t}: {err}");
        }
    }

    #[test]
    fn a_tenant_part_needs_the_store_part_and_existing_plain_tables() {
        let mut conn = Connection::open_in_memory().unwrap();
        let err = apply(&mut conn, &[Part::from(DEMO), Part::from(DEMO_TENANT)]).unwrap_err().to_string();
        assert!(err.contains("organization.v1.demo") && err.contains("organization.v1.store"), "{err}");

        const MISSING: Procedure = tenant_part("organization.v1.missing", &["no_such_table"]);
        const ODD: Procedure = tenant_part("organization.v1.odd", &["widgets; DROP TABLE orgs"]);
        for bad in [MISSING, ODD] {
            let mut conn = store_db();
            schema::apply(&mut conn, &[DEMO]).unwrap();
            let err = apply(&mut conn, &[bad]).unwrap_err().to_string();
            assert!(err.contains(bad.name), "{err}");
            assert_eq!(conn.query_row("SELECT COUNT(*) FROM orgs", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
        }
    }

    #[test]
    fn org_counts_reports_active_and_suspended_non_default_organizations() {
        let empty = Connection::open_in_memory().unwrap();
        assert_eq!(org_counts(&empty).unwrap(), None);

        let conn = store_db();
        assert_eq!(org_counts(&conn).unwrap(), Some(OrgCounts { total: 1, non_default: 0 }));
        assert!(!org_counts(&conn).unwrap().unwrap().has_non_default());

        conn.execute(
            "INSERT INTO orgs (id, slug, display_name, status, created_at) \
             VALUES ('org-b', 'org-b', 'Org B', 'active', '2026-01-01T00:00:00+00:00')",
            [],
        )
        .unwrap();
        let c = org_counts(&conn).unwrap().unwrap();
        assert_eq!(c, OrgCounts { total: 2, non_default: 1 });
        assert!(c.has_non_default());

        conn.execute(
            "INSERT INTO orgs (id, slug, display_name, status, created_at) \
             VALUES ('org-c', 'org-c', 'Org C', 'suspended', '2026-01-01T00:00:00+00:00')",
            [],
        )
        .unwrap();
        let c = org_counts(&conn).unwrap().unwrap();
        assert_eq!(c, OrgCounts { total: 3, non_default: 2 });
        assert!(c.has_non_default());
    }
}
