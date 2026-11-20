//! Persistence for the organization registry.
//!
//! [`OrgRead`] and [`OrgWrite`] are the database surface `ua-org` uses. The
//! methods take and return plain values; `rusqlite` stays inside this module.
//! A write runs on the caller's [`WriteTx`] so the row and its ledger event
//! commit in one transaction.

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use ua_core::{UaError, UaResult};

use crate::db::WriteTx;
use crate::ledger::{self, EventInput};

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

    fn record(&mut self, channel: &str, payload: Value, originator: &str) -> UaResult<()> {
        ledger::append(self, EventInput::new(channel, payload).by(originator))?;
        Ok(())
    }
}
