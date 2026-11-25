//! Storage schema of the organization registry.
//!
//! Released parts are checksum-locked by `ua-store` (SHA-256 of `sql`): never
//! edit one; add a new versioned part instead.
//!
//! This part is the registry slice. It creates the `orgs` row the design's
//! office table references, and the office, role, seat and service tables.
//! It does not add `org_id` to the existing tenant tables, and it is not
//! `organization.v1` or `organization.v3`: those parts land with the tenancy
//! and team slices. The `CREATE TABLE IF NOT EXISTS` statements match the
//! design's `orgs` and `offices` columns, so a later part that creates the
//! same tables leaves them in place.

use ua_store::SchemaPart;

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "organization.registry.v1",
    sql: "
CREATE TABLE IF NOT EXISTS orgs (
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
CREATE TRIGGER IF NOT EXISTS orgs_no_delete BEFORE DELETE ON orgs
BEGIN SELECT RAISE(ABORT, 'organizations are suspended, never deleted'); END;

INSERT OR IGNORE INTO orgs (id, slug, display_name, status, allowed_profiles,
                            memory_default_visibility, created_at)
    VALUES ('default', 'default', 'Default organization', 'active',
            '[\"public\",\"remote-assistant\",\"remote-vault-curator\",\"research\",\"acp-session\",\"operator\",\"reviewer\",\"developer\",\"lead\",\"coordinator\"]',
            'org', '2026-01-01T00:00:00+00:00');

CREATE TABLE IF NOT EXISTS offices (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id),
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    profiles   TEXT NOT NULL CHECK (json_valid(profiles) AND json_type(profiles) = 'array'),
    created_at TEXT NOT NULL,
    UNIQUE (org_id, slug),
    UNIQUE (org_id, id)
);

CREATE TABLE IF NOT EXISTS org_role_grants (
    org_id   TEXT NOT NULL REFERENCES orgs(id),
    label    TEXT NOT NULL COLLATE NOCASE,
    role     TEXT NOT NULL
             CHECK (role IN ('org_owner','org_admin','team_lead','member','auditor')),
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY (org_id, label)
);

CREATE TABLE IF NOT EXISTS org_seats (
    org_id     TEXT NOT NULL,
    label      TEXT NOT NULL COLLATE NOCASE,
    office_id  TEXT NOT NULL,
    profile    TEXT NOT NULL,
    agent_kind TEXT NOT NULL CHECK (agent_kind IN ('local','cloud')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (org_id, label),
    FOREIGN KEY (org_id, office_id) REFERENCES offices(org_id, id)
);

CREATE TABLE IF NOT EXISTS org_service_identities (
    org_id TEXT NOT NULL REFERENCES orgs(id),
    label  TEXT NOT NULL COLLATE NOCASE,
    PRIMARY KEY (org_id, label)
);
",
};

pub fn schema_parts() -> Vec<SchemaPart> {
    vec![SCHEMA]
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn the_registry_part_keeps_its_checksum() {
        let sum = hex::encode(Sha256::digest(SCHEMA.sql.as_bytes()));
        assert_eq!(
            (SCHEMA.name, sum.as_str()),
            ("organization.registry.v1", "407e631c88b4e9c632fdffaa883fe1ac93d70744ac78134584e70a2dd9a7ab62"),
            "released schema part checksum"
        );
    }
}
