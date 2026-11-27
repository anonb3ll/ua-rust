//! Organizations for ua-rust (`docs/organization.md`).
//!
//! Two slices live here: [`authz`], the one module authority checks go
//! through, and [`registry`], the organization registry of offices, roles and
//! seats. Users, memberships, teams and the rest of the design land here with
//! `organization.v2` and later.
//!
//! The registry reaches SQLite through [`ua_store::org::OrgRead`] and
//! [`ua_store::org::OrgWrite`]; it does not know about the tool registry. Its
//! tools (`org_registry_read`, `org_office_register`, `org_role_register`,
//! `org_seat_register`, `org_service_register`) are registered by `ua-tools`,
//! and adapters do not call this crate directly.
//!
//! An office is a named capability scope: a slug, a display name and the
//! profiles its seats may hold. A role is one of `org_owner`, `org_admin`,
//! `team_lead`, `member` and `auditor`, granted to an identity label. A seat
//! places an agent label in one office with one profile. Service identities
//! are catalog labels that send as themselves and hold no office and no role.
//! Nothing here grants a profile or an approval.
//!
//! Registry rows belong to the caller's organization: the tools pass
//! `ctx.caller.org_id` and refuse a caller whose organization differs from the
//! row's (`ua_org::authz::require_same_org`). Tool arguments do not carry an
//! organization id. Team specs, team plans, topology, snapshots,
//! self-organization, blueprints and skill packages are later slices.

pub mod authz;
pub mod registry;
pub mod schema;

pub use registry::{
    CHANNEL, DEFAULT_ORG_ID, Finding, Health, ISSUE_ACTIVE_WITHOUT_OFFICE, ISSUE_MEMBER_NOT_IN_ROSTER,
    ISSUE_SERVICE_IN_OFFICE, ISSUE_SERVICE_NOT_IN_ROSTER, NEUTRAL_ORIGINATOR, Office, OrgSettings, Outcome,
    RegisterOffice, RegisterRole, RegisterSeat, RegisterService, Registry, RoleGrant, SETTINGS_CHANNEL, Seat,
    UpdateOrgSettings, find_office, health, load, office_for_identity, offices_for_identity, register_office,
    register_role, register_seat, register_service, update_settings,
};
pub use schema::{SCHEMA, schema_parts};
