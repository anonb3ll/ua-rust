//! Organization registry: offices, roles and seats.
//!
//! This crate is the organization domain for the registry slice. It depends
//! on `ua-core` and `ua-store` only, and it reaches SQLite through
//! [`ua_store::org::OrgRead`] and [`ua_store::org::OrgWrite`]. It does not
//! know about the tool registry.
//!
//! The tools (`org_registry_read`, `org_office_register`, `org_role_register`,
//! `org_seat_register`, `org_service_register`) are registered by `ua-tools`.
//! Adapters do not call this crate directly.
//!
//! An office is a named capability scope: a slug, a display name and the
//! profiles its seats may hold. A role is one of `org_owner`, `org_admin`,
//! `team_lead`, `member` and `auditor`, granted to an identity label. A seat
//! places an agent label in one office with one profile. Service identities
//! are catalog labels that send as themselves and hold no office and no role.
//! Nothing here grants a profile or an approval.
//!
//! Rows belong to the `'default'` organization. Tool arguments do not carry
//! an organization id. Team specs, team plans, topology, snapshots,
//! self-organization, blueprints and skill packages are later slices.

pub mod registry;
pub mod schema;

pub use registry::{
    CHANNEL, DEFAULT_ORG_ID, Finding, Health, ISSUE_ACTIVE_WITHOUT_OFFICE, ISSUE_MEMBER_NOT_IN_ROSTER,
    ISSUE_SERVICE_IN_OFFICE, ISSUE_SERVICE_NOT_IN_ROSTER, Office, Outcome, RegisterOffice, RegisterRole,
    RegisterSeat, RegisterService, Registry, RoleGrant, Seat, find_office, health, load, office_for_identity,
    offices_for_identity, register_office, register_role, register_seat, register_service,
};
pub use schema::{SCHEMA, schema_parts};
