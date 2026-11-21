//! Organizations.
//!
//! The organization is the partition key of tenant data (see
//! `docs/organization.md`). Until a second organization can be created, every
//! row and every ledger event belongs to the seeded default organization.

/// The id (and slug) of the organization every hub is seeded with. Hub
/// maintenance runs as this organization, and rows written before tenancy
/// belong to it.
pub const DEFAULT_ORG: &str = "default";
