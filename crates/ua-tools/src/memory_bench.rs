//! Operator entry for `ua memory bench`.
//!
//! The harness scores an isolated database, not the hub. It is not a registry
//! tool: a tool call would be profile-gated and recorded against the hub
//! database. `ua-cli` cannot depend on `ua-memory` (only this crate may), so
//! the command enters here.

pub use ua_memory::bench::{Kind, Options, run, table};
