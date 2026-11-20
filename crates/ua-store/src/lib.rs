//! SQLite storage for ua-rust.
//!
//! One database file in WAL mode. All writes go through a single writer
//! connection inside `BEGIN IMMEDIATE` transactions, so concurrent agent
//! sessions serialize cleanly instead of failing with `SQLITE_BUSY`. Reads use
//! a small pool of read-only connections and never block the writer.
//!
//! Each feature area contributes [`SchemaPart`]s. Parts are applied once, in
//! registration order, and recorded by name, so independent modules can add
//! tables without coordinating version numbers.

pub mod db;
pub mod ledger;
pub mod org;
pub mod schema;

pub use db::{Db, WriteTx};
pub use ledger::{Event, EventInput};
pub use schema::SchemaPart;
