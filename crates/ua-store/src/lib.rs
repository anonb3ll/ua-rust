//! SQLite storage for ua-rust.
//!
//! One database file in WAL mode. All writes go through a single writer
//! connection inside `BEGIN IMMEDIATE` transactions, so concurrent agent
//! sessions serialize cleanly instead of failing with `SQLITE_BUSY`. Reads use
//! a small pool of read-only connections and never block the writer.
//!
//! Each feature area contributes schema parts: static [`SchemaPart`]s and
//! [`Procedure`]s, both converted into [`Part`]. Parts are applied once, in
//! registration order, and recorded by name, so independent modules can add
//! tables without coordinating version numbers.

pub mod backup;
pub mod db;
pub mod ledger;
pub mod lock;
pub mod org;
pub mod schema;

pub use db::{Db, Fence, WriteTx};
pub use ledger::{Event, EventInput};
pub use lock::{HubLock, ServeLock};
pub use schema::{NewerSchema, Part, Procedure, SchemaPart};
