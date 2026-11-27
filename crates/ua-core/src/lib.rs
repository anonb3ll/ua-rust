//! Core types shared by every ua-rust crate.
//!
//! Nothing here touches the database or the network. The crate holds the
//! configuration model, caller identity, session profiles, the error type every
//! tool returns, and the path and command resolvers that keep tools inside
//! their sandbox.

pub mod canonical;
pub mod config;
pub mod error;
pub mod identity;
pub mod org;
pub mod profiles;
pub mod safety;
pub mod time;

pub use config::{Config, MemoryConfig, SlackIdentity};
pub use error::{UaError, UaResult};
pub use identity::{ActorKind, Caller};
pub use org::DEFAULT_ORG;
pub use profiles::Profile;
