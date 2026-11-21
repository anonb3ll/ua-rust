//! The hub's boundary to the outside world (`docs/ingress.md`).
//!
//! This crate is where talking to other systems is meant to live, so each
//! guard is written once:
//!
//! - [`addr`]: the one classifier that says whether an IP address is public
//!   and, if not, why;
//! - [`Outbound`]: the one guarded HTTP client. Every call names a
//!   [`Policy`] (one per destination class) that fixes the schemes, hosts,
//!   ports and addresses it may reach, whether redirects are followed, the
//!   response body cap and the timeouts.
//!
//! Inbound delivery handling (signature checks and duplicate-delivery
//! tables) moves here in later slices. A ratchet test
//! (`tests/ingress_guard.rs`) counts the duplicates that are still outside
//! the crate; the counts may only go down.
//!
//! The crate depends on `ua-core` and third-party crates only.

pub mod addr;
pub mod outbound;
pub mod policy;

pub use outbound::{Body, Outbound, OutboundError, Request, Response};
pub use policy::{Addresses, Hosts, Policy, Schemes};
/// HTTP types used in the [`Outbound`] API, so callers need no `reqwest`
/// dependency of their own.
pub use reqwest::{Method, StatusCode, header};
pub use url::Url;
