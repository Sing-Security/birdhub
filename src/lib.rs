//! birdhub — a relay whose two ends know each other by certificate.
//!
//! One core, two run modes, chosen by `[app] mode`:
//!
//! - **hub** terminates sessions and dials the targets the client's grants
//!   allow.
//! - **client** binds local addresses and tunnels each to one fixed
//!   destination through the hub.
//!
//! Identity comes from a Temper keypair on disk (`identity.rs`), vouched for
//! by a fleet CA (`ca.rs`): a node is its keys, a peer is whoever presents a
//! certificate over those keys that chains to the CA, and the network address
//! is only how the two reach each other.
//!
//! Enrollment is three commands away from nothing:
//!
//! ```text
//! birdhub ca init --key ca.key --pub ca.pub        # once, for the fleet
//! birdhub identity export --key identity.key --pub node.pub   # on the node
//! birdhub ca issue --ca ca.key --identity node.pub --days 365 --out node.cert
//! ```
//!
//! The node then needs `ca.pub` and `node.cert` (a client also wants the
//! hub's `hub.cert`); the CA key never leaves the machine that issued.
//!
//! The library half exists so a frontend can embed the core instead of
//! wrapping the binary: build a `Hub` or a node with an `EventLog`, run it on
//! a runtime of your own, and read the same state the log lines come from.
//! The `birdhub` binary is one such caller and the console (`birdhub-console`)
//! is another.

pub mod ca;
pub mod config;
pub mod control;
pub mod error;
pub mod events;
pub mod hub;
pub mod identity;
pub mod mux;
pub mod node;
pub mod registry;
pub mod relay;
pub mod target;
pub mod time;
pub mod transport;

#[cfg(test)]
mod testutil;

pub use error::{Error, Result};
