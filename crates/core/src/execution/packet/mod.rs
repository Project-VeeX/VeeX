//! Packet (UDP) execution plane.
//!
//! The packet side is organized around dispatcher orchestration, DNS hijack handling,
//! carrier consumption, and association runtime.

mod association;
pub mod dispatcher;
pub mod dns;

pub use dispatcher::PacketDispatcher;
