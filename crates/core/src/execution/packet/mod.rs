//! Packet (UDP) execution plane.
//!
//! The packet side is organized around dispatcher orchestration, DNS hijack handling,
//! packet I/O handles, and association runtime.

mod association;
pub mod dispatcher;
pub mod dns;
pub mod io;

pub use dispatcher::PacketDispatcher;
