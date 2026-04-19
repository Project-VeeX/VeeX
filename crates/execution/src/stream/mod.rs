//! Stream (TCP) execution plane.
//!
//! The stream side is organized around dispatcher orchestration, DNS hijack handling,
//! carrier consumption, and relay runtime.

mod dispatcher;
mod dns;
mod relay;

pub use dispatcher::StreamDispatcher;
pub use relay::{RelayErrorWithStats, RelayStats, relay_bidirectional};
