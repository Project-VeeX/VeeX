//! Stream (TCP) execution plane.
//!
//! The stream side is organized around dispatcher orchestration, DNS hijack handling,
//! carrier consumption, and relay runtime.

pub mod dispatcher;
pub mod dns;
pub mod relay;

pub use dispatcher::StreamDispatcher;
