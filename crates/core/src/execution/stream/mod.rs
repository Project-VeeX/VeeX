//! Stream (TCP) execution plane.
//!
//! The stream side is organized around dispatcher orchestration, DNS hijack handling,
//! erased stream I/O, and relay runtime.

pub mod dispatcher;
pub mod dns;
pub mod io;
pub mod relay;

pub use dispatcher::StreamDispatcher;
