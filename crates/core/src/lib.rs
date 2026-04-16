//! Core runtime abstractions shared by all protocol and integration crates.

pub mod dns;
pub mod error;
pub mod execution;
pub mod io;
pub mod listen;
pub mod logging;
pub mod portal;
pub mod routing;
pub mod session;
pub mod shutdown;
pub mod types;

pub use error::{ErrorKind, ProxyError, Result};
pub use shutdown::{shutdown_channel, ShutdownSignal, ShutdownTrigger};
