//! Core runtime abstractions shared by all protocol and integration crates.

pub mod dispatcher;
pub mod error;
pub mod listen;
pub mod logging;
pub mod relay;
pub mod router;
pub mod shutdown;
pub mod sniff;
#[cfg(test)]
mod test_support;
pub mod traits;
pub mod types;

pub use dispatcher::SimpleDispatcher;
pub use error::{ErrorKind, ProxyError, Result};
pub use listen::{format_listen_addr, parse_listen_addr};
pub use logging::sanitize_field;
pub use relay::{relay_bidirectional, RelayErrorWithStats, RelayStats};
pub use router::{
    RouteAction, RouteDecision, RouteFinalAction, RouteInput, RouteRule, RouteTarget,
    RouteUpgradeAction, Router, SniffAction,
};
pub use shutdown::{shutdown_channel, ShutdownSignal, ShutdownTrigger};
pub use sniff::{sniff_stream, PrefixedStream, SniffOutcome, SniffedProtocol};
pub use traits::{BoxFuture, Dispatcher, Inbound, Outbound};
pub use types::{
    AsyncStream, BoxedAsyncStream, Destination, Host, Network, RouteReason, SessionContext,
    SessionMeta, SessionRoute, SessionState,
};
