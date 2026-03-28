//! Core runtime abstractions shared by all protocol and integration crates.

pub mod dispatcher;
pub mod error;
pub mod outbound_direct;
pub mod relay;
pub mod router;
pub mod traits;
pub mod types;

pub use dispatcher::SimpleDispatcher;
pub use error::{ProxyError, Result};
pub use outbound_direct::DirectOutbound;
pub use relay::{relay_bidirectional, RelayStats};
pub use router::{RouteDecision, RouteReason, Router};
pub use traits::{BoxFuture, Dispatcher, Inbound, Outbound};
pub use types::{
    AsyncStream, BoxedAsyncStream, Destination, Host, Network, SessionContext, SessionMeta,
};
