//! Execution layer abstractions.
//!
//! ```text
//! execution/
//!   bridge.rs  — consume router RouteResult and hand off to execution dispatchers
//!   catalog.rs  — shared outbound catalog / wiring
//!   stream/  — TCP stream execution via StreamDispatcher
//!   packet/  — UDP packet execution via PacketDispatcher
//! ```

mod bridge;
mod catalog;
mod packet;
mod stream;
mod traits;

pub use bridge::{RoutedPacketDispatch, RoutedStreamDispatch};
pub use catalog::OutboundCatalog;
pub use packet::PacketDispatcher;
pub use stream::{RelayErrorWithStats, RelayStats, StreamDispatcher, relay_bidirectional};
pub use traits::{ExecutionFuture, ExecutionOutbound, PacketDispatch, StreamDispatch};
