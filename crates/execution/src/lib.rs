//! Execution layer abstractions.
//!
//! ```text
//! execution/
//!   bridge.rs  — consume router RouteResult and hand off to execution dispatchers
//!   registry.rs  — shared outbound registry / wiring
//!   stream/  — TCP stream execution via StreamDispatcher
//!   packet/  — UDP packet execution via PacketDispatcher
//! ```

mod bridge;
mod catalog;
pub mod packet;
pub mod stream;
pub mod traits;

pub use bridge::{RoutedPacketDispatch, RoutedStreamDispatch};
pub use catalog::OutboundCatalog;
pub use packet::dispatcher::PacketDispatcher;
pub use stream::dispatcher::StreamDispatcher;
pub use stream::relay::{relay_bidirectional, RelayErrorWithStats, RelayStats};
pub use traits::{ExecutionFuture, ExecutionOutbound, PacketDispatch, StreamDispatch};
