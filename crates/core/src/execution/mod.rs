//! Execution layer abstractions.
//!
//! ```text
//! execution/
//!   bridge.rs  — router + execution composition kept outside routing semantics
//!   registry.rs  — shared outbound registry / wiring
//!   stream/  — TCP stream execution via StreamDispatcher
//!   packet/  — UDP packet execution via PacketDispatcher
//! ```

mod bridge;
pub mod packet;
mod registry;
pub mod stream;
pub mod traits;

pub use bridge::{RoutedPacketDispatch, RoutedStreamDispatch};
pub use packet::dispatcher::PacketDispatcher;
pub use registry::{OutboundRegistry, OutboundRegistryBuilder};
pub use stream::dispatcher::StreamDispatcher;
pub use stream::relay::{relay_bidirectional, RelayErrorWithStats, RelayStats};
pub use traits::{ExecutionOutbound, PacketDispatch, StreamDispatch};
