//! Execution layer abstractions.
//!
//! ```text
//! execution/
//!   registry.rs  — shared outbound registry / wiring
//!   stream/  — TCP stream execution via StreamDispatcher
//!   packet/  — UDP packet execution via PacketDispatcher
//! ```

pub mod packet;
mod registry;
pub mod stream;
pub mod traits;

pub use crate::routing::RouteReason;
pub use crate::session::{SessionContext, SessionMeta, SessionRoute, SessionState};
pub use packet::dispatcher::PacketDispatcher;
pub use packet::io::{
    PacketAssociationKey, PacketFrame, PacketMetadata, PacketSession, PacketSessionHandle,
    PacketWriter,
};
pub use registry::{OutboundRegistry, OutboundRegistryBuilder};
pub use stream::dispatcher::StreamDispatcher;
pub use stream::io::{AsyncStream, BoxedAsyncStream};
pub use stream::relay::{relay_bidirectional, RelayErrorWithStats, RelayStats};
pub use traits::{ExecutionOutbound, PacketDispatch, StreamDispatch};
