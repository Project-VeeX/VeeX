//! Execution plane abstractions.
//!
//! ```text
//! plane/
//!   stream/  — TCP stream execution via StreamDispatcher
//!   packet/  — UDP packet execution via PacketDispatcher
//! ```

pub mod outbound;
pub mod packet;
pub mod registry;
pub mod session;
pub mod stream;

pub use crate::router::RouteReason;
pub use outbound::PlaneOutbound;
pub use packet::dispatcher::{PacketDispatcher, PacketSink};
pub use packet::io::{
    PacketAssociationKey, PacketFrame, PacketMetadata, PacketSession, PacketSessionHandle,
    PacketWriter,
};
pub use registry::OutboundRegistry;
pub use session::{SessionContext, SessionMeta, SessionRoute, SessionState};
pub use stream::dispatcher::{StreamDispatcher, StreamSink};
pub use stream::io::{AsyncStream, BoxedAsyncStream};
pub use stream::relay::{relay_bidirectional, RelayErrorWithStats, RelayStats};
