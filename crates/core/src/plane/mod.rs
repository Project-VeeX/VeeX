//! Execution plane abstractions.
//!
//! ```text
//! plane/
//!   stream/  — TCP stream execution via StreamDispatcher
//!   packet/  — UDP packet execution via PacketDispatcher
//! ```

pub mod packet;
pub mod stream;
pub(crate) mod support;
pub mod traits;
pub mod types;

pub use crate::router::RouteReason;
pub use packet::dispatcher::PacketDispatcher;
pub use packet::io::{
    PacketAssociationKey, PacketFrame, PacketMetadata, PacketSession, PacketSessionHandle,
    PacketWriter,
};
pub use stream::dispatcher::StreamDispatcher;
pub use stream::io::{AsyncStream, BoxedAsyncStream};
pub use stream::relay::{relay_bidirectional, RelayErrorWithStats, RelayStats};
pub use traits::{PacketSink, PlaneOutbound, StreamSink};
pub use types::{OutboundRegistry, SessionContext, SessionMeta, SessionRoute, SessionState};
