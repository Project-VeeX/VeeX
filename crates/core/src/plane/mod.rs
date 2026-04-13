//! Execution plane abstractions.
//!
//! ```text
//! plane/
//!   stream/  — TCP stream execution via StreamDispatcher
//!   packet/  — UDP packet execution via PacketDispatcher
//! ```

pub mod packet;
pub mod stream;

pub use packet::dispatcher::{PacketDispatcher, PacketSink};
pub use packet::session::{
    PacketAssociationKey, PacketFrame, PacketMetadata, PacketSession, PacketSessionHandle,
    PacketWriter,
};
pub use stream::dispatcher::{InboundSink, StreamDispatcher};
pub use stream::relay::{relay_bidirectional, RelayErrorWithStats, RelayStats};
