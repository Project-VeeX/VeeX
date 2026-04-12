//! Core runtime abstractions shared by all protocol and integration crates.

pub mod dispatcher;
pub mod dns;
pub mod error;
pub mod listen;
pub mod logging;
pub mod packet;
pub mod packet_dispatcher;
pub mod relay;
pub mod router;
pub mod service;
pub mod session;
pub mod shutdown;
pub mod sniff;
pub mod traits;
pub mod types;

pub use dispatcher::{Dispatcher, InboundSink, OutboundConnector, OutboundRegistry};
pub use dns::{
    read_dns_tcp_message, write_dns_tcp_message, DnsExecutorHandle, DnsRequest, DnsResponse,
};
pub use error::{ErrorKind, ProxyError, Result};
pub use listen::{format_listen_addr, parse_listen_addr};
pub use logging::{sanitize_field, Logger};
pub use packet::{
    PacketAssociationKey, PacketFrame, PacketMetadata, PacketSession, PacketSessionHandle,
    PacketWriter,
};
pub use packet_dispatcher::{PacketDispatcher, PacketSink};
pub use relay::{relay_bidirectional, RelayErrorWithStats, RelayStats};
pub use router::{
    RouteAction, RouteDecision, RouteFinalAction, RouteInput, RouteRule, RouteTarget,
    RouteUpgradeAction, Router, SniffAction,
};
pub use service::{
    Dial, DialConnect, DialContext, Dialer, InboundMeta, Listener, ListenerAcceptHandler,
    ListenerFactory, OutboundMeta, PacketConnect, PacketDialer,
};
pub use session::{build_session_bootstrap, SessionBootstrap};
pub use shutdown::{shutdown_channel, ShutdownSignal, ShutdownTrigger};
pub use sniff::{sniff_stream, PrefixedStream, SniffOutcome, SniffedProtocol};
pub use traits::{
    BoxFuture, Inbound, Outbound, ProxyOutbound, StreamInbound, StreamOutbound, TransparentInbound,
};
pub use types::{
    AsyncStream, BoxedAsyncStream, Destination, Host, Listen, Network, RouteReason, SessionContext,
    SessionMeta, SessionRoute, SessionState,
};
