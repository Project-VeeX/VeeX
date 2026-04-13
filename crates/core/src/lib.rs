//! Core runtime abstractions shared by all protocol and integration crates.

pub mod dns;
pub mod error;
pub mod listen;
pub mod logging;
pub mod plane;
pub mod router;
pub mod service;
pub mod session;
pub mod shutdown;
pub mod sniff;
pub mod traits;
pub mod types;

pub use dns::{
    read_dns_tcp_message, write_dns_tcp_message, DnsExecutorHandle, DnsRequest, DnsResponse,
    DomainResolverHandle, ResolveContext, ResolvePurpose,
};
pub use error::{ErrorKind, ProxyError, Result};
pub use listen::{format_listen_addr, parse_listen_addr};
pub use logging::{sanitize_field, Logger};
pub use plane::{
    packet::dispatcher::{PacketDispatcher, PacketSink},
    packet::session::{
        PacketAssociationKey, PacketFrame, PacketMetadata, PacketSession, PacketSessionHandle,
        PacketWriter,
    },
    stream::dispatcher::{InboundSink, StreamDispatcher},
    stream::relay::{relay_bidirectional, RelayErrorWithStats, RelayStats},
};
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
    BoxFuture, Inbound, Outbound, OutboundConnector, ProxyOutbound, StreamInbound, StreamOutbound,
    TransparentInbound,
};
pub use types::{
    AsyncStream, BoxedAsyncStream, Destination, Host, Listen, Network, OutboundRegistry,
    RouteReason, SessionContext, SessionMeta, SessionRoute, SessionState,
};
