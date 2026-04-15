//! Core runtime abstractions shared by all protocol and integration crates.

pub mod dns;
pub mod error;
pub mod execution;
pub mod listen;
pub mod logging;
pub mod portal;
pub mod router;
pub mod session;
pub mod shutdown;
pub mod sniff;
pub mod types;

pub use dns::{
    read_dns_tcp_message, write_dns_tcp_message, DnsExecutorHandle, DnsRequest, DnsResponse,
    DomainResolverHandle, ResolveContext, ResolvePurpose,
};
pub use error::{ErrorKind, ProxyError, Result};
pub use execution::{
    relay_bidirectional, AsyncStream, BoxedAsyncStream, ExecutionOutbound, OutboundRegistry,
    OutboundRegistryBuilder, PacketAssociationKey, PacketDispatch, PacketDispatcher, PacketFrame,
    PacketMetadata, PacketSession, PacketSessionHandle, PacketWriter, RelayErrorWithStats,
    RelayStats, SessionContext, SessionMeta, SessionRoute, SessionState, StreamDispatch,
    StreamDispatcher,
};
pub use listen::{format_listen_addr, parse_listen_addr};
pub use logging::{sanitize_field, Logger};
pub use portal::{
    dialer::{Dial, DialConnect, DialContext, Dialer, PacketConnect, PacketDialer},
    listener::{
        Listener, ListenerAcceptHandler, ListenerFactory, PacketListener, PacketListenerFactory,
        PacketListenerReceive, PacketListenerReceiveHandler,
    },
    meta::{InboundMeta, OutboundMeta},
    traits::{
        BoxFuture, Inbound, Outbound, ProxyOutbound, StreamInbound, StreamOutbound,
        TransparentInbound,
    },
};
pub use router::{
    RouteAction, RouteDecision, RouteFinalAction, RouteInput, RouteReason, RouteRule, RouteTarget,
    RouteUpgradeAction, Router, SniffAction,
};
pub use session::{build_session_bootstrap, SessionBootstrap};
pub use shutdown::{shutdown_channel, ShutdownSignal, ShutdownTrigger};
pub use sniff::{sniff_stream, PrefixedStream, SniffOutcome, SniffedProtocol};
pub use types::{Destination, Host, Listen, Network};
