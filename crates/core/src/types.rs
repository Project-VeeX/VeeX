use std::{
    fmt,
    net::{AddrParseError, IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use tokio::io::{AsyncRead, AsyncWrite};

/// A stream that supports both async read and async write operations.
/// All implementations must be Send-safe for use across task boundaries.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A type-erased boxed async stream.
pub type BoxedAsyncStream = Box<dyn AsyncStream>;

/// Network protocol type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Network {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// The target of a connection — either an IP address or a domain name.
///
/// This distinction is important because domain names require resolution
/// before a TCP connection can be established, while IP addresses can
/// be connected directly.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Host {
    /// A numeric IP address (IPv4 or IPv6).
    Ip(IpAddr),
    /// A domain name requiring DNS resolution.
    Domain(String),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Domain(domain) => f.write_str(domain),
        }
    }
}

impl Host {
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Self::Domain(domain) => Some(domain.as_str()),
            Self::Ip(_) => None,
        }
    }
}

/// A destination endpoint for a connection, combining a host and port.
///
/// This is the primary key used to route and connect sessions.
/// Display format is `"host:port"` for IPv4/domains and `"[ipv6]:port"` for IPv6.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Destination {
    /// The target host — either an IP address or domain name.
    pub host: Host,
    /// The TCP port number.
    pub port: u16,
}

impl Destination {
    pub fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }

    pub fn from_ip(ip: IpAddr, port: u16) -> Self {
        Self::new(Host::Ip(ip), port)
    }

    pub fn from_domain(domain: impl Into<String>, port: u16) -> Self {
        Self::new(Host::Domain(domain.into()), port)
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            _ => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

/// Common listen fields shared by listener-backed components.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Listen {
    listen: String,
    listen_port: u16,
}

impl Listen {
    pub fn new(listen: impl Into<String>, listen_port: u16) -> Self {
        Self {
            listen: listen.into(),
            listen_port,
        }
    }

    pub fn listen(&self) -> &str {
        &self.listen
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub fn format_addr(&self) -> String {
        crate::listen::format_listen_addr(&self.listen, self.listen_port)
    }

    pub fn parse_addr(&self) -> Result<SocketAddr, AddrParseError> {
        crate::listen::parse_listen_addr(&self.listen, self.listen_port)
    }
}

/// The reason a particular route decision was made.
///
/// This is used for observability and logging to understand why
/// a session was routed to a specific outbound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteReason {
    /// Routed by the user-defined route.rules chain.
    Rule,
    /// Routed by the default final action after no rule produced a final action.
    Final,
}

impl RouteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Final => "final",
        }
    }
}

/// Immutable metadata for a session.
///
/// This is wrapped in `Arc` within `SessionContext` because the same
/// metadata may need to be accessed from multiple tasks during the
/// session lifecycle while ensuring consistency.
#[derive(Clone, Debug)]
pub struct SessionMeta {
    /// Unique session identifier, assigned at session creation.
    pub id: u64,
    /// Network protocol (currently always TCP).
    pub network: Network,
    /// Tag of the inbound that accepted this session.
    pub inbound_tag: String,
    /// Client peer's socket address.
    pub peer: SocketAddr,
    /// Destination the client wants to reach.
    pub destination: Destination,
    /// Session start time, used for duration calculations.
    pub start: Instant,
}

/// Routing decision for a session.
///
/// Tracks which outbound was selected and why. Starts empty and is
/// populated by the router before dispatch.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionRoute {
    /// Tag of the selected outbound, if routing has occurred.
    pub selected_outbound: Option<String>,
    /// Reason for the route decision, if routing has occurred.
    pub reason: Option<RouteReason>,
}

impl SessionRoute {
    pub fn selected(selected_outbound: impl Into<String>, reason: RouteReason) -> Self {
        Self {
            selected_outbound: Some(selected_outbound.into()),
            reason: Some(reason),
        }
    }
}

/// Mutable session state.
///
/// Contains buffered payload data accumulated before routing decision is made.
/// This allows the relay to handle pipelined or pre-loaded request data.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionState {
    /// Payload data received from the client before the outbound was selected.
    pub buffered_payload: Vec<u8>,
}

/// Complete session context, combining immutable metadata with mutable routing and state.
///
/// `meta` is wrapped in `Arc` to allow sharing across tasks while maintaining
/// identity. `route` and `state` are owned directly and updated during the session.
#[derive(Clone, Debug)]
pub struct SessionContext {
    /// Immutable session metadata, shared via Arc for multi-task access.
    pub meta: Arc<SessionMeta>,
    /// Routing decision for this session.
    pub route: SessionRoute,
    /// Mutable session state, including buffered payload.
    pub state: SessionState,
}

impl SessionContext {
    pub fn new(meta: SessionMeta, buffered_payload: Vec<u8>) -> Self {
        Self {
            meta: Arc::new(meta),
            route: SessionRoute::default(),
            state: SessionState { buffered_payload },
        }
    }

    pub fn set_route(&mut self, selected_outbound: impl Into<String>, reason: RouteReason) {
        self.route = SessionRoute::selected(selected_outbound, reason);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Instant,
    };

    use super::{Destination, Host, Listen, Network, RouteReason, SessionContext, SessionMeta};

    #[test]
    fn display_formats_ipv4_and_domain() {
        let ipv4 = Destination::from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let domain = Destination::from_domain("example.com", 8443);

        assert_eq!(ipv4.to_string(), "1.2.3.4:443");
        assert_eq!(domain.to_string(), "example.com:8443");
    }

    #[test]
    fn display_wraps_ipv6() {
        let dest = Destination::new(Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)), 1080);
        assert_eq!(dest.to_string(), "[::1]:1080");
    }

    #[test]
    fn listen_formats_and_parses_ipv6() {
        let listen = Listen::new("::", 1041);

        assert_eq!(listen.format_addr(), "[::]:1041");
        assert_eq!(
            listen.parse_addr().expect("listen addr should parse"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041))
        );
    }

    #[test]
    fn session_context_starts_with_empty_route_and_buffered_payload_state() {
        let ctx = SessionContext::new(
            SessionMeta {
                id: 1,
                network: Network::Tcp,
                inbound_tag: "test".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 30000)),
                destination: Destination::from_domain("example.com", 443),
                start: Instant::now(),
            },
            b"ping".to_vec(),
        );

        assert_eq!(ctx.route.selected_outbound, None);
        assert_eq!(ctx.route.reason, None);
        assert_eq!(ctx.state.buffered_payload, b"ping");
    }

    #[test]
    fn session_context_route_can_be_set_after_construction() {
        let mut ctx = SessionContext::new(
            SessionMeta {
                id: 1,
                network: Network::Tcp,
                inbound_tag: "test".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 30000)),
                destination: Destination::from_domain("example.com", 443),
                start: Instant::now(),
            },
            Vec::new(),
        );

        ctx.set_route("proxy", RouteReason::Final);

        assert_eq!(ctx.route.selected_outbound.as_deref(), Some("proxy"));
        assert_eq!(ctx.route.reason, Some(RouteReason::Final));
    }
}
