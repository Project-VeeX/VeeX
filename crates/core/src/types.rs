use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedAsyncStream = Box<dyn AsyncStream>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Tcp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Host {
    Ip(IpAddr),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Destination {
    pub host: Host,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteReason {
    Final,
    BypassLoopback,
    BypassPrivate,
    BypassLinkLocal,
    BypassConfigured,
}

impl RouteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Final => "final",
            Self::BypassLoopback => "loopback",
            Self::BypassPrivate => "private",
            Self::BypassLinkLocal => "link_local",
            Self::BypassConfigured => "configured",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub id: u64,
    pub network: Network,
    pub inbound_tag: String,
    pub peer: SocketAddr,
    pub destination: Destination,
    pub start: Instant,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionRoute {
    pub selected_outbound: Option<String>,
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionState {
    pub buffered_payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SessionContext {
    pub meta: Arc<SessionMeta>,
    pub route: SessionRoute,
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

    use super::{Destination, Host, Network, RouteReason, SessionContext, SessionMeta};

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
