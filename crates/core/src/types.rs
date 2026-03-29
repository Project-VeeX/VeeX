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

#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub id: u64,
    pub network: Network,
    pub inbound_tag: String,
    pub peer: SocketAddr,
    pub destination: Destination,
    pub start: Instant,
}

#[derive(Clone, Debug)]
pub struct SessionContext {
    pub meta: Arc<SessionMeta>,
    pub buffered_payload: Vec<u8>,
}

impl SessionContext {
    pub fn new(meta: SessionMeta, buffered_payload: Vec<u8>) -> Self {
        Self {
            meta: Arc::new(meta),
            buffered_payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{Destination, Host};

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
}
