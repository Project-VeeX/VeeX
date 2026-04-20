use std::{fmt, net::IpAddr};

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
