use std::time::Duration;

use super::{dns::DnsConfig, inbound::InboundConfig, outbound::OutboundConfig, route::RouteConfig};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyConfig {
    pub log: LogConfig,
    pub dns: Option<DnsConfig>,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub route: RouteConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogConfig {
    pub level: String,
    pub disabled: bool,
    pub timestamp: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenFields {
    pub listen: String,
    pub listen_port: u16,
}

impl ListenFields {
    pub fn new(listen: impl Into<String>, listen_port: u16) -> Self {
        Self {
            listen: listen.into(),
            listen_port,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DialFields {
    pub detour: Option<String>,
    /// Per-address TCP connect timeout applied by transport dialing.
    pub connect_timeout: Duration,
    pub routing_mark: Option<u32>,
    pub disable_tcp_keep_alive: bool,
    pub tcp_keep_alive: Duration,
    pub tcp_keep_alive_interval: Duration,
    pub domain_resolver: Option<DomainResolverConfig>,
}

impl DialFields {
    pub fn new(connect_timeout: Duration) -> Self {
        Self {
            detour: None,
            connect_timeout,
            routing_mark: None,
            disable_tcp_keep_alive: false,
            tcp_keep_alive: crate::DEFAULT_TCP_KEEPALIVE,
            tcp_keep_alive_interval: crate::DEFAULT_TCP_KEEPALIVE_INTERVAL,
            domain_resolver: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsFields {
    pub enabled: bool,
    pub alpn: Option<Vec<String>>,
    pub server_name: Option<String>,
    pub disable_sni: bool,
    pub insecure: bool,
    pub certificate_path: Option<String>,
    pub ca_path: Option<String>,
    /// TLS handshake-only timeout applied by transport TLS setup.
    pub handshake_timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainResolverConfig {
    pub server: String,
    pub disable_cache: bool,
}
