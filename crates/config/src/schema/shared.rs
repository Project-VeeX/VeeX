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
pub struct TrojanTlsConfig {
    pub enabled: bool,
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
}
