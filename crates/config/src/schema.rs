use std::{collections::BTreeMap, time::Duration};

use ipnet::IpNet;

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
pub enum InboundConfig {
    Direct(DirectInboundConfig),
    Socks(SocksInboundConfig),
    Redirect(RedirectInboundConfig),
    TProxy(TProxyInboundConfig),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundType {
    Direct,
    Socks,
    Redirect,
    TProxy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectInboundConfig {
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
    pub network: Option<String>,
    pub override_address: Option<String>,
    pub override_port: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksInboundConfig {
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirectInboundConfig {
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TProxyInboundConfig {
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
    pub network: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundConfig {
    Trojan(TrojanOutboundConfig),
    Direct(DirectOutboundConfig),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundType {
    Trojan,
    Direct,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanOutboundConfig {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub password: String,
    pub domain_resolver: Option<DomainResolverConfig>,
    /// Per-address TCP connect timeout applied by transport dialing.
    pub connect_timeout: Duration,
    pub tls: TrojanTlsConfig,
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
pub struct DirectOutboundConfig {
    pub tag: String,
    /// Per-address TCP connect timeout applied by transport dialing.
    pub connect_timeout: Duration,
    pub routing_mark: Option<u32>,
    pub domain_resolver: Option<DomainResolverConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteConfig {
    pub final_outbound: String,
    pub rules: Vec<RouteRuleConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsConfig {
    pub final_server: String,
    pub servers: Vec<DnsServerConfig>,
    pub rules: Vec<DnsRuleConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsServerConfig {
    pub tag: String,
    pub kind: DnsServerTypeConfig,
    pub server: String,
    pub server_port: u16,
    pub path: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub detour: String,
    pub domain_resolver: Option<DomainResolverConfig>,
    pub tls: TrojanTlsConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainResolverConfig {
    pub server: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsServerTypeConfig {
    Local,
    Udp,
    Tcp,
    Tls,
    Https,
    Unsupported(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRuleConfig {
    pub domain: Vec<String>,
    pub server: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRuleConfig {
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub ip_cidr: Vec<IpNet>,
    pub ip_is_private: bool,
    pub ip_is_loopback: bool,
    pub ip_is_link_local: bool,
    pub port: Vec<u16>,
    pub inbound: Vec<String>,
    pub action: RouteActionConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteActionConfig {
    Upgrade(RouteUpgradeActionConfig),
    Final(RouteFinalActionConfig),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteUpgradeActionConfig {
    Sniff(SniffActionConfig),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SniffActionConfig {
    pub timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteFinalActionConfig {
    Route(RouteTargetConfig),
    HijackDns,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteTargetConfig {
    pub outbound: String,
}

impl InboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Direct(config) => &config.tag,
            Self::Socks(config) => &config.tag,
            Self::Redirect(config) => &config.tag,
            Self::TProxy(config) => &config.tag,
        }
    }

    pub fn kind(&self) -> InboundType {
        match self {
            Self::Direct(_) => InboundType::Direct,
            Self::Socks(_) => InboundType::Socks,
            Self::Redirect(_) => InboundType::Redirect,
            Self::TProxy(_) => InboundType::TProxy,
        }
    }
}

impl OutboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Trojan(config) => &config.tag,
            Self::Direct(config) => &config.tag,
        }
    }

    pub fn kind(&self) -> OutboundType {
        match self {
            Self::Trojan(_) => OutboundType::Trojan,
            Self::Direct(_) => OutboundType::Direct,
        }
    }
}

impl RouteRuleConfig {
    pub fn has_matcher(&self) -> bool {
        !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.ip_cidr.is_empty()
            || self.ip_is_private
            || self.ip_is_loopback
            || self.ip_is_link_local
            || !self.port.is_empty()
            || !self.inbound.is_empty()
    }
}

impl DnsRuleConfig {
    pub fn has_matcher(&self) -> bool {
        !self.domain.is_empty()
    }
}
