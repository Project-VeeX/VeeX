use std::time::Duration;

use super::shared::{DomainResolverConfig, TrojanTlsConfig};

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
pub struct DirectOutboundConfig {
    pub tag: String,
    /// Per-address TCP connect timeout applied by transport dialing.
    pub connect_timeout: Duration,
    pub routing_mark: Option<u32>,
    pub domain_resolver: Option<DomainResolverConfig>,
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
