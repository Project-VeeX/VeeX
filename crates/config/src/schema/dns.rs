use std::collections::BTreeMap;

use super::shared::{DomainResolverConfig, TrojanTlsConfig};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsConfig {
    pub final_server: String,
    pub disable_cache: bool,
    pub cache_capacity: Option<usize>,
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
    pub disable_cache: bool,
}

impl DnsRuleConfig {
    pub fn has_matcher(&self) -> bool {
        !self.domain.is_empty()
    }
}
