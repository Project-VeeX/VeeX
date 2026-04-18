use std::time::Duration;

use ipnet::IpNet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteConfig {
    pub final_outbound: String,
    pub rules: Vec<RouteRuleConfig>,
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
