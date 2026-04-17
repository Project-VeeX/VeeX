use ipnet::IpNet;

use super::{
    matchers::{normalize_domain_str, normalize_domain_suffix},
    types::{RouteAction, RouteRule},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompiledRouteRule {
    pub(crate) rule_index: usize,
    pub(crate) matcher_summary: String,
    pub(crate) domain: Vec<String>,
    pub(crate) domain_suffix: Vec<String>,
    pub(crate) ip_cidr: Vec<IpNet>,
    pub(crate) ip_is_private: bool,
    pub(crate) ip_is_loopback: bool,
    pub(crate) ip_is_link_local: bool,
    pub(crate) port: Vec<u16>,
    pub(crate) inbound: Vec<String>,
    pub(crate) action: RouteAction,
}

impl CompiledRouteRule {
    pub(crate) fn compile(rule: RouteRule, rule_index: usize) -> Self {
        Self {
            rule_index,
            matcher_summary: build_matcher_summary(&rule),
            domain: rule
                .domain
                .into_iter()
                .map(|domain| normalize_domain_str(&domain))
                .collect(),
            domain_suffix: rule
                .domain_suffix
                .into_iter()
                .map(|suffix| normalize_domain_suffix(&suffix))
                .collect(),
            ip_cidr: rule.ip_cidr,
            ip_is_private: rule.ip_is_private,
            ip_is_loopback: rule.ip_is_loopback,
            ip_is_link_local: rule.ip_is_link_local,
            port: rule.port,
            inbound: rule.inbound,
            action: rule.action,
        }
    }
}

fn build_matcher_summary(rule: &RouteRule) -> String {
    let mut matchers = Vec::new();

    if !rule.domain.is_empty() {
        matchers.push("domain");
    }
    if !rule.domain_suffix.is_empty() {
        matchers.push("domain_suffix");
    }
    if !rule.ip_cidr.is_empty() {
        matchers.push("ip_cidr");
    }
    if rule.ip_is_private {
        matchers.push("ip_is_private");
    }
    if rule.ip_is_loopback {
        matchers.push("ip_is_loopback");
    }
    if rule.ip_is_link_local {
        matchers.push("ip_is_link_local");
    }
    if !rule.port.is_empty() {
        matchers.push("port");
    }
    if !rule.inbound.is_empty() {
        matchers.push("inbound");
    }

    if matchers.is_empty() {
        "none".to_string()
    } else {
        matchers.join(",")
    }
}
