use std::{collections::BTreeSet, net::IpAddr};

use ipnet::IpNet;

pub use crate::types::RouteReason;

use crate::types::{Destination, Host, SessionContext};

/// The result of a routing decision for a session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDecision {
    /// Tag of the outbound selected to handle this session.
    pub outbound_tag: String,
    /// Reason for the routing decision.
    pub reason: RouteReason,
}

/// Minimal route rule shape supported by the current router.
///
/// All populated matcher fields must match (`AND` semantics).
/// Rules are evaluated in declaration order and the first match wins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRule {
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub ip_cidr: Vec<IpNet>,
    pub port: Vec<u16>,
    pub inbound: Vec<String>,
    pub outbound_tag: String,
}

impl RouteRule {
    pub fn new(outbound_tag: impl Into<String>) -> Self {
        Self {
            domain: Vec::new(),
            domain_suffix: Vec::new(),
            ip_cidr: Vec::new(),
            port: Vec::new(),
            inbound: Vec::new(),
            outbound_tag: outbound_tag.into(),
        }
    }
}

/// Minimal routing input shape used by the pure router.
///
/// `domain` is separate from `destination.host` so the router can be rerun
/// after a future sniff phase provides richer metadata for an IP destination.
#[derive(Clone, Copy, Debug)]
pub struct RouteInput<'a> {
    pub destination: &'a Destination,
    pub inbound_tag: Option<&'a str>,
    pub domain: Option<&'a str>,
}

impl<'a> RouteInput<'a> {
    pub fn new(
        destination: &'a Destination,
        inbound_tag: Option<&'a str>,
        domain: Option<&'a str>,
    ) -> Self {
        Self {
            destination,
            inbound_tag,
            domain,
        }
    }

    pub fn from_session(ctx: &'a SessionContext) -> Self {
        Self {
            destination: &ctx.meta.destination,
            inbound_tag: Some(ctx.meta.inbound_tag.as_str()),
            domain: ctx.meta.destination.host.as_domain(),
        }
    }

    fn host(self) -> &'a Host {
        &self.destination.host
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompiledRouteRule {
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    ip_cidr: Vec<IpNet>,
    port: Vec<u16>,
    inbound: Vec<String>,
    outbound_tag: String,
}

impl From<RouteRule> for CompiledRouteRule {
    fn from(rule: RouteRule) -> Self {
        Self {
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
            port: rule.port,
            inbound: rule.inbound,
            outbound_tag: rule.outbound_tag,
        }
    }
}

impl CompiledRouteRule {
    fn matches(&self, input: RouteInput<'_>, normalized_domain: Option<&str>) -> bool {
        self.matches_exact_domain(normalized_domain)
            && self.matches_domain_suffix(normalized_domain)
            && self.matches_ip_cidr(input.host())
            && self.matches_port(input.destination.port)
            && self.matches_inbound(input.inbound_tag)
    }

    fn matches_exact_domain(&self, normalized_domain: Option<&str>) -> bool {
        if self.domain.is_empty() {
            return true;
        }

        normalized_domain
            .map(|domain| self.domain.iter().any(|candidate| candidate == domain))
            .unwrap_or(false)
    }

    fn matches_domain_suffix(&self, normalized_domain: Option<&str>) -> bool {
        if self.domain_suffix.is_empty() {
            return true;
        }

        normalized_domain
            .map(|domain| {
                self.domain_suffix
                    .iter()
                    .any(|suffix| matches_domain_suffix(domain, suffix))
            })
            .unwrap_or(false)
    }

    fn matches_ip_cidr(&self, host: &Host) -> bool {
        if self.ip_cidr.is_empty() {
            return true;
        }

        match host {
            Host::Ip(ip) => self.ip_cidr.iter().any(|cidr| cidr.contains(ip)),
            Host::Domain(_) => false,
        }
    }

    fn matches_port(&self, port: u16) -> bool {
        self.port.is_empty() || self.port.contains(&port)
    }

    fn matches_inbound(&self, inbound_tag: Option<&str>) -> bool {
        if self.inbound.is_empty() {
            return true;
        }

        inbound_tag
            .map(|tag| self.inbound.iter().any(|candidate| candidate == tag))
            .unwrap_or(false)
    }
}

/// Static router that decides which outbound should handle a session.
///
/// The routing decision pipeline is:
/// 1. Built-in bypass: loopback, private, link-local addresses → direct
/// 2. Configured bypass: exact domain or IP matches → direct
/// 3. User-defined route.rules: first match wins
/// 4. Final fallback: configured final outbound
///
/// `Router` is constructed once at startup and performs pure computation
/// with no I/O or DNS resolution.
#[derive(Clone, Debug)]
pub struct Router {
    final_outbound_tag: String,
    direct_outbound_tag: String,
    bypass_domains: BTreeSet<String>,
    bypass_ips: BTreeSet<IpAddr>,
    rules: Vec<CompiledRouteRule>,
}

impl Router {
    pub fn new(
        final_outbound_tag: impl Into<String>,
        direct_outbound_tag: impl Into<String>,
    ) -> Self {
        Self {
            final_outbound_tag: final_outbound_tag.into(),
            direct_outbound_tag: direct_outbound_tag.into(),
            bypass_domains: BTreeSet::new(),
            bypass_ips: BTreeSet::new(),
            rules: Vec::new(),
        }
    }

    pub fn with_bypass_host(mut self, host: impl Into<String>) -> Self {
        self.insert_bypass_host(&host.into());
        self
    }

    pub fn with_bypass_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for host in hosts {
            self.insert_bypass_host(&host.into());
        }
        self
    }

    pub fn with_rule(mut self, rule: RouteRule) -> Self {
        self.rules.push(rule.into());
        self
    }

    pub fn with_rules<I>(mut self, rules: I) -> Self
    where
        I: IntoIterator<Item = RouteRule>,
    {
        self.rules
            .extend(rules.into_iter().map(CompiledRouteRule::from));
        self
    }

    pub fn select(&self, ctx: &SessionContext) -> RouteDecision {
        self.select_input(RouteInput::from_session(ctx))
    }

    pub fn select_input(&self, input: RouteInput<'_>) -> RouteDecision {
        if let Some(reason) = self.match_bypass_reason(input) {
            return self.bypass_decision(reason);
        }

        if let Some(outbound_tag) = self.match_route_rules(input) {
            return self.rule_decision(outbound_tag);
        }

        self.final_decision()
    }

    fn insert_bypass_host(&mut self, host: &str) {
        match parse_bypass_host(host) {
            BypassHost::Ip(ip) => {
                self.bypass_ips.insert(ip);
            }
            BypassHost::Domain(domain) => {
                self.bypass_domains.insert(domain);
            }
        }
    }

    fn match_bypass_reason(&self, input: RouteInput<'_>) -> Option<RouteReason> {
        let host = input.host();
        match_builtin_bypass(host).or_else(|| {
            self.matches_configured_bypass(host)
                .then_some(RouteReason::BypassConfigured)
        })
    }

    fn match_route_rules(&self, input: RouteInput<'_>) -> Option<&str> {
        let normalized_domain = input.domain.map(normalize_domain_str);

        self.rules
            .iter()
            .find(|rule| rule.matches(input, normalized_domain.as_deref()))
            .map(|rule| rule.outbound_tag.as_str())
    }

    fn matches_configured_bypass(&self, host: &Host) -> bool {
        is_configured_bypass(host, &self.bypass_domains, &self.bypass_ips)
    }

    fn bypass_decision(&self, reason: RouteReason) -> RouteDecision {
        RouteDecision {
            outbound_tag: self.direct_outbound_tag.clone(),
            reason,
        }
    }

    fn rule_decision(&self, outbound_tag: &str) -> RouteDecision {
        RouteDecision {
            outbound_tag: outbound_tag.to_string(),
            reason: RouteReason::Rule,
        }
    }

    fn final_decision(&self) -> RouteDecision {
        RouteDecision {
            outbound_tag: self.final_outbound_tag.clone(),
            reason: RouteReason::Final,
        }
    }
}

fn normalize_domain_str(host: &str) -> String {
    host.trim().to_ascii_lowercase()
}

fn normalize_domain_suffix(suffix: &str) -> String {
    suffix.trim().trim_start_matches('.').to_ascii_lowercase()
}

fn matches_domain_suffix(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || (domain.len() > suffix.len()
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
}

enum BypassHost {
    Ip(IpAddr),
    Domain(String),
}

fn parse_bypass_host(host: &str) -> BypassHost {
    let host = host.trim();
    match host.parse::<IpAddr>() {
        Ok(ip) => BypassHost::Ip(ip),
        Err(_) => BypassHost::Domain(normalize_domain_str(host)),
    }
}

fn is_configured_bypass(
    host: &Host,
    bypass_domains: &BTreeSet<String>,
    bypass_ips: &BTreeSet<IpAddr>,
) -> bool {
    // `route.bypass` currently supports exact domain and exact IP matches only.
    // It does not implement suffix matching, wildcard expansion, or regex rules.
    match host {
        Host::Ip(ip) => bypass_ips.contains(ip),
        Host::Domain(domain) => bypass_domains.contains(&normalize_domain_str(domain)),
    }
}

fn is_loopback(host: &Host) -> bool {
    match host {
        Host::Ip(ip) => ip.is_loopback(),
        Host::Domain(_) => false,
    }
}

fn match_builtin_bypass(host: &Host) -> Option<RouteReason> {
    if is_loopback(host) {
        return Some(RouteReason::BypassLoopback);
    }

    if is_private_or_unique_local(host) {
        return Some(RouteReason::BypassPrivate);
    }

    if is_link_local(host) {
        return Some(RouteReason::BypassLinkLocal);
    }

    None
}

fn is_private_or_unique_local(host: &Host) -> bool {
    match host {
        Host::Ip(std::net::IpAddr::V4(ip)) => ip.is_private(),
        Host::Ip(std::net::IpAddr::V6(ip)) => ip.is_unique_local(),
        Host::Domain(_) => false,
    }
}

fn is_link_local(host: &Host) -> bool {
    match host {
        Host::Ip(std::net::IpAddr::V4(ip)) => ip.is_link_local(),
        Host::Ip(std::net::IpAddr::V6(ip)) => ip.is_unicast_link_local(),
        Host::Domain(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Instant,
    };

    use crate::types::{Destination, Network, SessionContext, SessionMeta};

    use super::{RouteInput, RouteReason, RouteRule, Router};

    fn build_ctx(destination: Destination) -> SessionContext {
        SessionContext::new(
            SessionMeta {
                id: 1,
                network: Network::Tcp,
                inbound_tag: "test".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        )
    }

    #[test]
    fn selects_final_for_normal_destinations() {
        let router = Router::new("proxy", "direct");
        let ctx = build_ctx(Destination::from_domain("example.com", 443));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag, "proxy");
        assert_eq!(decision.reason, RouteReason::Final);
    }

    #[test]
    fn bypasses_loopback() {
        let router = Router::new("proxy", "direct");
        let ctx = build_ctx(Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag, "direct");
        assert_eq!(decision.reason, RouteReason::BypassLoopback);
    }

    #[test]
    fn bypasses_private_ipv4() {
        let router = Router::new("proxy", "direct");
        let ctx = build_ctx(Destination::from_ip(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            53,
        ));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag, "direct");
        assert_eq!(decision.reason, RouteReason::BypassPrivate);
    }

    #[test]
    fn bypasses_configured_host() {
        let router = Router::new("proxy", "direct").with_bypass_host("trojan.example.com");
        let ctx = build_ctx(Destination::from_domain("trojan.example.com", 443));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag, "direct");
        assert_eq!(decision.reason, RouteReason::BypassConfigured);
    }

    #[test]
    fn splits_configured_domains_and_ips() {
        let router = Router::new("proxy", "direct").with_bypass_hosts([
            " Trojan.EXAMPLE.com ",
            "192.0.2.10",
            "2001:db8::1",
        ]);

        assert!(router.bypass_domains.contains("trojan.example.com"));
        assert!(router.bypass_ips.contains(&"192.0.2.10".parse().unwrap()));
        assert!(router.bypass_ips.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn bypasses_configured_ip() {
        let router = Router::new("proxy", "direct").with_bypass_host("192.0.2.10");
        let ctx = build_ctx(Destination::from_ip("192.0.2.10".parse().unwrap(), 443));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag, "direct");
        assert_eq!(decision.reason, RouteReason::BypassConfigured);
    }

    #[test]
    fn prefers_loopback_reason_over_configured_bypass() {
        let router = Router::new("proxy", "direct").with_bypass_host("127.0.0.1");
        let ctx = build_ctx(Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag, "direct");
        assert_eq!(decision.reason, RouteReason::BypassLoopback);
    }

    #[test]
    fn prefers_private_reason_over_configured_bypass() {
        let router = Router::new("proxy", "direct").with_bypass_host("192.168.1.10");
        let ctx = build_ctx(Destination::from_ip(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        ));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag, "direct");
        assert_eq!(decision.reason, RouteReason::BypassPrivate);
    }

    #[test]
    fn prefers_link_local_reason_over_configured_bypass() {
        let router = Router::new("proxy", "direct").with_bypass_host("169.254.10.20");
        let ctx = build_ctx(Destination::from_ip(
            IpAddr::V4(Ipv4Addr::new(169, 254, 10, 20)),
            8080,
        ));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag, "direct");
        assert_eq!(decision.reason, RouteReason::BypassLinkLocal);
    }

    #[test]
    fn matches_domain_rule_exactly() {
        let router = Router::new("final", "direct").with_rule(RouteRule {
            domain: vec!["example.com".into()],
            ..RouteRule::new("proxy")
        });
        let ctx = build_ctx(Destination::from_domain("Example.COM", 443));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag, "proxy");
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn matches_domain_suffix_for_apex_and_subdomain() {
        let router = Router::new("final", "direct").with_rule(RouteRule {
            domain_suffix: vec!["google.com".into()],
            ..RouteRule::new("proxy")
        });

        let apex = Destination::from_domain("google.com", 443);
        let subdomain = Destination::from_domain("www.google.com", 443);

        let apex_decision =
            router.select_input(RouteInput::new(&apex, Some("test"), Some("google.com")));
        let subdomain_decision = router.select_input(RouteInput::new(
            &subdomain,
            Some("test"),
            Some("www.google.com"),
        ));

        assert_eq!(apex_decision.outbound_tag, "proxy");
        assert_eq!(apex_decision.reason, RouteReason::Rule);
        assert_eq!(subdomain_decision.outbound_tag, "proxy");
        assert_eq!(subdomain_decision.reason, RouteReason::Rule);
    }

    #[test]
    fn matches_ip_cidr_rule_for_ip_destinations() {
        let router = Router::new("final", "direct").with_rule(RouteRule {
            ip_cidr: vec!["198.51.100.0/24".parse().unwrap()],
            ..RouteRule::new("proxy")
        });
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let decision = router.select_input(RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag, "proxy");
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn matches_port_and_inbound_rules() {
        let router = Router::new("final", "direct").with_rules([
            RouteRule {
                port: vec![53],
                ..RouteRule::new("dns")
            },
            RouteRule {
                inbound: vec!["socks-in".into()],
                ..RouteRule::new("socks-out")
            },
        ]);
        let port_destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 53);
        let inbound_destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 80);

        let port_match = router.select_input(RouteInput::new(
            &port_destination,
            Some("redirect-in"),
            None,
        ));
        let inbound_match = router.select_input(RouteInput::new(
            &inbound_destination,
            Some("socks-in"),
            None,
        ));

        assert_eq!(port_match.outbound_tag, "dns");
        assert_eq!(port_match.reason, RouteReason::Rule);
        assert_eq!(inbound_match.outbound_tag, "socks-out");
        assert_eq!(inbound_match.reason, RouteReason::Rule);
    }

    #[test]
    fn requires_all_matchers_in_a_rule_to_match() {
        let router = Router::new("final", "direct").with_rule(RouteRule {
            domain_suffix: vec!["google.com".into()],
            port: vec![443],
            ..RouteRule::new("proxy")
        });
        let matching = Destination::from_domain("www.google.com", 443);
        let mismatched_port = Destination::from_domain("www.google.com", 80);

        let matching_decision = router.select_input(RouteInput::new(
            &matching,
            Some("test"),
            Some("www.google.com"),
        ));
        let mismatched_decision = router.select_input(RouteInput::new(
            &mismatched_port,
            Some("test"),
            Some("www.google.com"),
        ));

        assert_eq!(matching_decision.outbound_tag, "proxy");
        assert_eq!(matching_decision.reason, RouteReason::Rule);
        assert_eq!(mismatched_decision.outbound_tag, "final");
        assert_eq!(mismatched_decision.reason, RouteReason::Final);
    }

    #[test]
    fn uses_first_matching_rule() {
        let router = Router::new("final", "direct").with_rules([
            RouteRule {
                port: vec![443],
                ..RouteRule::new("first")
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("second")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let decision = router.select_input(RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag, "first");
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn configured_bypass_still_precedes_rules() {
        let router = Router::new("final", "direct")
            .with_bypass_host("example.com")
            .with_rule(RouteRule {
                domain: vec!["example.com".into()],
                ..RouteRule::new("proxy")
            });
        let ctx = build_ctx(Destination::from_domain("example.com", 443));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag, "direct");
        assert_eq!(decision.reason, RouteReason::BypassConfigured);
    }

    #[test]
    fn built_in_bypass_still_precedes_rules() {
        let router = Router::new("final", "direct").with_rule(RouteRule {
            port: vec![8080],
            ..RouteRule::new("proxy")
        });
        let destination = Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);

        let decision = router.select_input(RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag, "direct");
        assert_eq!(decision.reason, RouteReason::BypassLoopback);
    }

    #[test]
    fn domain_rules_do_not_match_when_domain_is_absent() {
        let router = Router::new("final", "direct").with_rules([
            RouteRule {
                domain: vec!["example.com".into()],
                ..RouteRule::new("proxy")
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("fallback-rule")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let decision = router.select_input(RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag, "fallback-rule");
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn can_be_rerun_after_domain_becomes_available() {
        let router = Router::new("final", "direct").with_rule(RouteRule {
            domain_suffix: vec!["google.com".into()],
            ..RouteRule::new("proxy")
        });
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let first = router.select_input(RouteInput::new(&destination, Some("test"), None));
        let second = router.select_input(RouteInput::new(
            &destination,
            Some("test"),
            Some("www.google.com"),
        ));

        assert_eq!(first.outbound_tag, "final");
        assert_eq!(first.reason, RouteReason::Final);
        assert_eq!(second.outbound_tag, "proxy");
        assert_eq!(second.reason, RouteReason::Rule);
    }
}
