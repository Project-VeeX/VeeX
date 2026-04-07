use std::{collections::BTreeSet, net::IpAddr};

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

/// Static router that decides which outbound should handle a session.
///
/// The routing decision pipeline is:
/// 1. Built-in bypass: loopback, private, link-local addresses → direct
/// 2. Configured bypass: exact domain or IP matches → direct
/// 3. Final fallback: configured final outbound
///
/// `Router` is constructed once at startup and performs pure computation
/// with no I/O or DNS resolution.
#[derive(Clone, Debug)]
pub struct Router {
    final_outbound_tag: String,
    direct_outbound_tag: String,
    bypass_domains: BTreeSet<String>,
    bypass_ips: BTreeSet<IpAddr>,
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

    pub fn select(&self, ctx: &SessionContext) -> RouteDecision {
        self.select_destination(&ctx.meta.destination)
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

    fn select_destination(&self, destination: &Destination) -> RouteDecision {
        let input = RouteInput::new(destination);
        if let Some(reason) = self.match_bypass_reason(input) {
            return self.bypass_decision(reason);
        }

        // Future `route.rules` matching can extend this decision pipeline here,
        // after the current minimal bypass handling and before the final fallback.
        self.final_decision()
    }

    fn match_bypass_reason(&self, input: RouteInput<'_>) -> Option<RouteReason> {
        let host = input.host();
        match_builtin_bypass(host).or_else(|| {
            self.matches_configured_bypass(host)
                .then_some(RouteReason::BypassConfigured)
        })
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

    fn final_decision(&self) -> RouteDecision {
        RouteDecision {
            outbound_tag: self.final_outbound_tag.clone(),
            reason: RouteReason::Final,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RouteInput<'a> {
    destination: &'a Destination,
}

impl<'a> RouteInput<'a> {
    fn new(destination: &'a Destination) -> Self {
        Self { destination }
    }

    fn host(self) -> &'a Host {
        &self.destination.host
    }
}

fn normalize_domain(host: &Host) -> Option<String> {
    match host {
        Host::Ip(_) => None,
        Host::Domain(domain) => Some(normalize_domain_str(domain)),
    }
}

fn normalize_domain_str(host: &str) -> String {
    host.trim().to_ascii_lowercase()
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
        Host::Domain(_) => normalize_domain(host)
            .map(|domain| bypass_domains.contains(&domain))
            .unwrap_or(false),
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

    use super::{RouteReason, Router};

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
}
