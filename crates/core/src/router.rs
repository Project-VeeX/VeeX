use std::collections::BTreeSet;

use crate::types::{Host, SessionContext};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteReason {
    Final,
    BypassLoopback,
    BypassPrivate,
    BypassLinkLocal,
    BypassConfigured,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDecision {
    pub outbound_tag: String,
    pub reason: RouteReason,
}

#[derive(Clone, Debug)]
pub struct Router {
    final_outbound_tag: String,
    direct_outbound_tag: String,
    bypass_hosts: BTreeSet<String>,
}

impl Router {
    pub fn new(
        final_outbound_tag: impl Into<String>,
        direct_outbound_tag: impl Into<String>,
    ) -> Self {
        Self {
            final_outbound_tag: final_outbound_tag.into(),
            direct_outbound_tag: direct_outbound_tag.into(),
            bypass_hosts: BTreeSet::new(),
        }
    }

    pub fn with_bypass_host(mut self, host: impl Into<String>) -> Self {
        self.bypass_hosts.insert(normalize_host_str(&host.into()));
        self
    }

    pub fn with_bypass_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for host in hosts {
            self.bypass_hosts.insert(normalize_host_str(&host.into()));
        }
        self
    }

    pub fn select(&self, ctx: &SessionContext) -> RouteDecision {
        let host = &ctx.meta.destination.host;

        if is_loopback(host) {
            return RouteDecision {
                outbound_tag: self.direct_outbound_tag.clone(),
                reason: RouteReason::BypassLoopback,
            };
        }

        if is_private_or_unique_local(host) {
            return RouteDecision {
                outbound_tag: self.direct_outbound_tag.clone(),
                reason: RouteReason::BypassPrivate,
            };
        }

        if is_link_local(host) {
            return RouteDecision {
                outbound_tag: self.direct_outbound_tag.clone(),
                reason: RouteReason::BypassLinkLocal,
            };
        }

        if self.bypass_hosts.contains(&normalize_host(host)) {
            return RouteDecision {
                outbound_tag: self.direct_outbound_tag.clone(),
                reason: RouteReason::BypassConfigured,
            };
        }

        RouteDecision {
            outbound_tag: self.final_outbound_tag.clone(),
            reason: RouteReason::Final,
        }
    }
}

fn normalize_host(host: &Host) -> String {
    match host {
        Host::Ip(ip) => ip.to_string(),
        Host::Domain(domain) => normalize_host_str(domain),
    }
}

fn normalize_host_str(host: &str) -> String {
    host.trim().to_ascii_lowercase()
}

fn is_loopback(host: &Host) -> bool {
    match host {
        Host::Ip(ip) => ip.is_loopback(),
        Host::Domain(_) => false,
    }
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
}
