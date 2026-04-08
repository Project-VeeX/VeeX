use veex_config::{
    OutboundConfig, ProxyConfig, RouteActionConfig, RouteFinalActionConfig, RouteRuleConfig,
    RouteUpgradeActionConfig, DEFAULT_DIRECT_OUTBOUND_TAG,
};
use veex_core::{
    RouteAction, RouteFinalAction, RouteRule, RouteTarget, RouteUpgradeAction, Router, SniffAction,
};

pub fn build_router(config: &ProxyConfig) -> Router {
    Router::new(
        config.route.final_outbound.clone(),
        DEFAULT_DIRECT_OUTBOUND_TAG,
    )
    .with_bypass_hosts(router_bypass_hosts(config))
    .with_rules(router_rules(config))
}

fn router_bypass_hosts(config: &ProxyConfig) -> Vec<String> {
    let mut hosts = config.route.bypass.clone();
    hosts.extend(config.outbounds.iter().filter_map(implicit_bypass_host));
    hosts
}

fn implicit_bypass_host(outbound: &OutboundConfig) -> Option<String> {
    match outbound {
        OutboundConfig::Trojan(trojan) => Some(trojan.server.clone()),
        OutboundConfig::Direct(_) => None,
    }
}

fn router_rules(config: &ProxyConfig) -> Vec<RouteRule> {
    config.route.rules.iter().map(route_rule).collect()
}

fn route_rule(rule: &RouteRuleConfig) -> RouteRule {
    RouteRule {
        domain: rule.domain.clone(),
        domain_suffix: rule.domain_suffix.clone(),
        ip_cidr: rule.ip_cidr.clone(),
        port: rule.port.clone(),
        inbound: rule.inbound.clone(),
        action: route_action(&rule.action),
    }
}

fn route_action(action: &RouteActionConfig) -> RouteAction {
    match action {
        RouteActionConfig::Upgrade(RouteUpgradeActionConfig::Sniff(sniff)) => {
            RouteAction::Upgrade(RouteUpgradeAction::Sniff(SniffAction {
                timeout: sniff.timeout,
            }))
        }
        RouteActionConfig::Final(RouteFinalActionConfig::Route(target)) => RouteAction::Final(
            RouteFinalAction::Route(RouteTarget::new(target.outbound.clone())),
        ),
        RouteActionConfig::Final(RouteFinalActionConfig::HijackDns) => {
            RouteAction::Final(RouteFinalAction::HijackDns)
        }
        RouteActionConfig::Final(RouteFinalActionConfig::Reject) => {
            RouteAction::Final(RouteFinalAction::Reject)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Instant};

    use veex_config::{
        DirectOutboundConfig, InboundConfig, LogConfig, OutboundConfig, ProxyConfig,
        RouteActionConfig, RouteConfig, RouteFinalActionConfig, RouteRuleConfig, RouteTargetConfig,
        SocksInboundConfig, TrojanOutboundConfig, TrojanTlsConfig, DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_TLS_HANDSHAKE_TIMEOUT,
    };
    use veex_core::{Destination, Host, RouteReason, SessionContext, SessionMeta};

    use super::build_router;

    fn build_config() -> ProxyConfig {
        ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
                tag: "socks-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: 1080,
            })],
            outbounds: vec![
                OutboundConfig::Direct(DirectOutboundConfig {
                    tag: "direct".into(),
                    connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                    routing_mark: None,
                }),
                OutboundConfig::Trojan(TrojanOutboundConfig {
                    tag: "proxy".into(),
                    server: "trojan.example.com".into(),
                    server_port: 443,
                    password: "secret".into(),
                    connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                    tls: TrojanTlsConfig {
                        enabled: true,
                        server_name: Some("trojan.example.com".into()),
                        disable_sni: false,
                        insecure: false,
                        certificate_path: None,
                        ca_path: None,
                        handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                    },
                }),
            ],
            route: RouteConfig {
                final_outbound: "proxy".into(),
                bypass: vec!["configured.example.com".into()],
                rules: vec![RouteRuleConfig {
                    domain_suffix: vec!["google.com".into()],
                    domain: vec![],
                    ip_cidr: vec![],
                    port: vec![],
                    inbound: vec![],
                    action: RouteActionConfig::Final(RouteFinalActionConfig::Route(
                        RouteTargetConfig {
                            outbound: "direct".into(),
                        },
                    )),
                }],
            },
        }
    }

    fn build_ctx(host: Host) -> SessionContext {
        SessionContext::new(
            SessionMeta {
                id: 1,
                network: veex_core::Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 30000)),
                destination: Destination::new(host, 443),
                start: Instant::now(),
            },
            Vec::new(),
        )
    }

    #[test]
    fn build_router_includes_explicit_bypass_and_trojan_server_bypass() {
        let router = build_router(&build_config());

        let configured = router.select(&build_ctx(Host::Domain("configured.example.com".into())));
        assert_eq!(configured.outbound_tag, "direct");
        assert_eq!(configured.reason, RouteReason::BypassConfigured);

        let trojan_server = router.select(&build_ctx(Host::Domain("trojan.example.com".into())));
        assert_eq!(trojan_server.outbound_tag, "direct");
        assert_eq!(trojan_server.reason, RouteReason::BypassConfigured);
    }

    #[test]
    fn build_router_includes_route_rules() {
        let router = build_router(&build_config());

        let ruled = router.select(&build_ctx(Host::Domain("www.google.com".into())));
        assert_eq!(ruled.outbound_tag, "direct");
        assert_eq!(ruled.reason, RouteReason::Rule);
    }
}
