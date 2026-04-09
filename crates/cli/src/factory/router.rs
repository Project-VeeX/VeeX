use veex_config::{
    ProxyConfig, RouteActionConfig, RouteFinalActionConfig, RouteRuleConfig,
    RouteUpgradeActionConfig,
};
use veex_core::{
    RouteAction, RouteFinalAction, RouteRule, RouteTarget, RouteUpgradeAction, Router, SniffAction,
};

pub fn build_router(config: &ProxyConfig) -> Router {
    Router::new(default_final_action(config)).with_rules(router_rules(config))
}

fn default_final_action(config: &ProxyConfig) -> RouteFinalAction {
    RouteFinalAction::Route(RouteTarget::new(config.route.final_outbound.clone()))
}

fn router_rules(config: &ProxyConfig) -> Vec<RouteRule> {
    config.route.rules.iter().map(route_rule).collect()
}

fn route_rule(rule: &RouteRuleConfig) -> RouteRule {
    RouteRule {
        domain: rule.domain.clone(),
        domain_suffix: rule.domain_suffix.clone(),
        ip_cidr: rule.ip_cidr.clone(),
        ip_is_private: rule.ip_is_private,
        ip_is_loopback: rule.ip_is_loopback,
        ip_is_link_local: rule.ip_is_link_local,
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
    use veex_core::{
        Destination, Host, RouteFinalAction, RouteReason, RouteTarget, SessionContext, SessionMeta,
    };

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
                rules: vec![RouteRuleConfig {
                    domain_suffix: vec!["google.com".into()],
                    domain: vec![],
                    ip_cidr: vec![],
                    ip_is_private: false,
                    ip_is_loopback: false,
                    ip_is_link_local: false,
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
    fn build_router_includes_route_rules() {
        let router = build_router(&build_config());

        let ruled = router.select(&build_ctx(Host::Domain("www.google.com".into())));
        assert_eq!(ruled.outbound_tag, "direct");
        assert_eq!(ruled.reason, RouteReason::Rule);
    }

    #[test]
    fn build_router_closes_route_final_into_default_final_action() {
        let router = build_router(&build_config());

        assert_eq!(
            router.default_final_action(),
            &RouteFinalAction::Route(RouteTarget::new("proxy"))
        );
    }
}
