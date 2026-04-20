use veex_config::ProxyConfig;
use veex_router::Router;

use crate::factory::lowering::lower_route;

pub fn build_router(config: &ProxyConfig) -> Router {
    let route = lower_route(&config.route);
    Router::new(route.default_final_action).with_rules(route.rules)
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Instant};

    use veex_config::{
        DEFAULT_CONNECT_TIMEOUT, DEFAULT_TLS_HANDSHAKE_TIMEOUT, DialFields, DirectOutboundConfig,
        InboundConfig, ListenFields, LogConfig, OutboundConfig, ProxyConfig, RouteActionConfig,
        RouteConfig, RouteFinalActionConfig, RouteRuleConfig, RouteTargetConfig,
        SocksInboundConfig, TlsFields, TrojanOutboundConfig,
    };
    use veex_core::{
        io::StreamCarrier,
        session::{SessionContext, SessionMeta},
        types::{Destination, Host, Network},
    };
    use veex_router::{RouteFinalAction, RouteReason, RouteTarget};

    use super::build_router;

    fn build_config() -> ProxyConfig {
        ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
                tag: "socks-in".into(),
                listen: ListenFields::new("127.0.0.1", 1080),
            })],
            outbounds: vec![
                OutboundConfig::Direct(DirectOutboundConfig {
                    tag: "direct".into(),
                    dial: DialFields::new(DEFAULT_CONNECT_TIMEOUT),
                }),
                OutboundConfig::Trojan(TrojanOutboundConfig {
                    tag: "proxy".into(),
                    server: "trojan.example.com".into(),
                    server_port: 443,
                    password: "secret".into(),
                    dial: DialFields::new(DEFAULT_CONNECT_TIMEOUT),
                    tls: TlsFields {
                        enabled: true,
                        alpn: None,
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
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 30000)),
                destination: Destination::new(host, 443),
                start: Instant::now(),
            },
            Vec::new(),
        )
    }

    #[tokio::test]
    async fn build_router_includes_route_rules() {
        let router = build_router(&build_config());
        let ctx = build_ctx(Host::Domain("www.google.com".into()));
        let (stream, _peer) = tokio::io::duplex(64);

        let routed = router
            .route_stream(StreamCarrier::new(Box::new(stream)), ctx)
            .await
            .expect("route_stream should succeed");
        assert_eq!(routed.decision.outbound_tag(), Some("direct"));
        assert_eq!(routed.decision.reason, RouteReason::Rule);
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
