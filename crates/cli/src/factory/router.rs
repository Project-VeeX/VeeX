use veex_config::{OutboundConfig, ProxyConfig, DEFAULT_DIRECT_OUTBOUND_TAG};
use veex_core::Router;

pub fn build_router(config: &ProxyConfig) -> Router {
    let mut router = Router::new(
        config.route.final_outbound.clone(),
        DEFAULT_DIRECT_OUTBOUND_TAG,
    )
    .with_bypass_hosts(config.route.bypass.iter().cloned());

    for outbound in &config.outbounds {
        if let OutboundConfig::Trojan(trojan) = outbound {
            router = router.with_bypass_host(trojan.server.clone());
        }
    }

    router
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Instant};

    use veex_config::{
        DirectOutboundConfig, InboundConfig, LogConfig, OutboundConfig, ProxyConfig, RouteConfig,
        SocksInboundConfig, TrojanOutboundConfig, TrojanTlsConfig,
    };
    use veex_core::{Destination, Host, RouteReason, SessionContext, SessionMeta};

    use super::build_router;

    fn build_config() -> ProxyConfig {
        ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
            },
            inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
                tag: "socks-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: 1080,
            })],
            outbounds: vec![
                OutboundConfig::Direct(DirectOutboundConfig {
                    tag: "direct".into(),
                    routing_mark: None,
                }),
                OutboundConfig::Trojan(TrojanOutboundConfig {
                    tag: "proxy".into(),
                    server: "trojan.example.com".into(),
                    server_port: 443,
                    password: "secret".into(),
                    tls: TrojanTlsConfig {
                        enabled: true,
                        server_name: Some("trojan.example.com".into()),
                        disable_sni: false,
                        insecure: false,
                        certificate_path: None,
                        ca_path: None,
                    },
                }),
            ],
            route: RouteConfig {
                final_outbound: "proxy".into(),
                bypass: vec!["configured.example.com".into()],
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
}
