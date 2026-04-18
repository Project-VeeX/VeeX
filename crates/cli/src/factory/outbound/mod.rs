mod direct;
mod trojan;

use std::sync::Arc;

use veex_config::ProxyConfig;
use veex_core::ProxyError;

use crate::factory::{
    lowering::{lower_outbound, LoweredOutbound},
    runtime::{RuntimeOutbounds, RuntimeOutboundsBuilder, RuntimeServices},
};

pub fn build_outbounds(
    config: &ProxyConfig,
    services: &RuntimeServices,
) -> Result<Arc<RuntimeOutbounds>, ProxyError> {
    let mut built = RuntimeOutboundsBuilder::new();
    for outbound in config.outbounds.iter().map(lower_outbound) {
        match outbound {
            LoweredOutbound::Direct(direct) => {
                let (direct, is_default_direct) = direct::build_direct_outbound(direct, services)?;
                if is_default_direct {
                    built.set_default_direct(Arc::clone(&direct.execution));
                }
                built.register(direct)?;
            }
            LoweredOutbound::Trojan(trojan) => {
                built.register(trojan::build_trojan_outbound(trojan, services)?)?
            }
        }
    }

    built.finalize(services)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Instant,
    };

    use veex_config::{
        DirectOutboundConfig, LogConfig, OutboundConfig, ProxyConfig, RouteConfig,
        TrojanOutboundConfig, TrojanTlsConfig, DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_DIRECT_OUTBOUND_TAG, DEFAULT_TLS_HANDSHAKE_TIMEOUT,
    };
    use veex_core::{
        session::{SessionContext, SessionMeta},
        types::{Destination, Host, Network},
        ErrorKind,
    };

    use super::build_outbounds;
    use crate::factory::{runtime::IMPLICIT_DIRECT_OUTBOUND_TAG, RuntimeServices};

    fn test_context(outbound_tag: &str) -> SessionContext {
        SessionContext::new(
            SessionMeta {
                id: 7,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30000),
                destination: Destination::new(Host::Domain(format!("{outbound_tag}.example")), 443),
                start: Instant::now(),
            },
            Vec::new(),
        )
    }

    #[tokio::test]
    async fn closing_registry_direct_outbound_is_visible_to_dispatch_view() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
                domain_resolver: None,
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
                rules: Vec::new(),
            },
        };
        let built =
            build_outbounds(&config, &RuntimeServices::default()).expect("outbounds should build");
        let registry_outbound = built
            .lifecycle()
            .next()
            .expect("runtime should contain direct outbound");
        registry_outbound
            .close()
            .await
            .expect("registry direct outbound should close");

        let route_outbound = built
            .catalog()
            .get("direct")
            .expect("dispatch view should contain direct outbound");
        let err = match route_outbound.open_stream(&test_context("direct")).await {
            Ok(_) => panic!("dispatch view should observe shutdown"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::Shutdown);
    }

    #[tokio::test]
    async fn closing_registry_trojan_outbound_is_visible_to_dispatch_view() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: "proxy".into(),
                server: "127.0.0.1".into(),
                server_port: 443,
                password: "secret".into(),
                domain_resolver: None,
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                tls: TrojanTlsConfig {
                    enabled: true,
                    server_name: Some("localhost".into()),
                    disable_sni: false,
                    insecure: true,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            })],
            route: RouteConfig {
                final_outbound: "proxy".into(),
                rules: Vec::new(),
            },
        };
        let built =
            build_outbounds(&config, &RuntimeServices::default()).expect("outbounds should build");
        let registry_outbound = built
            .lifecycle()
            .next()
            .expect("runtime should contain trojan outbound");
        registry_outbound
            .close()
            .await
            .expect("registry trojan outbound should close");

        let route_outbound = built
            .catalog()
            .get("proxy")
            .expect("dispatch view should contain trojan outbound");
        let err = match route_outbound.open_stream(&test_context("proxy")).await {
            Ok(_) => panic!("dispatch view should observe shutdown"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::Shutdown);
    }

    #[test]
    fn build_outbounds_installs_implicit_default_direct_when_tag_direct_is_missing() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: "proxy".into(),
                server: "127.0.0.1".into(),
                server_port: 443,
                password: "secret".into(),
                domain_resolver: None,
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                tls: TrojanTlsConfig {
                    enabled: true,
                    server_name: Some("localhost".into()),
                    disable_sni: false,
                    insecure: true,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            })],
            route: RouteConfig {
                final_outbound: "proxy".into(),
                rules: Vec::new(),
            },
        };

        let built =
            build_outbounds(&config, &RuntimeServices::default()).expect("outbounds should build");
        let default = built.catalog().default_outbound();

        assert_eq!(default.tag(), IMPLICIT_DIRECT_OUTBOUND_TAG);
    }

    #[test]
    fn build_outbounds_does_not_treat_non_direct_tag_direct_as_default() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: DEFAULT_DIRECT_OUTBOUND_TAG.into(),
                server: "127.0.0.1".into(),
                server_port: 443,
                password: "secret".into(),
                domain_resolver: None,
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                tls: TrojanTlsConfig {
                    enabled: true,
                    server_name: Some("localhost".into()),
                    disable_sni: false,
                    insecure: true,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            })],
            route: RouteConfig {
                final_outbound: DEFAULT_DIRECT_OUTBOUND_TAG.into(),
                rules: Vec::new(),
            },
        };

        let built =
            build_outbounds(&config, &RuntimeServices::default()).expect("outbounds should build");
        let default = built.catalog().default_outbound();

        assert_eq!(default.tag(), IMPLICIT_DIRECT_OUTBOUND_TAG);
    }
}
