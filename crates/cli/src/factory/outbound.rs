use std::{collections::HashMap, sync::Arc};

use veex_config::ProxyConfig;
use veex_core::{Outbound, ProxyError, ProxyOutbound, RuntimeOutbound, StreamOutbound};
use veex_outbound_direct::{build_dialer as build_direct_dialer, DirectOutbound};
use veex_outbound_trojan::{build_dialer as build_trojan_dialer, TrojanOutbound};

use crate::factory::{lower_outbound, LoweredOutbound, RuntimeServices};

pub struct BuiltOutbounds {
    pub registry: Vec<Arc<dyn Outbound>>,
    pub routing: HashMap<String, RuntimeOutbound>,
}

pub fn build_outbounds(
    config: &ProxyConfig,
    services: &RuntimeServices,
) -> Result<BuiltOutbounds, ProxyError> {
    let mut registry: Vec<Arc<dyn Outbound>> = Vec::new();
    let mut routing: HashMap<String, RuntimeOutbound> = HashMap::new();

    for outbound in config.outbounds.iter().map(lower_outbound) {
        match outbound {
            LoweredOutbound::Direct(direct) => {
                let logger =
                    veex_core::Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                let dialer = build_direct_dialer(direct.dial, Arc::clone(&services.host_resolver))?;
                let instance = Arc::new(DirectOutbound::new(direct.meta.clone(), logger, dialer)?);
                registry.push(Arc::clone(&instance) as Arc<dyn Outbound>);
                routing.insert(
                    direct.meta.tag.clone(),
                    RuntimeOutbound::Stream(Arc::clone(&instance) as Arc<dyn StreamOutbound>),
                );
            }
            LoweredOutbound::Trojan(trojan) => {
                let logger =
                    veex_core::Logger::new(trojan.meta.tag.clone(), trojan.meta.r#type.clone());
                let dialer = build_trojan_dialer(trojan.dial);
                let instance = Arc::new(TrojanOutbound::new(
                    trojan.meta.clone(),
                    logger,
                    dialer,
                    trojan.server,
                    trojan.server_port,
                    trojan.password,
                    trojan.tls,
                )?);
                registry.push(Arc::clone(&instance) as Arc<dyn Outbound>);
                routing.insert(
                    trojan.meta.tag.clone(),
                    RuntimeOutbound::Proxy(Arc::clone(&instance) as Arc<dyn ProxyOutbound>),
                );
            }
        }
    }

    Ok(BuiltOutbounds { registry, routing })
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
        DEFAULT_TLS_HANDSHAKE_TIMEOUT,
    };
    use veex_core::{
        Destination, ErrorKind, Host, Network, RuntimeOutbound, SessionContext, SessionMeta,
    };

    use super::build_outbounds;
    use crate::factory::RuntimeServices;

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
    async fn closing_registry_direct_outbound_is_visible_to_routing_view() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
                rules: Vec::new(),
            },
        };
        let built =
            build_outbounds(&config, &RuntimeServices::default()).expect("outbounds should build");
        let registry_outbound = built
            .registry
            .first()
            .expect("registry should contain direct outbound");
        registry_outbound
            .close()
            .await
            .expect("registry direct outbound should close");

        let route_outbound = built
            .routing
            .get("direct")
            .expect("routing view should contain direct outbound");
        let err = match route_outbound {
            RuntimeOutbound::Stream(outbound) => {
                match outbound.connect_stream(&test_context("direct")).await {
                    Ok(_) => panic!("routing view should observe shutdown"),
                    Err(err) => err,
                }
            }
            RuntimeOutbound::Proxy(_) => panic!("direct outbound should register as stream"),
        };
        assert_eq!(err.kind(), ErrorKind::Shutdown);
    }

    #[tokio::test]
    async fn closing_registry_trojan_outbound_is_visible_to_routing_view() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: "proxy".into(),
                server: "127.0.0.1".into(),
                server_port: 443,
                password: "secret".into(),
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
            .registry
            .first()
            .expect("registry should contain trojan outbound");
        registry_outbound
            .close()
            .await
            .expect("registry trojan outbound should close");

        let route_outbound = built
            .routing
            .get("proxy")
            .expect("routing view should contain trojan outbound");
        let err = match route_outbound {
            RuntimeOutbound::Proxy(outbound) => {
                match outbound.connect_proxy_stream(&test_context("proxy")).await {
                    Ok(_) => panic!("routing view should observe shutdown"),
                    Err(err) => err,
                }
            }
            RuntimeOutbound::Stream(_) => panic!("trojan outbound should register as proxy"),
        };
        assert_eq!(err.kind(), ErrorKind::Shutdown);
    }
}
