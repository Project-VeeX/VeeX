use std::sync::Arc;

use veex_config::{ProxyConfig, DEFAULT_DIRECT_OUTBOUND_TAG};
use veex_core::{
    Dial, ExecutionOutbound, Logger, OutboundMeta, OutboundRegistry, OutboundRegistryBuilder,
    ProxyError,
};
use veex_outbound_direct::{
    build_dialer as build_direct_dialer, build_packet_dialer as build_direct_packet_dialer,
    DirectOutbound,
};
use veex_outbound_trojan::{build_dialer as build_trojan_dialer, TrojanOutbound};

use crate::factory::{lower_outbound, LoweredOutbound, RuntimeServices};

const IMPLICIT_DIRECT_OUTBOUND_TAG: &str = "implicit-direct";

pub fn build_outbounds(
    config: &ProxyConfig,
    services: &RuntimeServices,
) -> Result<Arc<OutboundRegistry>, ProxyError> {
    let mut registry = OutboundRegistryBuilder::default();
    let mut configured_default_direct: Option<Arc<dyn ExecutionOutbound>> = None;

    for outbound in config.outbounds.iter().map(lower_outbound) {
        match outbound {
            LoweredOutbound::Direct(direct) => {
                let logger =
                    veex_core::Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                let dialer =
                    build_direct_dialer(direct.dial.clone(), Arc::clone(&services.host_resolver))?;
                let packet_dialer =
                    build_direct_packet_dialer(direct.dial, Arc::clone(&services.host_resolver))?;
                let instance: Arc<dyn ExecutionOutbound> = Arc::new(DirectOutbound::new(
                    direct.meta,
                    logger,
                    dialer,
                    packet_dialer,
                )?);
                if instance.meta().tag == DEFAULT_DIRECT_OUTBOUND_TAG {
                    configured_default_direct = Some(Arc::clone(&instance));
                }
                registry.register(instance)?;
            }
            LoweredOutbound::Trojan(trojan) => {
                let logger =
                    veex_core::Logger::new(trojan.meta.tag.clone(), trojan.meta.r#type.clone());
                let dialer = build_trojan_dialer(trojan.dial, Arc::clone(&services.host_resolver));
                let instance: Arc<dyn ExecutionOutbound> = Arc::new(TrojanOutbound::new(
                    trojan.meta,
                    logger,
                    dialer,
                    trojan.upstream_addr,
                    trojan.key,
                    trojan.tls,
                )?);
                registry.register(instance)?;
            }
        }
    }

    let default_outbound = match configured_default_direct {
        Some(outbound) => outbound,
        None => build_implicit_direct_outbound(services)?,
    };

    Ok(Arc::new(registry.finalize(default_outbound)))
}

fn build_implicit_direct_outbound(
    services: &RuntimeServices,
) -> Result<Arc<dyn ExecutionOutbound>, ProxyError> {
    let dialer = build_direct_dialer(Dial::default(), Arc::clone(&services.host_resolver))?;
    let packet_dialer =
        build_direct_packet_dialer(Dial::default(), Arc::clone(&services.host_resolver))?;

    Ok(Arc::new(DirectOutbound::new(
        OutboundMeta::new(IMPLICIT_DIRECT_OUTBOUND_TAG, "direct"),
        Logger::new(IMPLICIT_DIRECT_OUTBOUND_TAG, "direct"),
        dialer,
        packet_dialer,
    )?))
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
    use veex_core::{Destination, ErrorKind, Host, Network, SessionContext, SessionMeta};

    use super::{build_outbounds, IMPLICIT_DIRECT_OUTBOUND_TAG};
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
            .iter()
            .next()
            .expect("registry should contain direct outbound");
        registry_outbound
            .close()
            .await
            .expect("registry direct outbound should close");

        let route_outbound = built
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
            .iter()
            .next()
            .expect("registry should contain trojan outbound");
        registry_outbound
            .close()
            .await
            .expect("registry trojan outbound should close");

        let route_outbound = built
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
        let default = built.default_outbound();

        assert_eq!(default.meta().tag, IMPLICIT_DIRECT_OUTBOUND_TAG);
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
        let default = built.default_outbound();

        assert_eq!(default.meta().tag, IMPLICIT_DIRECT_OUTBOUND_TAG);
    }
}
