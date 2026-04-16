use std::sync::Arc;

use veex_config::ProxyConfig;
use veex_core::{
    execution::{PacketDispatch, StreamDispatch},
    logging::Logger,
    portal::Inbound,
    ProxyError,
};
use veex_portal_inbound::direct::{create_direct_packet_listener, create_direct_stream_listener};
use veex_portal_inbound::socks::create_socks_listener;
use veex_portal_inbound::transparent::{
    create_redirect_stream_listener, create_tproxy_stream_listener,
};
use veex_portal_inbound::{
    DirectInbound, DirectUdpInbound, RedirectInbound, SocksInbound, TProxyInbound,
};

use crate::factory::{lower_inbound, LoweredDirectNetwork, LoweredInbound};

pub fn build_inbounds(
    config: &ProxyConfig,
    stream_sink: Arc<dyn StreamDispatch>,
    packet_sink: Arc<dyn PacketDispatch>,
) -> Result<Vec<Arc<dyn Inbound>>, ProxyError> {
    let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();

    for inbound in config.inbounds.iter().map(lower_inbound) {
        match inbound {
            LoweredInbound::Direct(direct) => match direct.network {
                LoweredDirectNetwork::Tcp => {
                    let logger = Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                    let listener = create_direct_stream_listener(direct.listen);
                    let instance = DirectInbound::new(
                        direct.meta,
                        logger,
                        Arc::clone(&stream_sink),
                        listener,
                        direct.override_host,
                        direct.override_port,
                    )?;
                    inbounds.push(instance as Arc<dyn Inbound>);
                }
                LoweredDirectNetwork::Udp => {
                    let logger = Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                    let listener = create_direct_packet_listener(direct.listen);
                    let instance = DirectUdpInbound::new(
                        direct.meta,
                        logger,
                        Arc::clone(&packet_sink),
                        listener,
                        direct.override_host,
                        direct.override_port,
                    )?;
                    inbounds.push(instance as Arc<dyn Inbound>);
                }
                LoweredDirectNetwork::Both => {
                    let tcp_logger =
                        Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                    let tcp_listener = create_direct_stream_listener(direct.listen.clone());
                    let tcp_instance = DirectInbound::new(
                        direct.meta.clone(),
                        tcp_logger,
                        Arc::clone(&stream_sink),
                        tcp_listener,
                        direct.override_host.clone(),
                        direct.override_port,
                    )?;
                    inbounds.push(tcp_instance as Arc<dyn Inbound>);

                    let udp_logger =
                        Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                    let udp_listener = create_direct_packet_listener(direct.listen);
                    let udp_instance = DirectUdpInbound::new(
                        direct.meta,
                        udp_logger,
                        Arc::clone(&packet_sink),
                        udp_listener,
                        direct.override_host,
                        direct.override_port,
                    )?;
                    inbounds.push(udp_instance as Arc<dyn Inbound>);
                }
            },
            LoweredInbound::Socks(socks) => {
                let logger = Logger::new(socks.meta.tag.clone(), socks.meta.r#type.clone());
                let listener = create_socks_listener(socks.listen);
                let instance =
                    SocksInbound::new(socks.meta, logger, Arc::clone(&stream_sink), listener)?;
                inbounds.push(instance as Arc<dyn Inbound>);
            }
            LoweredInbound::Redirect(redirect) => {
                let logger = Logger::new(redirect.meta.tag.clone(), redirect.meta.r#type.clone());
                let listener = create_redirect_stream_listener(redirect.listen);
                let instance = RedirectInbound::new(
                    redirect.meta,
                    logger,
                    Arc::clone(&stream_sink),
                    listener,
                )?;
                inbounds.push(instance as Arc<dyn Inbound>);
            }
            LoweredInbound::TProxy(tproxy) => {
                let logger = Logger::new(tproxy.meta.tag.clone(), tproxy.meta.r#type.clone());
                let listener = create_tproxy_stream_listener(tproxy.listen);
                let instance = TProxyInbound::new(
                    tproxy.meta,
                    logger,
                    Arc::clone(&stream_sink),
                    listener,
                    tproxy.network,
                )?;
                inbounds.push(instance as Arc<dyn Inbound>);
            }
        }
    }

    Ok(inbounds)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use veex_config::{
        DirectInboundConfig, DirectOutboundConfig, InboundConfig, LogConfig, OutboundConfig,
        ProxyConfig, RouteConfig, TProxyInboundConfig, DEFAULT_CONNECT_TIMEOUT,
    };
    use veex_core::{
        execution::{
            ExecutionOutbound, OutboundRegistry, OutboundRegistryBuilder, PacketDispatcher,
            RoutedPacketDispatch, RoutedStreamDispatch, StreamDispatcher,
        },
        io::BoxedAsyncStream,
        portal::{BoxFuture, Outbound, OutboundMeta},
        routing::Router,
        session::SessionContext,
    };
    struct UnusedExecutionOutbound {
        meta: OutboundMeta,
        logger: Logger,
    }

    impl UnusedExecutionOutbound {
        fn new() -> Self {
            Self {
                meta: OutboundMeta::new("direct", "direct"),
                logger: Logger::new("direct", "direct"),
            }
        }
    }

    impl Outbound for UnusedExecutionOutbound {
        fn meta(&self) -> &OutboundMeta {
            &self.meta
        }

        fn logger(&self) -> &Logger {
            &self.logger
        }

        fn close(&self) -> BoxFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    impl ExecutionOutbound for UnusedExecutionOutbound {
        fn open_stream(&self, _ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("unused")) })
        }
    }

    fn test_outbounds() -> Arc<OutboundRegistry> {
        Arc::new(
            OutboundRegistryBuilder::default().finalize(Arc::new(UnusedExecutionOutbound::new())),
        )
    }

    #[test]
    fn builds_direct_inbound_from_config() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: vec![InboundConfig::Direct(DirectInboundConfig {
                tag: "direct-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: 9000,
                network: Some("tcp".into()),
                override_address: Some("example.com".into()),
                override_port: Some(443),
            })],
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
                domain_resolver: None,
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
                rules: vec![],
            },
        };
        let sink: Arc<dyn StreamDispatch> = Arc::new(RoutedStreamDispatch::new(
            Router::with_default_outbound("direct"),
            Arc::new(StreamDispatcher::new(test_outbounds())),
        ));
        let packet_sink: Arc<dyn PacketDispatch> = Arc::new(RoutedPacketDispatch::new(
            Router::with_default_outbound("direct"),
            Arc::new(PacketDispatcher::new(test_outbounds())),
        ));

        let inbounds = build_inbounds(&config, sink, packet_sink).expect("inbounds should build");

        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].meta().tag, "direct-in");
    }

    #[test]
    fn builds_both_tcp_and_udp_direct_inbounds_when_network_is_omitted() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: vec![InboundConfig::Direct(DirectInboundConfig {
                tag: "dns-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: 15353,
                network: None,
                override_address: None,
                override_port: None,
            })],
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
                domain_resolver: None,
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
                rules: vec![],
            },
        };
        let sink: Arc<dyn StreamDispatch> = Arc::new(RoutedStreamDispatch::new(
            Router::with_default_outbound("direct"),
            Arc::new(StreamDispatcher::new(test_outbounds())),
        ));
        let packet_sink: Arc<dyn PacketDispatch> = Arc::new(RoutedPacketDispatch::new(
            Router::with_default_outbound("direct"),
            Arc::new(PacketDispatcher::new(test_outbounds())),
        ));

        let inbounds = build_inbounds(&config, sink, packet_sink).expect("inbounds should build");

        assert_eq!(inbounds.len(), 2);
        assert!(inbounds
            .iter()
            .all(|inbound| inbound.meta().tag == "dns-in"));
    }

    #[test]
    fn builds_tproxy_inbound_from_config() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: vec![InboundConfig::TProxy(TProxyInboundConfig {
                tag: "tproxy-in".into(),
                listen: "0.0.0.0".into(),
                listen_port: 1041,
                network: None,
            })],
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
                domain_resolver: None,
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
                rules: vec![],
            },
        };
        let sink: Arc<dyn StreamDispatch> = Arc::new(RoutedStreamDispatch::new(
            Router::with_default_outbound("direct"),
            Arc::new(StreamDispatcher::new(test_outbounds())),
        ));
        let packet_sink: Arc<dyn PacketDispatch> = Arc::new(RoutedPacketDispatch::new(
            Router::with_default_outbound("direct"),
            Arc::new(PacketDispatcher::new(test_outbounds())),
        ));

        let inbounds = build_inbounds(&config, sink, packet_sink).expect("inbounds should build");

        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].meta().tag, "tproxy-in");
    }
}
