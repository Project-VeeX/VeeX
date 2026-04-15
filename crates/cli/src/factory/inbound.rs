use std::sync::Arc;

use veex_config::ProxyConfig;
use veex_core::{Inbound, Listener, ListenerFactory, PacketDispatch, ProxyError, StreamDispatch};
use veex_inbound_direct::{create_direct_listener, DirectInbound, DirectUdpInbound};
use veex_inbound_socks::SocksInbound;
use veex_inbound_transparent::{
    create_redirect_listener, create_tproxy_listener, RedirectInbound, TProxyInbound,
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
                    let logger =
                        veex_core::Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                    let listener_factory: Arc<ListenerFactory> = Arc::new(|addr| {
                        Box::pin(async move { create_direct_listener(addr).map_err(Into::into) })
                    });
                    let listener = Listener::new(direct.listen, listener_factory);
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
                    let logger =
                        veex_core::Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                    let instance = DirectUdpInbound::new(
                        direct.meta,
                        logger,
                        Arc::clone(&packet_sink),
                        direct.listen,
                        direct.override_host,
                        direct.override_port,
                    )?;
                    inbounds.push(instance as Arc<dyn Inbound>);
                }
                LoweredDirectNetwork::Both => {
                    let tcp_logger =
                        veex_core::Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                    let listener_factory: Arc<ListenerFactory> = Arc::new(|addr| {
                        Box::pin(async move { create_direct_listener(addr).map_err(Into::into) })
                    });
                    let tcp_listener = Listener::new(direct.listen.clone(), listener_factory);
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
                        veex_core::Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                    let udp_instance = DirectUdpInbound::new(
                        direct.meta,
                        udp_logger,
                        Arc::clone(&packet_sink),
                        direct.listen,
                        direct.override_host,
                        direct.override_port,
                    )?;
                    inbounds.push(udp_instance as Arc<dyn Inbound>);
                }
            },
            LoweredInbound::Socks(socks) => {
                let logger =
                    veex_core::Logger::new(socks.meta.tag.clone(), socks.meta.r#type.clone());
                let listener = Listener::new(
                    socks.listen,
                    Arc::new(|addr| {
                        Box::pin(async move { Ok(tokio::net::TcpListener::bind(addr).await?) })
                    }),
                );
                let instance =
                    SocksInbound::new(socks.meta, logger, Arc::clone(&stream_sink), listener)?;
                inbounds.push(instance as Arc<dyn Inbound>);
            }
            LoweredInbound::Redirect(redirect) => {
                let logger =
                    veex_core::Logger::new(redirect.meta.tag.clone(), redirect.meta.r#type.clone());
                let listener_factory: Arc<ListenerFactory> = Arc::new(|addr| {
                    Box::pin(async move { create_redirect_listener(addr).map_err(Into::into) })
                });
                let listener = Listener::new(redirect.listen, listener_factory);
                let instance = RedirectInbound::new(
                    redirect.meta,
                    logger,
                    Arc::clone(&stream_sink),
                    listener,
                )?;
                inbounds.push(instance as Arc<dyn Inbound>);
            }
            LoweredInbound::TProxy(tproxy) => {
                let logger =
                    veex_core::Logger::new(tproxy.meta.tag.clone(), tproxy.meta.r#type.clone());
                let listener_factory: Arc<ListenerFactory> = Arc::new(|addr| {
                    Box::pin(async move { create_tproxy_listener(addr).map_err(Into::into) })
                });
                let listener = Listener::new(tproxy.listen, listener_factory);
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
        BoxFuture, BoxedAsyncStream, Logger, Outbound, OutboundMeta, OutboundRegistry,
        OutboundRegistryBuilder, ProxyError, SessionContext,
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

    impl veex_core::ExecutionOutbound for UnusedExecutionOutbound {
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
        let sink: Arc<dyn StreamDispatch> = Arc::new(veex_core::StreamDispatcher::new(
            veex_core::Router::with_default_outbound("direct"),
            test_outbounds(),
        ));
        let packet_sink: Arc<dyn PacketDispatch> = Arc::new(veex_core::PacketDispatcher::new(
            veex_core::Router::with_default_outbound("direct"),
            test_outbounds(),
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
        let sink: Arc<dyn StreamDispatch> = Arc::new(veex_core::StreamDispatcher::new(
            veex_core::Router::with_default_outbound("direct"),
            test_outbounds(),
        ));
        let packet_sink: Arc<dyn PacketDispatch> = Arc::new(veex_core::PacketDispatcher::new(
            veex_core::Router::with_default_outbound("direct"),
            test_outbounds(),
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
        let sink: Arc<dyn StreamDispatch> = Arc::new(veex_core::StreamDispatcher::new(
            veex_core::Router::with_default_outbound("direct"),
            test_outbounds(),
        ));
        let packet_sink: Arc<dyn PacketDispatch> = Arc::new(veex_core::PacketDispatcher::new(
            veex_core::Router::with_default_outbound("direct"),
            test_outbounds(),
        ));

        let inbounds = build_inbounds(&config, sink, packet_sink).expect("inbounds should build");

        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].meta().tag, "tproxy-in");
    }
}
