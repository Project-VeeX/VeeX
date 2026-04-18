mod direct;
mod socks;
mod transparent;

use std::sync::Arc;

use veex_config::ProxyConfig;
use veex_core::{portal::Inbound, ProxyError};
use veex_execution::{PacketDispatch, StreamDispatch};

use crate::factory::lowering::{lower_inbound, LoweredInbound};

pub fn build_inbounds(
    config: &ProxyConfig,
    stream_sink: Arc<dyn StreamDispatch>,
    packet_sink: Arc<dyn PacketDispatch>,
) -> Result<Vec<Arc<dyn Inbound>>, ProxyError> {
    let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();

    for inbound in config.inbounds.iter().map(lower_inbound) {
        match inbound {
            LoweredInbound::Direct(direct) => inbounds.extend(direct::build_direct_inbounds(
                direct,
                Arc::clone(&stream_sink),
                Arc::clone(&packet_sink),
            )?),
            LoweredInbound::Socks(socks) => {
                inbounds.push(socks::build_socks_inbound(socks, Arc::clone(&stream_sink))?)
            }
            LoweredInbound::Redirect(redirect) => inbounds.push(
                transparent::build_redirect_inbound(redirect, Arc::clone(&stream_sink))?,
            ),
            LoweredInbound::TProxy(tproxy) => inbounds.push(transparent::build_tproxy_inbound(
                tproxy,
                Arc::clone(&stream_sink),
            )?),
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
        io::BoxedAsyncStream,
        logging::Logger,
        portal::{BoxFuture, Outbound, OutboundMeta},
        session::SessionContext,
    };
    use veex_execution::{
        ExecutionFuture, ExecutionOutbound, OutboundCatalog, PacketDispatcher,
        RoutedPacketDispatch, RoutedStreamDispatch, StreamDispatcher,
    };
    use veex_router::Router;
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
        fn tag(&self) -> &str {
            &self.meta.tag
        }

        fn open_stream(&self, _ctx: &SessionContext) -> ExecutionFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("unused")) })
        }
    }

    fn test_outbounds() -> Arc<OutboundCatalog> {
        let outbound: Arc<dyn ExecutionOutbound> = Arc::new(UnusedExecutionOutbound::new());
        let mut outbounds = std::collections::HashMap::new();
        outbounds.insert(outbound.tag().to_string(), Arc::clone(&outbound));
        Arc::new(OutboundCatalog::new(outbounds, outbound))
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
