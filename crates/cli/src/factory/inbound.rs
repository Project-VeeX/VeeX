use std::sync::Arc;

use veex_config::ProxyConfig;
use veex_core::{Inbound, InboundSink, Listener, ListenerFactory, ProxyError};
use veex_inbound_socks::SocksInbound;
use veex_inbound_transparent::{
    create_redirect_listener, create_tproxy_listener, RedirectInbound, TProxyInbound,
};

use crate::factory::{lower_inbound, LoweredInbound};

pub fn build_inbounds(
    config: &ProxyConfig,
    sink: Arc<dyn InboundSink>,
) -> Result<Vec<Arc<dyn Inbound>>, ProxyError> {
    let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();

    for inbound in config.inbounds.iter().map(lower_inbound) {
        match inbound {
            LoweredInbound::Socks(socks) => {
                let logger =
                    veex_core::Logger::new(socks.meta.tag.clone(), socks.meta.r#type.clone());
                let listener = Listener::new(
                    socks.listen,
                    Arc::new(|addr| {
                        Box::pin(async move { Ok(tokio::net::TcpListener::bind(addr).await?) })
                    }),
                );
                let instance = SocksInbound::new(socks.meta, logger, Arc::clone(&sink), listener)?;
                inbounds.push(instance as Arc<dyn Inbound>);
            }
            LoweredInbound::Redirect(redirect) => {
                let logger =
                    veex_core::Logger::new(redirect.meta.tag.clone(), redirect.meta.r#type.clone());
                let listener_factory: Arc<ListenerFactory> = Arc::new(|addr| {
                    Box::pin(async move { create_redirect_listener(addr).map_err(Into::into) })
                });
                let listener = Listener::new(redirect.listen, listener_factory);
                let instance =
                    RedirectInbound::new(redirect.meta, logger, Arc::clone(&sink), listener)?;
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
                    Arc::clone(&sink),
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
    use super::*;
    use veex_config::InboundConfig;
    use veex_config::TProxyInboundConfig;
    use veex_config::{
        DirectOutboundConfig, LogConfig, OutboundConfig, ProxyConfig, RouteConfig,
        DEFAULT_CONNECT_TIMEOUT,
    };

    #[test]
    fn builds_tproxy_inbound_from_config() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
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
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
                rules: vec![],
            },
        };
        let sink: Arc<dyn InboundSink> = Arc::new(veex_core::Dispatcher::new(
            veex_core::Router::with_default_outbound("direct"),
            Arc::new(veex_core::OutboundRegistry::default()),
        ));

        let inbounds = build_inbounds(&config, sink).expect("inbounds should build");

        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].meta().tag, "tproxy-in");
    }
}
