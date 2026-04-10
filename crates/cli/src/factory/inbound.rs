use std::sync::Arc;

use veex_config::ProxyConfig;
use veex_core::{Inbound, ProxyError, ShutdownSignal};
use veex_inbound_socks::SocksInbound;
use veex_inbound_transparent::{RedirectInbound, TProxyInbound};

use crate::factory::{lower_inbound, LoweredInbound};

pub fn build_inbounds(
    config: &ProxyConfig,
    shutdown_signal: ShutdownSignal,
) -> Result<Vec<Arc<dyn Inbound>>, ProxyError> {
    let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();

    for inbound in config.inbounds.iter().map(lower_inbound) {
        match inbound {
            LoweredInbound::Socks(socks) => {
                let instance = SocksInbound::with_shutdown_signal(
                    socks.tag,
                    socks.listen,
                    socks.listen_port,
                    shutdown_signal.clone(),
                );
                instance.validate()?;
                inbounds.push(Arc::new(instance));
            }
            LoweredInbound::Redirect(redirect) => {
                let instance = RedirectInbound::with_shutdown_signal(
                    redirect.tag,
                    redirect.listen,
                    redirect.listen_port,
                    shutdown_signal.clone(),
                );
                instance.validate()?;
                inbounds.push(Arc::new(instance));
            }
            LoweredInbound::TProxy(tproxy) => {
                let instance = TProxyInbound::with_shutdown_signal(
                    tproxy.tag,
                    tproxy.listen,
                    tproxy.listen_port,
                    shutdown_signal.clone(),
                );
                instance.validate()?;
                inbounds.push(Arc::new(instance));
            }
        }
    }

    Ok(inbounds)
}

#[cfg(test)]
mod tests {
    use veex_config::InboundConfig;
    use veex_config::TProxyInboundConfig;
    use veex_config::{
        DirectOutboundConfig, LogConfig, OutboundConfig, ProxyConfig, RouteConfig,
        DEFAULT_CONNECT_TIMEOUT,
    };
    use veex_core::shutdown_channel;

    use super::*;

    #[test]
    fn builds_tproxy_inbound_from_config() {
        let (_trigger, shutdown_signal) = shutdown_channel();
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

        let inbounds = build_inbounds(&config, shutdown_signal).expect("inbounds should build");

        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].tag(), "tproxy-in");
    }
}
