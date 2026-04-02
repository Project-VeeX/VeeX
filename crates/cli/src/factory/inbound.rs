use std::sync::Arc;

use veex_config::{InboundConfig, ProxyConfig};
use veex_core::{Inbound, ShutdownSignal};
use veex_inbound_redirect::RedirectInbound;
use veex_inbound_socks::SocksInbound;
use veex_inbound_tproxy::TProxyInbound;

pub fn build_inbounds(
    config: &ProxyConfig,
    shutdown_signal: ShutdownSignal,
) -> Result<Vec<Arc<dyn Inbound>>, String> {
    let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();

    for inbound in &config.inbounds {
        match inbound {
            InboundConfig::Socks(socks) => {
                let instance: Arc<dyn Inbound> = Arc::new(SocksInbound::with_shutdown_signal(
                    socks.tag.clone(),
                    socks.listen.clone(),
                    socks.listen_port,
                    shutdown_signal.clone(),
                ));
                inbounds.push(instance);
            }
            InboundConfig::Redirect(redirect) => {
                let instance: Arc<dyn Inbound> = Arc::new(RedirectInbound::with_shutdown_signal(
                    redirect.tag.clone(),
                    redirect.listen.clone(),
                    redirect.listen_port,
                    shutdown_signal.clone(),
                ));
                inbounds.push(instance);
            }
            InboundConfig::TProxy(tproxy) => {
                let instance: Arc<dyn Inbound> = Arc::new(TProxyInbound::with_shutdown_signal(
                    tproxy.tag.clone(),
                    tproxy.listen.clone(),
                    tproxy.listen_port,
                    shutdown_signal.clone(),
                ));
                inbounds.push(instance);
            }
        }
    }

    Ok(inbounds)
}

#[cfg(test)]
mod tests {
    use veex_config::TProxyInboundConfig;
    use veex_config::{DirectOutboundConfig, LogConfig, OutboundConfig, ProxyConfig, RouteConfig};
    use veex_core::shutdown_channel;

    use super::*;

    #[test]
    fn builds_tproxy_inbound_from_config() {
        let (_trigger, shutdown_signal) = shutdown_channel();
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
            },
            inbounds: vec![InboundConfig::TProxy(TProxyInboundConfig {
                tag: "tproxy-in".into(),
                listen: "0.0.0.0".into(),
                listen_port: 1041,
                network: None,
            })],
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
            },
        };

        let inbounds = build_inbounds(&config, shutdown_signal).expect("inbounds should build");

        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].tag(), "tproxy-in");
    }
}
