use std::sync::Arc;

use veex_config::{InboundConfig, ProxyConfig};
use veex_core::{Inbound, ShutdownSignal};
use veex_inbound_redirect::RedirectInbound;
use veex_inbound_socks::SocksInbound;

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
        }
    }

    Ok(inbounds)
}
