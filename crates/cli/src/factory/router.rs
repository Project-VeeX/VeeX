use veex_config::{OutboundConfig, ProxyConfig, DEFAULT_DIRECT_OUTBOUND_TAG};
use veex_core::Router;

pub fn build_router(config: &ProxyConfig) -> Router {
    let mut router = Router::new(
        config.route.final_outbound.clone(),
        DEFAULT_DIRECT_OUTBOUND_TAG,
    );

    for outbound in &config.outbounds {
        if let OutboundConfig::Trojan(trojan) = outbound {
            router = router.with_bypass_host(trojan.server.clone());
        }
    }

    router
}
