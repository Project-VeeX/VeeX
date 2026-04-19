use std::sync::Arc;

use veex_core::{ProxyError, logging::Logger};
use veex_portal_outbound::trojan::{TrojanOutbound, build_dialer as build_trojan_dialer};

use crate::factory::{
    lowering::LoweredTrojanOutbound,
    runtime::{BuiltRuntimeOutbound, RuntimeServices},
};

pub(super) fn build_trojan_outbound(
    trojan: LoweredTrojanOutbound,
    services: &RuntimeServices,
) -> Result<BuiltRuntimeOutbound, ProxyError> {
    let logger = Logger::new(trojan.meta.tag.clone(), trojan.meta.r#type.clone());
    let dialer = build_trojan_dialer(trojan.dial, Arc::clone(&services.host_resolver));
    let instance = Arc::new(TrojanOutbound::new(
        trojan.meta,
        logger,
        dialer,
        trojan.upstream_addr,
        trojan.key,
        trojan.tls,
    )?);

    Ok(BuiltRuntimeOutbound::new(instance))
}
