use std::sync::Arc;

use veex_core::{ProxyError, logging::Logger};
use veex_portal_outbound::direct::{
    DirectOutbound, build_dialer as build_direct_dialer,
    build_packet_dialer as build_direct_packet_dialer,
};

use crate::factory::{
    lowering::LoweredDirectOutbound,
    runtime::{BuiltRuntimeOutbound, RuntimeServices, is_default_direct_tag},
};

pub(super) fn build_direct_outbound(
    direct: LoweredDirectOutbound,
    services: &RuntimeServices,
) -> Result<(BuiltRuntimeOutbound, bool), ProxyError> {
    let is_default_direct = is_default_direct_tag(&direct.meta.tag);
    let logger = Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
    let dialer = build_direct_dialer(direct.dial.clone(), Arc::clone(&services.host_resolver))?;
    let packet_dialer =
        build_direct_packet_dialer(direct.dial, Arc::clone(&services.host_resolver))?;
    let instance = Arc::new(DirectOutbound::new(
        direct.meta,
        logger,
        dialer,
        packet_dialer,
    )?);

    Ok((BuiltRuntimeOutbound::new(instance), is_default_direct))
}
