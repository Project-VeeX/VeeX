use std::sync::Arc;

use veex_core::{logging::Logger, ProxyError};
use veex_portal_outbound::direct::{
    build_dialer as build_direct_dialer, build_packet_dialer as build_direct_packet_dialer,
    DirectOutbound,
};

use crate::factory::{
    lowering::LoweredDirectOutbound,
    runtime::{is_default_direct_tag, BuiltRuntimeOutbound, RuntimeServices},
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
