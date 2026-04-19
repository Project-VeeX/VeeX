use std::sync::Arc;

use veex_core::{ProxyError, logging::Logger, portal::Inbound};
use veex_execution::{PacketDispatch, StreamDispatch};
use veex_portal_inbound::direct::{create_direct_packet_listener, create_direct_stream_listener};
use veex_portal_inbound::{DirectInbound, DirectUdpInbound};

use crate::factory::lowering::{LoweredDirectInbound, LoweredDirectNetwork};

pub(super) fn build_direct_inbounds(
    direct: LoweredDirectInbound,
    stream_sink: Arc<dyn StreamDispatch>,
    packet_sink: Arc<dyn PacketDispatch>,
) -> Result<Vec<Arc<dyn Inbound>>, ProxyError> {
    match direct.network {
        LoweredDirectNetwork::Tcp => Ok(vec![build_tcp_inbound(direct, stream_sink)?]),
        LoweredDirectNetwork::Udp => Ok(vec![build_udp_inbound(direct, packet_sink)?]),
        LoweredDirectNetwork::Both => Ok(vec![
            build_tcp_inbound(direct.clone(), Arc::clone(&stream_sink))?,
            build_udp_inbound(direct, packet_sink)?,
        ]),
    }
}

fn build_tcp_inbound(
    direct: LoweredDirectInbound,
    stream_sink: Arc<dyn StreamDispatch>,
) -> Result<Arc<dyn Inbound>, ProxyError> {
    let logger = Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
    let listener = create_direct_stream_listener(direct.listen);
    let instance = DirectInbound::new(
        direct.meta,
        logger,
        stream_sink,
        listener,
        direct.override_host,
        direct.override_port,
    )?;
    Ok(instance as Arc<dyn Inbound>)
}

fn build_udp_inbound(
    direct: LoweredDirectInbound,
    packet_sink: Arc<dyn PacketDispatch>,
) -> Result<Arc<dyn Inbound>, ProxyError> {
    let logger = Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
    let listener = create_direct_packet_listener(direct.listen);
    let instance = DirectUdpInbound::new(
        direct.meta,
        logger,
        packet_sink,
        listener,
        direct.override_host,
        direct.override_port,
    )?;
    Ok(instance as Arc<dyn Inbound>)
}
