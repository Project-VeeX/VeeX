use std::sync::Arc;

use tracing::{info, warn};

use crate::{
    dns::{DnsExecutorHandle, DnsRequest},
    logging::sanitize_field,
    plane::packet::io::{PacketFrame, PacketWriter},
    router::RouteReason,
};

pub(crate) async fn hijack_packet_dns(
    executor: &Arc<dyn DnsExecutorHandle>,
    packet: PacketFrame,
    writer: Arc<dyn PacketWriter>,
    route_reason: RouteReason,
) -> crate::Result<()> {
    let inbound = sanitize_field(&packet.metadata.inbound_tag).into_owned();
    let peer = sanitize_field(&packet.metadata.peer.to_string()).into_owned();
    let destination = sanitize_field(&packet.metadata.destination.to_string()).into_owned();

    info!(
        event = "packet_hijack_dns",
        inbound = %inbound,
        peer = %peer,
        destination = %destination,
        route_reason = %route_reason.as_str(),
        "packet handed off to dns executor"
    );

    let peer_addr = packet.metadata.peer;
    let response = match executor
        .execute_query(DnsRequest::from_packet(packet))
        .await
    {
        Ok(response) => response,
        Err(err) => {
            warn!(
                event = "packet_hijack_dns_failed",
                inbound = %inbound,
                peer = %peer,
                destination = %destination,
                route_reason = %route_reason.as_str(),
                error_kind = ?err.kind(),
                error = %err,
                "dns executor failed"
            );
            return Err(err);
        }
    };

    if let Err(err) = writer.send_to(peer_addr, response.raw_message).await {
        warn!(
            event = "packet_hijack_dns_write_failed",
            inbound = %inbound,
            peer = %peer,
            destination = %destination,
            route_reason = %route_reason.as_str(),
            error_kind = ?err.kind(),
            error = %err,
            "dns response write-back failed"
        );
        return Err(err);
    }

    info!(
        event = "packet_hijack_dns_complete",
        inbound = %inbound,
        peer = %peer,
        destination = %destination,
        route_reason = %route_reason.as_str(),
        "dns response written back to client"
    );
    Ok(())
}
