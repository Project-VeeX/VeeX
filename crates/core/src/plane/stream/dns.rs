use std::sync::Arc;

use tracing::{info, warn};

use crate::{
    dns::{read_dns_tcp_message, write_dns_tcp_message, DnsExecutorHandle, DnsRequest},
    logging::sanitize_field,
    plane::{stream::io::BoxedAsyncStream, types::SessionContext},
    router::RouteReason,
};

pub(crate) async fn hijack_stream_dns(
    executor: &Arc<dyn DnsExecutorHandle>,
    mut inbound_stream: BoxedAsyncStream,
    ctx: SessionContext,
    route_reason: RouteReason,
) -> crate::Result<()> {
    let inbound = sanitize_field(ctx.meta.inbound_tag.as_str()).into_owned();
    let peer = sanitize_field(&ctx.meta.peer.to_string()).into_owned();
    let destination = sanitize_field(&ctx.meta.destination.to_string()).into_owned();

    info!(
        event = "stream_hijack_dns",
        session_id = ctx.meta.id,
        inbound = %inbound,
        peer = %peer,
        destination = %destination,
        route_reason = %route_reason.as_str(),
        "stream handed off to dns executor"
    );

    loop {
        let query = match read_dns_tcp_message(&mut *inbound_stream).await {
            Ok(Some(query)) => query,
            Ok(None) => break,
            Err(err) => {
                warn!(
                    event = "stream_hijack_dns_failed",
                    session_id = ctx.meta.id,
                    inbound = %inbound,
                    peer = %peer,
                    destination = %destination,
                    route_reason = %route_reason.as_str(),
                    error_kind = ?err.kind(),
                    error = %err,
                    "dns over tcp ingress read failed"
                );
                return Err(err);
            }
        };

        let request = DnsRequest::new(
            query,
            ctx.meta.network,
            ctx.meta.inbound_tag.clone(),
            ctx.meta.peer,
            ctx.meta.destination.clone(),
        );
        let response = match executor.execute_query(request).await {
            Ok(response) => response,
            Err(err) => {
                warn!(
                    event = "stream_hijack_dns_failed",
                    session_id = ctx.meta.id,
                    inbound = %inbound,
                    peer = %peer,
                    destination = %destination,
                    route_reason = %route_reason.as_str(),
                    error_kind = ?err.kind(),
                    error = %err,
                    "dns executor failed for stream ingress"
                );
                return Err(err);
            }
        };

        if let Err(err) = write_dns_tcp_message(&mut *inbound_stream, &response.raw_message).await {
            warn!(
                event = "stream_hijack_dns_write_failed",
                session_id = ctx.meta.id,
                inbound = %inbound,
                peer = %peer,
                destination = %destination,
                route_reason = %route_reason.as_str(),
                error_kind = ?err.kind(),
                error = %err,
                "dns over tcp response write failed"
            );
            return Err(err);
        }
    }

    info!(
        event = "stream_hijack_dns_complete",
        session_id = ctx.meta.id,
        inbound = %inbound,
        peer = %peer,
        destination = %destination,
        route_reason = %route_reason.as_str(),
        "stream dns handoff completed"
    );
    Ok(())
}
