use std::sync::Arc;

use crate::{
    dns::DnsExecutorHandle,
    error::ProxyError,
    plane::{
        packet::io::{PacketFrame, PacketSessionHandle, PacketWriter},
        stream::io::BoxedAsyncStream,
        types::SessionContext,
    },
    portal::traits::{BoxFuture, Outbound},
    router::RouteReason,
};

use super::support::require_dns_executor;

/// Dispatch-facing outbound capability used by execution planes.
///
/// Stream execution is required. Packet execution remains optional and
/// defaults to a protocol error for outbounds that do not implement it.
pub trait PlaneOutbound: Outbound {
    fn open_stream(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream>;

    fn open_packet(&self, ctx: &SessionContext) -> BoxFuture<'_, PacketSessionHandle> {
        let outbound_tag = self.meta().tag.clone();
        let network = ctx.meta.network;
        Box::pin(async move {
            Err(ProxyError::protocol(format!(
                "outbound '{}' does not support packet execution for {}",
                outbound_tag,
                network.as_str()
            )))
        })
    }
}

pub trait StreamSink: Send + Sync {
    fn submit(&self, inbound_stream: BoxedAsyncStream, ctx: SessionContext) -> BoxFuture<'_, ()>;
}

pub trait PacketSink: Send + Sync {
    fn submit_packet(
        &self,
        packet: PacketFrame,
        writer: Arc<dyn PacketWriter>,
    ) -> BoxFuture<'_, ()>;
}

pub(crate) trait DnsHijack: Send + Sync {
    type Input;

    fn dns_executor(&self) -> Option<&Arc<dyn DnsExecutorHandle>>;

    fn hijack_with_executor(
        &self,
        executor: Arc<dyn DnsExecutorHandle>,
        input: Self::Input,
        route_reason: RouteReason,
    ) -> BoxFuture<'_, ()>;

    fn hijack(&self, input: Self::Input, route_reason: RouteReason) -> BoxFuture<'_, ()> {
        match require_dns_executor(self.dns_executor()) {
            Ok(executor) => self.hijack_with_executor(executor, input, route_reason),
            Err(err) => Box::pin(async move { Err(err) }),
        }
    }
}
