use std::sync::Arc;

use crate::{
    dns::DnsExecutorHandle,
    error::ProxyError,
    io::{BoxedAsyncStream, PacketFrame, PacketSessionHandle, PacketWriter},
    portal::traits::{BoxFuture, Outbound},
    routing::RouteReason,
    session::SessionContext,
};

/// Dispatch-facing outbound capability used by the execution layer.
///
/// Stream execution is required. Packet execution remains optional and
/// defaults to a protocol error for outbounds that do not implement it.
pub trait ExecutionOutbound: Outbound {
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

pub trait StreamDispatch: Send + Sync {
    fn dispatch_stream(
        &self,
        inbound_stream: BoxedAsyncStream,
        ctx: SessionContext,
    ) -> BoxFuture<'_, ()>;
}

pub trait PacketDispatch: Send + Sync {
    fn dispatch_packet(
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
        match self.dns_executor().cloned() {
            Some(executor) => self.hijack_with_executor(executor, input, route_reason),
            None => Box::pin(async move {
                Err(ProxyError::config(
                    "route selected 'hijack-dns' but dns executor is not configured",
                ))
            }),
        }
    }
}
