use std::{future::Future, pin::Pin, sync::Arc};

use veex_core::{
    dns::DnsExecutorHandle,
    io::{BoxedAsyncStream, PacketFrame, PacketSessionHandle, PacketWriter},
    session::SessionContext,
    ProxyError,
};
use veex_router::RouteReason;

pub type ExecutionFuture<'a, T> = Pin<Box<dyn Future<Output = veex_core::Result<T>> + Send + 'a>>;

/// Dispatch-facing outbound capability used by the execution layer.
///
/// Stream execution is required. Packet execution remains optional and
/// defaults to a protocol error for outbounds that do not implement it.
pub trait ExecutionOutbound: Send + Sync {
    fn tag(&self) -> &str;

    fn open_stream(&self, ctx: &SessionContext) -> ExecutionFuture<'_, BoxedAsyncStream>;

    fn open_packet(&self, ctx: &SessionContext) -> ExecutionFuture<'_, PacketSessionHandle> {
        let outbound_tag = self.tag().to_string();
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
    ) -> ExecutionFuture<'_, ()>;
}

pub trait PacketDispatch: Send + Sync {
    fn dispatch_packet(
        &self,
        packet: PacketFrame,
        writer: Arc<dyn PacketWriter>,
    ) -> ExecutionFuture<'_, ()>;
}

pub(crate) trait DnsHijack: Send + Sync {
    type Input;

    fn dns_executor(&self) -> Option<&Arc<dyn DnsExecutorHandle>>;

    fn hijack_with_executor(
        &self,
        executor: Arc<dyn DnsExecutorHandle>,
        input: Self::Input,
        route_reason: RouteReason,
    ) -> ExecutionFuture<'_, ()>;

    fn hijack(&self, input: Self::Input, route_reason: RouteReason) -> ExecutionFuture<'_, ()> {
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
