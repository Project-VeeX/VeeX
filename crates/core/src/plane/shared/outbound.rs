use crate::{
    error::ProxyError,
    plane::{
        packet::forward::PacketSessionHandle, shared::context::SessionContext,
        stream::io::BoxedAsyncStream,
    },
    portal::traits::{BoxFuture, Outbound},
};

/// Dispatch-facing outbound capability used by execution planes.
///
/// Stream execution is required. Packet execution remains optional and
/// defaults to a protocol error for outbounds that do not implement it.
pub trait DispatchOutbound: Outbound {
    fn connect(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream>;

    fn connect_packet(&self, ctx: &SessionContext) -> BoxFuture<'_, PacketSessionHandle> {
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
