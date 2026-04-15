use std::{fmt, sync::Arc, time::Instant};

use veex_core::{
    BoxedAsyncStream, Destination, Dial, DnsRequest, ExecutionOutbound, Network, OutboundRegistry,
    PacketSessionHandle, ProxyError, SessionContext, SessionMeta,
};

#[derive(Clone)]
pub(crate) struct DnsDialer {
    server_tag: String,
    dial: Dial,
    outbound: Arc<dyn ExecutionOutbound>,
}

impl fmt::Debug for DnsDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsDialer")
            .field("server_tag", &self.server_tag)
            .field("dial", &self.dial)
            .finish()
    }
}

impl DnsDialer {
    pub(crate) fn new(
        server_tag: String,
        dial: Dial,
        outbounds: &Arc<OutboundRegistry>,
    ) -> veex_core::Result<Self> {
        let detour = dial.detour.as_deref().ok_or_else(|| {
            ProxyError::config(format!("missing dns detour for server: {server_tag}"))
        })?;
        let outbound = outbounds.require(detour)?;

        Ok(Self {
            server_tag,
            dial,
            outbound,
        })
    }

    pub(crate) fn detour_tag(&self) -> &str {
        self.dial.detour.as_deref().unwrap_or("")
    }

    pub(crate) fn routing_mark(&self) -> Option<u32> {
        self.dial.routing_mark
    }

    pub(crate) async fn open_packet(
        &self,
        request: &DnsRequest,
        destination: &Destination,
        network: Network,
    ) -> veex_core::Result<PacketSessionHandle> {
        let ctx = self.build_session_context(request, destination.clone(), network);
        self.outbound.open_packet(&ctx).await
    }

    pub(crate) async fn connect_stream(
        &self,
        request: &DnsRequest,
        destination: &Destination,
        network: Network,
    ) -> veex_core::Result<BoxedAsyncStream> {
        let ctx = self.build_session_context(request, destination.clone(), network);
        self.outbound.open_stream(&ctx).await
    }

    fn build_session_context(
        &self,
        request: &DnsRequest,
        destination: Destination,
        network: Network,
    ) -> SessionContext {
        let mut ctx = SessionContext::new(
            SessionMeta {
                id: request.session_id.unwrap_or_default(),
                network,
                inbound_tag: request.inbound_tag.clone(),
                peer: request.peer,
                destination,
                start: Instant::now(),
            },
            request.buffered_payload.clone(),
        );
        ctx.set_resolve_context(request.resolve_context.clone());
        ctx
    }
}
