use std::{fmt, net::SocketAddr, sync::Arc, time::Instant};

use veex_core::{
    BoxedAsyncStream, Destination, Dial, DnsRequest, ExecutionOutbound, Network, OutboundRegistry,
    PacketSessionHandle, ProxyError, ResolveContext, SessionContext, SessionMeta,
};
use veex_transport::{connect_tls_stream, ConnectTraceContext, TlsClientOptions};

use crate::{types::upstream_network, DnsServer};

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

    pub(crate) fn bind_client_request(&self, request: &DnsRequest, query_id: u64) -> DnsRequest {
        request
            .clone()
            .with_session_id(query_id)
            .with_resolve_context(self.upstream_resolve_context(ResolveContext::client_query()))
    }

    pub(crate) fn bind_resolution_request(
        &self,
        domain: &str,
        server: &DnsServer,
        query: &[u8],
        query_id: u64,
        parent_context: &ResolveContext,
    ) -> DnsRequest {
        DnsRequest::new(
            query.to_vec(),
            upstream_network(&server.transport),
            "dns-resolver",
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server.destination.clone(),
        )
        .with_session_id(query_id)
        .with_resolve_context(self.upstream_resolve_context(parent_context.clone()))
        .with_buffered_payload(domain.as_bytes().to_vec())
    }

    pub(crate) async fn open_packet(
        &self,
        request: &DnsRequest,
        destination: &Destination,
        network: Network,
    ) -> veex_core::Result<PacketSessionHandle> {
        let ctx = build_request_context(request, destination.clone(), network);
        self.outbound.open_packet(&ctx).await
    }

    pub(crate) async fn connect_stream(
        &self,
        request: &DnsRequest,
        destination: &Destination,
        network: Network,
    ) -> veex_core::Result<BoxedAsyncStream> {
        let ctx = build_request_context(request, destination.clone(), network);
        self.outbound.open_stream(&ctx).await
    }

    pub(crate) async fn connect_tls(
        &self,
        stream: BoxedAsyncStream,
        destination: &Destination,
        tls: &TlsClientOptions,
        request: &DnsRequest,
    ) -> veex_core::Result<BoxedAsyncStream> {
        let trace = ConnectTraceContext {
            session_id: request.session_id.unwrap_or_default(),
            outbound: self.detour_tag().to_string(),
            routing_mark: self.dial.routing_mark,
        };
        connect_tls_stream(
            stream,
            &destination.host,
            destination.port,
            tls,
            Some(&trace),
        )
        .await
    }

    fn upstream_resolve_context(&self, parent: ResolveContext) -> ResolveContext {
        parent.for_dns_upstream_dial(
            self.detour_tag().to_string(),
            self.server_tag.clone(),
            self.dial.domain_resolver.clone(),
        )
    }
}

fn build_request_context(
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
