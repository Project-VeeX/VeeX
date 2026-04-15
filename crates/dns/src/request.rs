use std::net::SocketAddr;

use veex_core::{DnsRequest, ResolveContext};

use crate::{types::upstream_network, DnsServer};

pub(crate) fn bind_client_upstream_request(
    request: &DnsRequest,
    server: &DnsServer,
    query_id: u64,
) -> DnsRequest {
    let request = request.clone().with_session_id(query_id);

    match build_upstream_resolve_context(server, &ResolveContext::client_query()) {
        Some(context) => request.with_resolve_context(context),
        None => request,
    }
}

pub(crate) fn build_resolution_upstream_request(
    domain: &str,
    server: &DnsServer,
    query: &[u8],
    query_id: u64,
    parent_context: &ResolveContext,
) -> DnsRequest {
    let request = DnsRequest::new(
        query.to_vec(),
        upstream_network(&server.transport),
        "dns-resolver",
        SocketAddr::from(([127, 0, 0, 1], 0)),
        server.destination.clone(),
    )
    .with_session_id(query_id)
    .with_buffered_payload(domain.as_bytes().to_vec());

    match build_upstream_resolve_context(server, parent_context) {
        Some(context) => request.with_resolve_context(context),
        None => request.with_resolve_context(parent_context.clone()),
    }
}

pub(crate) fn build_upstream_resolve_context(
    server: &DnsServer,
    parent_context: &ResolveContext,
) -> Option<ResolveContext> {
    server.dial.detour.as_ref().map(|detour| {
        parent_context.for_dns_upstream_dial(
            detour.clone(),
            server.tag.clone(),
            server.dial.domain_resolver.clone(),
        )
    })
}
