use std::net::SocketAddr;

use veex_core::dns::{DnsRequest, ResolveContext};

use crate::{DnsServer, types::upstream_network};

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
    .with_resolution_domain(domain);

    match build_upstream_resolve_context(server, parent_context) {
        Some(context) => request.with_resolve_context(context),
        None => request.with_resolve_context(parent_context.clone()),
    }
}

pub(crate) fn build_upstream_resolve_context(
    server: &DnsServer,
    parent_context: &ResolveContext,
) -> Option<ResolveContext> {
    server.outbound_tag().map(|detour| {
        parent_context.for_dns_upstream_dial(
            detour.to_string(),
            server.tag.clone(),
            server.dial.domain_resolver.clone(),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use veex_core::{
        dns::ResolveContext,
        portal::Dial,
        types::{Destination, Host},
    };

    use crate::types::{DnsServer, DnsServerTransport};

    use super::build_resolution_upstream_request;

    #[test]
    fn resolution_request_keeps_domain_as_control_metadata() {
        let server = DnsServer {
            tag: "bootstrap".into(),
            transport: DnsServerTransport::Udp,
            destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
            dial: Dial {
                detour: None,
                connect_timeout: None,
                routing_mark: None,
                domain_resolver: None,
            },
        };

        let request = build_resolution_upstream_request(
            "resolver.example.com",
            &server,
            &[0x12, 0x34],
            7,
            &ResolveContext::outbound_dial("proxy", None),
        );

        assert_eq!(
            request.resolution_domain.as_deref(),
            Some("resolver.example.com")
        );
        assert_eq!(
            request
                .resolve_context
                .as_ref()
                .and_then(|context| context.caller_outbound_tag.as_deref()),
            Some("direct")
        );
        assert!(request.buffered_payload.is_empty());
    }
}
