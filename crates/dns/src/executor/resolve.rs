use std::net::SocketAddr;

use veex_core::{ProxyError, dns::ResolveContext, types::Host};

use crate::{
    build_a_query, cache::DnsCacheKey, parse_query_info, parse_response_ips,
    request::build_resolution_upstream_request,
};

use super::{DnsExecutor, MAX_DNS_RECURSION_DEPTH, RESOLVE_QUERY_KIND};

impl DnsExecutor {
    pub(super) async fn resolve_host_impl(
        &self,
        host: Host,
        port: u16,
        context: ResolveContext,
    ) -> veex_core::Result<Vec<SocketAddr>> {
        match host {
            Host::Ip(ip) => Ok(vec![SocketAddr::new(ip, port)]),
            Host::Domain(domain) => self.resolve_domain_impl(domain, port, context).await,
        }
    }

    pub(super) async fn resolve_domain_impl(
        &self,
        domain: String,
        port: u16,
        context: ResolveContext,
    ) -> veex_core::Result<Vec<SocketAddr>> {
        if context.recursion_depth >= MAX_DNS_RECURSION_DEPTH {
            return Err(ProxyError::resolve(format!(
                "domain resolver recursion depth exceeded for {domain}:{} at depth {}",
                port, context.recursion_depth
            )));
        }

        let selection = self
            .router
            .select_resolution_upstream(&context, &self.server_routes())?
            .ok_or_else(|| {
                ProxyError::resolve(format!(
                    "no safe dns server available for dial-side resolution of {domain}"
                ))
            })?;
        let server = self.lookup_server(&selection.server_tag)?;
        let query_id = self.next_query_id();
        let raw_query = build_a_query(&domain, query_id as u16)?;
        let query = parse_query_info(&raw_query)?;
        let cache_key = DnsCacheKey::new(
            query.name.clone(),
            query.qtype,
            &selection.candidate_server_tags,
        );

        self.log_domain_resolve_start(
            &domain,
            port,
            &server.server,
            &selection,
            query_id,
            &context,
        );

        if let Some(cached) = self.lookup_cache(
            query_id,
            RESOLVE_QUERY_KIND,
            &query.name,
            query.qtype,
            &selection,
            context.disable_cache,
        ) {
            let addresses = parse_response_ips(&cached.raw_message)?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect::<Vec<_>>();
            self.log_domain_resolve_success(
                &domain,
                port,
                &server.server,
                &selection,
                query_id,
                &context,
                &addresses,
            );
            return Ok(addresses);
        }

        let exchange = self
            .exchange_candidates(
                query_id,
                RESOLVE_QUERY_KIND,
                &query.name,
                query.qtype,
                &selection,
                |server| {
                    build_resolution_upstream_request(
                        &domain,
                        &server.server,
                        &raw_query,
                        query_id,
                        &context,
                    )
                },
                |_server, response| {
                    Ok(parse_response_ips(&response.raw_message)?
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect::<Vec<_>>())
                },
            )
            .await;

        match exchange {
            Ok((winner_server_tag, response, addresses)) => {
                self.maybe_store_cache(
                    query_id,
                    RESOLVE_QUERY_KIND,
                    &cache_key,
                    &query.name,
                    query.qtype,
                    context.disable_cache,
                    &winner_server_tag,
                    &response,
                );
                self.log_domain_resolve_success(
                    &domain,
                    port,
                    &server.server,
                    &selection,
                    query_id,
                    &context,
                    &addresses,
                );
                Ok(addresses)
            }
            Err(err) => {
                self.log_domain_resolve_failure(
                    &domain,
                    port,
                    &server.server,
                    &selection,
                    query_id,
                    &context,
                    &err,
                );
                Err(err)
            }
        }
    }
}
