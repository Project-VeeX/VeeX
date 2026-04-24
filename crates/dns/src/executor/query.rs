use veex_core::dns::{DnsRequest, DnsResponse};

use crate::{
    cache::DnsCacheKey, parse_query_info, request::bind_client_upstream_request, rewrite_message_id,
};

use super::{
    CLIENT_QUERY_KIND, DnsExecutor, exchange::CacheStoreContext, logging::QueryFinishContext,
};

impl DnsExecutor {
    pub(super) async fn execute_query_impl(
        &self,
        request: DnsRequest,
    ) -> veex_core::Result<DnsResponse> {
        let query = parse_query_info(&request.raw_message)?;
        let selection = self
            .router
            .select_client_upstream(&query.name, &self.server_routes())?;
        let server = self.lookup_server(&selection.server_tag)?;
        let query_id = self.next_query_id();
        let disable_cache = request.disable_cache || selection.disable_cache;
        let cache_key = DnsCacheKey::new(
            query.name.clone(),
            query.qtype,
            &selection.candidate_server_tags,
        );

        self.log_query_start(&request, &query, &server.server, &selection, query_id);

        if let Some(cached) = self.lookup_cache(
            query_id,
            CLIENT_QUERY_KIND,
            &query.name,
            query.qtype,
            &selection,
            disable_cache,
        ) {
            let response = DnsResponse::new(rewrite_message_id(&cached.raw_message, query.id)?);
            self.on_client_response(&query.name, &response);
            self.log_query_finish(
                QueryFinishContext {
                    request: &request,
                    query: &query,
                    server: &server.server,
                    selection: &selection,
                    query_id,
                    cache_hit: true,
                    winner_server_tag: &cached.stored_server_tag,
                },
                &response,
            );
            return Ok(response);
        }

        let exchange = self
            .exchange_candidates(
                query_id,
                CLIENT_QUERY_KIND,
                &query.name,
                query.qtype,
                &selection,
                |server| bind_client_upstream_request(&request, &server.server, query_id),
                |_server, response| Ok(response.clone()),
            )
            .await;

        match exchange {
            Ok((winner_server_tag, response, _)) => {
                self.maybe_store_cache(
                    CacheStoreContext {
                        query_id,
                        query_kind: CLIENT_QUERY_KIND,
                        cache_key: &cache_key,
                        query_name: &query.name,
                        query_type: query.qtype,
                        disable_cache,
                        winner_server_tag: &winner_server_tag,
                    },
                    &response,
                );
                self.on_client_response(&query.name, &response);
                self.log_query_finish(
                    QueryFinishContext {
                        request: &request,
                        query: &query,
                        server: &server.server,
                        selection: &selection,
                        query_id,
                        cache_hit: false,
                        winner_server_tag: &winner_server_tag,
                    },
                    &response,
                );
                Ok(response)
            }
            Err(err) => {
                self.log_query_failure(
                    &request,
                    &query,
                    &server.server,
                    &selection,
                    query_id,
                    &err,
                );
                Err(err)
            }
        }
    }
}
