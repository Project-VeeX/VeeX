use std::{collections::HashMap, sync::Arc};

use tokio::{sync::mpsc, task::JoinHandle};
use tracing::warn;
use veex_core::{
    ErrorKind, ProxyError,
    dns::{DnsRequest, DnsResponse},
    logging::sanitize_field,
};

use crate::{
    cache::{DnsCacheKey, DnsCacheLookup, DnsCacheValue},
    parse_response_min_ttl,
    types::DnsSelection,
};

use super::{DnsExecutor, RESOLVE_QUERY_KIND, runtime::DnsServerRuntime};

impl DnsExecutor {
    pub(super) fn lookup_cache(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        disable_cache: bool,
    ) -> Option<DnsCacheValue> {
        let cache_key = DnsCacheKey::new(
            query_name.to_string(),
            query_type,
            &selection.candidate_server_tags,
        );

        if !self.cache_enabled || disable_cache {
            self.log_cache_bypass(query_id, query_kind, query_name, query_type, selection);
            return None;
        }

        self.log_cache_lookup(query_id, query_kind, query_name, query_type, selection);
        let result = self
            .cache
            .lock()
            .expect("dns cache lock poisoned")
            .lookup(&cache_key);
        match result {
            DnsCacheLookup::Hit(value) => {
                self.log_cache_hit(
                    query_id, query_kind, query_name, query_type, selection, &value,
                );
                Some(value)
            }
            DnsCacheLookup::Miss => {
                self.log_cache_miss(query_id, query_kind, query_name, query_type, selection);
                None
            }
            DnsCacheLookup::Expired => {
                self.log_cache_expired(query_id, query_kind, query_name, query_type, selection);
                None
            }
        }
    }

    pub(super) fn maybe_store_cache(
        &self,
        query_id: u64,
        query_kind: &str,
        cache_key: &DnsCacheKey,
        query_name: &str,
        query_type: u16,
        disable_cache: bool,
        winner_server_tag: &str,
        response: &DnsResponse,
    ) {
        if !self.cache_enabled || disable_cache {
            return;
        }

        let ttl = match parse_response_min_ttl(&response.raw_message, query_type) {
            Ok(Some(ttl)) => ttl,
            Ok(None) => return,
            Err(err) => {
                warn!(
                    event = "dns_cache_store_skipped",
                    query_id,
                    query_kind = %query_kind,
                    query_name = %sanitize_field(query_name),
                    query_type = query_type as u64,
                    error_kind = ?err.kind(),
                    error = %err,
                    "dns cache store skipped due to uncacheable response"
                );
                return;
            }
        };

        self.cache.lock().expect("dns cache lock poisoned").store(
            cache_key.clone(),
            response.raw_message.clone(),
            ttl,
            winner_server_tag.to_string(),
        );
        self.log_cache_store(
            query_id,
            query_kind,
            query_name,
            query_type,
            &cache_key.selection_scope,
            winner_server_tag,
            ttl,
        );
    }

    pub(super) async fn exchange_candidates<T, BuildRequest, Validate>(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        build_request: BuildRequest,
        mut validate: Validate,
    ) -> veex_core::Result<(String, DnsResponse, T)>
    where
        BuildRequest: Fn(&DnsServerRuntime) -> DnsRequest,
        Validate: FnMut(&DnsServerRuntime, &DnsResponse) -> veex_core::Result<T>,
    {
        let candidates = self.lookup_candidate_servers(&selection.candidate_server_tags)?;
        if candidates.is_empty() {
            return Err(ProxyError::config(
                "dns selection produced no upstream candidates",
            ));
        }

        if candidates.len() == 1 {
            let server = candidates[0];
            self.log_upstream_query_start(
                query_id, query_kind, query_name, query_type, selection, server,
            );
            let response = server.upstream.exchange(build_request(server)).await;
            return match response {
                Ok(response) => match validate(server, &response) {
                    Ok(validated) => {
                        self.log_upstream_query_won(
                            query_id, query_kind, query_name, query_type, selection, server, false,
                        );
                        Ok((server.server.tag.clone(), response, validated))
                    }
                    Err(err) => {
                        self.log_upstream_query_failed(
                            query_id, query_kind, query_name, query_type, selection, server, &err,
                        );
                        Err(err)
                    }
                },
                Err(err) => {
                    self.log_upstream_query_failed(
                        query_id, query_kind, query_name, query_type, selection, server, &err,
                    );
                    Err(err)
                }
            };
        }

        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handles = HashMap::<String, JoinHandle<()>>::new();
        let mut server_by_tag = HashMap::<String, &DnsServerRuntime>::new();
        for server in candidates {
            self.log_upstream_query_start(
                query_id, query_kind, query_name, query_type, selection, server,
            );
            let tag = server.server.tag.clone();
            let upstream = Arc::clone(&server.upstream);
            let request = build_request(server);
            let tx = tx.clone();
            server_by_tag.insert(tag.clone(), server);
            handles.insert(
                tag.clone(),
                tokio::spawn(async move {
                    let result = upstream.exchange(request).await;
                    let _ = tx.send((tag, result));
                }),
            );
        }
        drop(tx);

        let mut failure_messages = Vec::new();
        let mut last_error = None;
        while let Some((tag, result)) = rx.recv().await {
            handles.remove(&tag);
            let server = server_by_tag
                .remove(&tag)
                .expect("dns candidate server should still exist");

            match result {
                Ok(response) => match validate(server, &response) {
                    Ok(validated) => {
                        self.log_upstream_query_won(
                            query_id, query_kind, query_name, query_type, selection, server, true,
                        );
                        for (pending_tag, handle) in handles {
                            handle.abort();
                            if let Some(pending_server) = server_by_tag.get(&pending_tag) {
                                self.log_upstream_query_cancelled(
                                    query_id,
                                    query_kind,
                                    query_name,
                                    query_type,
                                    selection,
                                    pending_server,
                                );
                            }
                        }
                        return Ok((tag, response, validated));
                    }
                    Err(err) => {
                        self.log_upstream_query_failed(
                            query_id, query_kind, query_name, query_type, selection, server, &err,
                        );
                        failure_messages.push(format!("{}: {}", server.server.tag, err));
                        last_error = Some(err);
                    }
                },
                Err(err) => {
                    self.log_upstream_query_failed(
                        query_id, query_kind, query_name, query_type, selection, server, &err,
                    );
                    failure_messages.push(format!("{}: {}", server.server.tag, err));
                    last_error = Some(err);
                }
            }
        }

        Err(self.aggregate_all_failed_error(
            query_kind,
            query_name,
            &selection.candidate_server_tags,
            failure_messages,
            last_error,
        ))
    }

    fn aggregate_all_failed_error(
        &self,
        query_kind: &str,
        query_name: &str,
        candidate_server_tags: &[String],
        failure_messages: Vec<String>,
        last_error: Option<ProxyError>,
    ) -> ProxyError {
        let failures = if failure_messages.is_empty() {
            "no upstream failure details were captured".to_string()
        } else {
            failure_messages.join("; ")
        };
        let message = format!(
            "all dns upstream queries failed for {query_kind} '{query_name}' across candidates [{}]: {failures}",
            candidate_server_tags.join(",")
        );
        match last_error.as_ref().map(ProxyError::kind) {
            Some(kind) => proxy_error_with_kind(kind, message),
            None if query_kind == RESOLVE_QUERY_KIND => ProxyError::resolve(message),
            None => ProxyError::protocol(message),
        }
    }
}

fn proxy_error_with_kind(kind: ErrorKind, message: String) -> ProxyError {
    match kind {
        ErrorKind::Config => ProxyError::config(message),
        ErrorKind::Dial => ProxyError::dial(message),
        ErrorKind::Resolve => ProxyError::resolve(message),
        ErrorKind::Tls => ProxyError::tls(message),
        ErrorKind::Protocol => ProxyError::protocol(message),
        ErrorKind::Relay => ProxyError::relay(message),
        ErrorKind::Timeout => ProxyError::timeout(message),
        ErrorKind::Io | ErrorKind::Shutdown => ProxyError::protocol(message),
    }
}
