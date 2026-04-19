use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{info, warn};
use veex_core::{
    ErrorKind,
    ProxyError,
    dns::{DnsExecutorHandle, DnsRequest, DnsResponse, DomainResolverHandle, ResolveContext},
    logging::sanitize_field,
    portal::BoxFuture,
    types::Host,
};
use veex_execution::OutboundCatalog;

use crate::{
    build_a_query,
    cache::{DnsCache, DnsCacheKey, DnsCacheLookup, DnsCacheValue},
    parse_query_info, parse_response_ips, parse_response_min_ttl, rewrite_message_id,
    request::{bind_client_upstream_request, build_resolution_upstream_request},
    router::{DnsRouter, DnsServerRoute},
    traits::DnsUpstream,
    types::{DnsRuntimeConfig, DnsSelection, DnsServer, DnsServerTransport},
    upstream::build_upstream,
};

const DEFAULT_DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_RECURSION_DEPTH: u8 = 4;
const CLIENT_QUERY_KIND: &str = "client_query";
const RESOLVE_QUERY_KIND: &str = "dial_side_resolve";

struct DnsServerRuntime {
    server: DnsServer,
    upstream: Arc<dyn DnsUpstream>,
}

impl DnsServerRuntime {
    fn new(
        server: DnsServer,
        outbounds: &Arc<OutboundCatalog>,
        query_timeout: Duration,
    ) -> veex_core::Result<Self> {
        let dialer = match &server.transport {
            DnsServerTransport::Unsupported(_) => None,
            _ => Some(crate::dialer::DnsDialer::new(
                server.tag.clone(),
                server.dial.clone(),
                outbounds,
            )?),
        };
        let upstream = build_upstream(&server, dialer.clone(), query_timeout)?;
        Ok(Self { server, upstream })
    }
}

pub struct DnsExecutor {
    router: DnsRouter,
    servers: HashMap<String, DnsServerRuntime>,
    cache_enabled: bool,
    cache: Mutex<DnsCache>,
    next_query_id: AtomicU64,
}

impl DnsExecutor {
    pub fn new(
        config: DnsRuntimeConfig,
        outbounds: Arc<OutboundCatalog>,
    ) -> veex_core::Result<Self> {
        let query_timeout = DEFAULT_DNS_QUERY_TIMEOUT;
        let mut servers = HashMap::new();
        for server in config.servers {
            let tag = server.tag.clone();
            let runtime = DnsServerRuntime::new(server, &outbounds, query_timeout)?;
            if servers.insert(tag, runtime).is_some() {
                return Err(ProxyError::config("duplicate dns server tag in runtime"));
            }
        }

        Ok(Self {
            router: DnsRouter::new(config.final_server_tag, config.rules),
            servers,
            cache_enabled: !config.disable_cache,
            cache: Mutex::new(DnsCache::new(config.cache_capacity)),
            next_query_id: AtomicU64::new(1),
        })
    }

    fn next_query_id(&self) -> u64 {
        self.next_query_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn execute_query_impl(&self, request: DnsRequest) -> veex_core::Result<DnsResponse> {
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
                &request,
                &query,
                &server.server,
                &selection,
                query_id,
                &response,
                true,
                &cached.stored_server_tag,
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
                    query_id,
                    CLIENT_QUERY_KIND,
                    &cache_key,
                    &query.name,
                    query.qtype,
                    disable_cache,
                    &winner_server_tag,
                    &response,
                );
                self.on_client_response(&query.name, &response);
                self.log_query_finish(
                    &request,
                    &query,
                    &server.server,
                    &selection,
                    query_id,
                    &response,
                    false,
                    &winner_server_tag,
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

    async fn resolve_host_impl(
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

    async fn resolve_domain_impl(
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

    fn lookup_cache(
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
                self.log_cache_hit(query_id, query_kind, query_name, query_type, selection, &value);
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

    fn maybe_store_cache(
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

    async fn exchange_candidates<T, BuildRequest, Validate>(
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
            return Err(ProxyError::config("dns selection produced no upstream candidates"));
        }

        if candidates.len() == 1 {
            let server = candidates[0];
            self.log_upstream_query_start(query_id, query_kind, query_name, query_type, selection, server);
            let response = server.upstream.exchange(build_request(server)).await;
            return match response {
                Ok(response) => match validate(server, &response) {
                    Ok(validated) => {
                        self.log_upstream_query_won(
                            query_id,
                            query_kind,
                            query_name,
                            query_type,
                            selection,
                            server,
                            false,
                        );
                        Ok((server.server.tag.clone(), response, validated))
                    }
                    Err(err) => {
                        self.log_upstream_query_failed(
                            query_id,
                            query_kind,
                            query_name,
                            query_type,
                            selection,
                            server,
                            &err,
                        );
                        Err(err)
                    }
                },
                Err(err) => {
                    self.log_upstream_query_failed(
                        query_id,
                        query_kind,
                        query_name,
                        query_type,
                        selection,
                        server,
                        &err,
                    );
                    Err(err)
                }
            };
        }

        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handles = HashMap::<String, JoinHandle<()>>::new();
        let mut server_by_tag = HashMap::<String, &DnsServerRuntime>::new();
        for server in candidates {
            self.log_upstream_query_start(query_id, query_kind, query_name, query_type, selection, server);
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
                            query_id,
                            query_kind,
                            query_name,
                            query_type,
                            selection,
                            server,
                            true,
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
                            query_id,
                            query_kind,
                            query_name,
                            query_type,
                            selection,
                            server,
                            &err,
                        );
                        failure_messages.push(format!("{}: {}", server.server.tag, err));
                        last_error = Some(err);
                    }
                },
                Err(err) => {
                    self.log_upstream_query_failed(
                        query_id,
                        query_kind,
                        query_name,
                        query_type,
                        selection,
                        server,
                        &err,
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

    fn lookup_candidate_servers(
        &self,
        candidate_server_tags: &[String],
    ) -> veex_core::Result<Vec<&DnsServerRuntime>> {
        candidate_server_tags
            .iter()
            .map(|tag| self.lookup_server(tag))
            .collect()
    }

    fn log_cache_lookup(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
    ) {
        info!(
            event = "dns_cache_lookup",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            route_reason = %selection.reason.as_str(),
            selection_scope = %sanitize_field(&selection.candidate_server_tags.join(",")),
            "dns cache lookup started"
        );
    }

    fn log_cache_hit(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        value: &DnsCacheValue,
    ) {
        info!(
            event = "dns_cache_hit",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            route_reason = %selection.reason.as_str(),
            selection_scope = %sanitize_field(&selection.candidate_server_tags.join(",")),
            winner_server = %sanitize_field(&value.stored_server_tag),
            ttl_secs = value.ttl.as_secs(),
            "dns cache hit"
        );
    }

    fn log_cache_miss(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
    ) {
        info!(
            event = "dns_cache_miss",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            route_reason = %selection.reason.as_str(),
            selection_scope = %sanitize_field(&selection.candidate_server_tags.join(",")),
            "dns cache miss"
        );
    }

    fn log_cache_expired(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
    ) {
        info!(
            event = "dns_cache_expired",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            route_reason = %selection.reason.as_str(),
            selection_scope = %sanitize_field(&selection.candidate_server_tags.join(",")),
            "dns cache entry expired"
        );
    }

    fn log_cache_bypass(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
    ) {
        info!(
            event = "dns_cache_bypass",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            route_reason = %selection.reason.as_str(),
            selection_scope = %sanitize_field(&selection.candidate_server_tags.join(",")),
            "dns cache bypassed for this query"
        );
    }

    fn log_cache_store(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection_scope: &str,
        winner_server_tag: &str,
        ttl: Duration,
    ) {
        info!(
            event = "dns_cache_store",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            selection_scope = %sanitize_field(selection_scope),
            winner_server = %sanitize_field(winner_server_tag),
            ttl_secs = ttl.as_secs(),
            "dns cache entry stored"
        );
    }

    fn log_upstream_query_start(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        server: &DnsServerRuntime,
    ) {
        info!(
            event = "dns_upstream_query_start",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            selected_server = %sanitize_field(&selection.server_tag),
            server = %sanitize_field(&server.server.tag),
            detour = %sanitize_field(server.server.detour_tag()),
            transport = %server.server.transport.as_str(),
            route_reason = %selection.reason.as_str(),
            candidate_count = selection.candidate_server_tags.len() as u64,
            "dns upstream query started"
        );
    }

    fn log_upstream_query_won(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        server: &DnsServerRuntime,
        concurrent: bool,
    ) {
        info!(
            event = "dns_upstream_query_won",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            selected_server = %sanitize_field(&selection.server_tag),
            server = %sanitize_field(&server.server.tag),
            route_reason = %selection.reason.as_str(),
            concurrent,
            "dns upstream query produced the winning response"
        );
    }

    fn log_upstream_query_cancelled(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        server: &DnsServerRuntime,
    ) {
        info!(
            event = "dns_upstream_query_cancelled",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            selected_server = %sanitize_field(&selection.server_tag),
            server = %sanitize_field(&server.server.tag),
            route_reason = %selection.reason.as_str(),
            "dns upstream query cancelled after another winner was selected"
        );
    }

    fn log_upstream_query_failed(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        server: &DnsServerRuntime,
        err: &ProxyError,
    ) {
        warn!(
            event = "dns_upstream_query_failed",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            selected_server = %sanitize_field(&selection.server_tag),
            server = %sanitize_field(&server.server.tag),
            route_reason = %selection.reason.as_str(),
            error_kind = ?err.kind(),
            error = %err,
            "dns upstream query failed"
        );
    }

    fn server_routes(&self) -> Vec<DnsServerRoute<'_>> {
        self.servers
            .values()
            .map(|server| DnsServerRoute {
                tag: server.server.tag.as_str(),
                detour: server.server.outbound_tag(),
            })
            .collect()
    }

    fn lookup_server(&self, server_tag: &str) -> veex_core::Result<&DnsServerRuntime> {
        self.servers
            .get(server_tag)
            .ok_or_else(|| ProxyError::config(format!("missing dns server tag: {server_tag}")))
    }

    fn log_query_start(
        &self,
        request: &DnsRequest,
        query: &crate::wire::DnsQueryInfo,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
    ) {
        info!(
            event = "dns_query_start",
            query_id,
            inbound = %sanitize_field(&request.inbound_tag),
            ingress_protocol = %request.protocol.as_str(),
            query_name = %sanitize_field(&query.name),
            query_type = query.qtype as u64,
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            destination = %sanitize_field(&server.destination.to_string()),
            route_reason = %selection.reason.as_str(),
            candidate_count = selection.candidate_server_tags.len() as u64,
            transport = %server.transport.as_str(),
            "dns query started"
        );
    }

    fn on_client_response(&self, _query_name: &str, _response: &DnsResponse) {
        // Reserved for a future reverse_mapping side effect. This remains a no-op
        // until the DNS subsystem grows an explicit reverse map store.
    }

    fn log_query_finish(
        &self,
        request: &DnsRequest,
        query: &crate::wire::DnsQueryInfo,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        response: &DnsResponse,
        cache_hit: bool,
        winner_server_tag: &str,
    ) {
        info!(
            event = "dns_query_finish",
            query_id,
            inbound = %sanitize_field(&request.inbound_tag),
            ingress_protocol = %request.protocol.as_str(),
            query_name = %sanitize_field(&query.name),
            query_type = query.qtype as u64,
            server = %sanitize_field(&server.tag),
            winner_server = %sanitize_field(winner_server_tag),
            detour = %sanitize_field(server.detour_tag()),
            destination = %sanitize_field(&server.destination.to_string()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            cache_hit,
            response_bytes = response.raw_message.len() as u64,
            "dns query finished"
        );
        info!(
            event = "dns_query_success",
            query_id,
            inbound = %sanitize_field(&request.inbound_tag),
            ingress_protocol = %request.protocol.as_str(),
            query_name = %sanitize_field(&query.name),
            query_type = query.qtype as u64,
            server = %sanitize_field(&server.tag),
            winner_server = %sanitize_field(winner_server_tag),
            detour = %sanitize_field(server.detour_tag()),
            destination = %sanitize_field(&server.destination.to_string()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            cache_hit,
            response_bytes = response.raw_message.len() as u64,
            "dns query succeeded"
        );
    }

    fn log_query_failure(
        &self,
        request: &DnsRequest,
        query: &crate::wire::DnsQueryInfo,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        err: &ProxyError,
    ) {
        warn!(
            event = "dns_query_failed",
            query_id,
            inbound = %sanitize_field(&request.inbound_tag),
            ingress_protocol = %request.protocol.as_str(),
            query_name = %sanitize_field(&query.name),
            query_type = query.qtype as u64,
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            destination = %sanitize_field(&server.destination.to_string()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            error_kind = ?err.kind(),
            error = %err,
            "dns upstream receive failed"
        );
    }

    fn log_domain_resolve_start(
        &self,
        domain: &str,
        port: u16,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        context: &ResolveContext,
    ) {
        info!(
            event = "domain_resolve_start",
            query_id,
            domain = %sanitize_field(domain),
            port,
            purpose = %context.purpose.as_str(),
            recursion_depth = context.recursion_depth as u64,
            caller_outbound = %sanitize_field(context.caller_outbound_tag.as_deref().unwrap_or("")),
            caller_dns_server = %sanitize_field(context.caller_dns_server_tag.as_deref().unwrap_or("")),
            explicit_server = %sanitize_field(context.explicit_server_tag.as_deref().unwrap_or("")),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            "dial-side domain resolution started"
        );
    }

    fn log_domain_resolve_success(
        &self,
        domain: &str,
        port: u16,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        context: &ResolveContext,
        addresses: &[SocketAddr],
    ) {
        let addresses_field = addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        info!(
            event = "domain_resolve_success",
            query_id,
            domain = %sanitize_field(domain),
            port,
            purpose = %context.purpose.as_str(),
            recursion_depth = context.recursion_depth as u64,
            caller_outbound = %sanitize_field(context.caller_outbound_tag.as_deref().unwrap_or("")),
            caller_dns_server = %sanitize_field(context.caller_dns_server_tag.as_deref().unwrap_or("")),
            explicit_server = %sanitize_field(context.explicit_server_tag.as_deref().unwrap_or("")),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            resolved_addrs = %sanitize_field(&addresses_field),
            "dial-side domain resolution succeeded"
        );
    }

    fn log_domain_resolve_failure(
        &self,
        domain: &str,
        port: u16,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        context: &ResolveContext,
        err: &ProxyError,
    ) {
        warn!(
            event = "domain_resolve_failed",
            query_id,
            domain = %sanitize_field(domain),
            port,
            purpose = %context.purpose.as_str(),
            recursion_depth = context.recursion_depth as u64,
            caller_outbound = %sanitize_field(context.caller_outbound_tag.as_deref().unwrap_or("")),
            caller_dns_server = %sanitize_field(context.caller_dns_server_tag.as_deref().unwrap_or("")),
            explicit_server = %sanitize_field(context.explicit_server_tag.as_deref().unwrap_or("")),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            error_kind = ?err.kind(),
            error = %err,
            "dial-side domain resolution failed"
        );
    }
}

impl DnsExecutorHandle for DnsExecutor {
    fn execute_query(&self, request: DnsRequest) -> BoxFuture<'_, DnsResponse> {
        Box::pin(async move { self.execute_query_impl(request).await })
    }
}

impl DomainResolverHandle for DnsExecutor {
    fn resolve_host(
        &self,
        host: Host,
        port: u16,
        context: ResolveContext,
    ) -> BoxFuture<'_, Vec<SocketAddr>> {
        Box::pin(async move { self.resolve_host_impl(host, port, context).await })
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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use tokio::sync::{Mutex, mpsc};
    use veex_core::{
        ProxyError,
        dns::{DnsExecutorHandle, DnsRequest, DomainResolverHandle, ResolveContext},
        io::{BoxedAsyncStream, PacketSession, PacketSessionHandle},
        logging::Logger,
        portal::{BoxFuture, Dial, Outbound, OutboundMeta},
        session::SessionContext,
        types::{Destination, Host, Network},
    };
    use veex_execution::{ExecutionFuture, ExecutionOutbound, OutboundCatalog};
    use veex_test_tracing::{assert_has_event, captured_events, install_test_subscriber};

    use crate::{
        DEFAULT_DNS_CACHE_CAPACITY, build_a_query, parse_response_ips,
        types::{DnsRule, DnsRuntimeConfig, DnsServer, DnsServerTransport},
    };

    use super::{DnsExecutor, MAX_DNS_RECURSION_DEPTH};

    struct TestPacketSession {
        recv: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        sent_count: AtomicUsize,
        sent_payloads: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl PacketSession for TestPacketSession {
        fn send_packet(&self, payload: Vec<u8>) -> BoxFuture<'_, ()> {
            self.sent_count.fetch_add(1, Ordering::Relaxed);
            let sent_payloads = Arc::clone(&self.sent_payloads);
            Box::pin(async move {
                sent_payloads.lock().await.push(payload);
                Ok(())
            })
        }

        fn recv_packet(&self) -> BoxFuture<'_, Vec<u8>> {
            Box::pin(async move {
                self.recv
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| ProxyError::protocol("test packet session closed"))
            })
        }
    }

    struct TestOutbound {
        meta: OutboundMeta,
        logger: Logger,
        session: PacketSessionHandle,
        connected_destinations: Arc<Mutex<Vec<Destination>>>,
    }

    impl Outbound for TestOutbound {
        fn meta(&self) -> &OutboundMeta {
            &self.meta
        }

        fn logger(&self) -> &Logger {
            &self.logger
        }

        fn close(&self) -> BoxFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    impl ExecutionOutbound for TestOutbound {
        fn tag(&self) -> &str {
            &self.meta.tag
        }

        fn open_stream(&self, _ctx: &SessionContext) -> ExecutionFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("stream path unused")) })
        }

        fn open_packet(&self, ctx: &SessionContext) -> ExecutionFuture<'_, PacketSessionHandle> {
            let session = Arc::clone(&self.session);
            let connected_destinations = Arc::clone(&self.connected_destinations);
            let destination = ctx.meta.destination.clone();
            Box::pin(async move {
                connected_destinations.lock().await.push(destination);
                Ok(session)
            })
        }
    }

    fn empty_test_session() -> PacketSessionHandle {
        let (_tx, rx) = mpsc::unbounded_channel();
        Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn queued_test_session(responses: Vec<Vec<u8>>) -> Arc<TestPacketSession> {
        let (tx, rx) = mpsc::unbounded_channel();
        for response in responses {
            tx.send(response).expect("response should enqueue");
        }
        drop(tx);
        Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn parked_test_session() -> (Arc<TestPacketSession>, mpsc::UnboundedSender<Vec<u8>>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(TestPacketSession {
                recv: Mutex::new(rx),
                sent_count: AtomicUsize::new(0),
                sent_payloads: Arc::new(Mutex::new(Vec::new())),
            }),
            tx,
        )
    }

    fn register_test_outbound(
        registry: &mut Vec<Arc<dyn ExecutionOutbound>>,
        tag: &str,
        session: PacketSessionHandle,
        connected_destinations: Arc<Mutex<Vec<Destination>>>,
    ) -> Arc<dyn ExecutionOutbound> {
        let outbound = Arc::new(TestOutbound {
            meta: OutboundMeta::new(tag, "test"),
            logger: Logger::new(tag, "test"),
            session,
            connected_destinations,
        }) as Arc<dyn ExecutionOutbound>;
        registry.push(Arc::clone(&outbound));
        outbound
    }

    fn finalize_catalog(
        builder: Vec<Arc<dyn ExecutionOutbound>>,
        default_outbound: Arc<dyn ExecutionOutbound>,
    ) -> Arc<OutboundCatalog> {
        let outbounds = builder
            .into_iter()
            .map(|outbound| (outbound.tag().to_string(), outbound))
            .collect();
        Arc::new(OutboundCatalog::new(outbounds, default_outbound))
    }

    fn register_default_test_outbound(
        registry: &mut Vec<Arc<dyn ExecutionOutbound>>,
        tag: &str,
        session: PacketSessionHandle,
        connected_destinations: Arc<Mutex<Vec<Destination>>>,
    ) -> Arc<dyn ExecutionOutbound> {
        register_test_outbound(registry, tag, session, connected_destinations)
    }

    fn dns_runtime_config(
        final_server_tag: &str,
        servers: Vec<DnsServer>,
        rules: Vec<DnsRule>,
    ) -> DnsRuntimeConfig {
        DnsRuntimeConfig {
            final_server_tag: final_server_tag.into(),
            disable_cache: false,
            cache_capacity: DEFAULT_DNS_CACHE_CAPACITY,
            servers,
            rules,
        }
    }

    fn dns_query_request(domain: &str, id: u16) -> DnsRequest {
        DnsRequest::new(
            build_a_query(domain, id).expect("query should build"),
            Network::Udp,
            "dns-in",
            SocketAddr::from(([127, 0, 0, 1], 53000)),
            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
        )
    }

    #[tokio::test]
    async fn dns_executor_uses_dns_rule_and_returns_upstream_response() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(vec![0x12, 0x34]).expect("response should enqueue");
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        });
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            session,
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "fallback".into(),
                disable_cache: false,
                cache_capacity: 4096,
                servers: vec![
                    DnsServer {
                        tag: "direct".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            53,
                        ),
                        dial: Dial {
                            detour: Some("direct".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                    DnsServer {
                        tag: "fallback".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        dial: Dial {
                            detour: Some("direct".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                ],
                rules: vec![DnsRule {
                    domain: vec!["trojan.example.com".into()],
                    server_tag: "direct".into(),
                    disable_cache: false,
                }],
            },
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let response = executor
            .execute_query(DnsRequest::new(
                vec![
                    0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
                    b't', b'r', b'o', b'j', b'a', b'n', 0x07, b'e', b'x', b'a', b'm', b'p', b'l',
                    b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
                ],
                Network::Udp,
                "dns-in",
                SocketAddr::from(([127, 0, 0, 1], 53000)),
                Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
            ))
            .await
            .expect("dns query should succeed");

        assert_eq!(response.raw_message, vec![0x12, 0x34]);
    }

    #[tokio::test]
    async fn dns_executor_cache_hit_avoids_second_upstream_exchange() {
        let session = queued_test_session(vec![build_dns_answer_response_with_id(
            "cache.example.com",
            [203, 0, 113, 20],
            60,
            0x1001,
        )]);
        let session_handle: PacketSessionHandle = session.clone();
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            session_handle,
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            dns_runtime_config(
                "direct",
                vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                Vec::new(),
            ),
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let _first = executor
            .execute_query(dns_query_request("cache.example.com", 0x1001))
            .await
            .expect("first query should succeed");
        let second = executor
            .execute_query(dns_query_request("cache.example.com", 0x1002))
            .await
            .expect("second query should hit cache");

        assert_eq!(session.sent_count.load(Ordering::Relaxed), 1);
        assert_eq!(&second.raw_message[..2], &[0x10, 0x02]);
        assert_eq!(
            parse_response_ips(&second.raw_message).expect("cached response should remain usable"),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20))]
        );
    }

    #[tokio::test]
    async fn dns_executor_expired_cache_triggers_new_upstream_exchange() {
        let session = queued_test_session(vec![
            build_dns_answer_response_with_ttl("expire.example.com", [203, 0, 113, 21], 1),
            build_dns_answer_response_with_ttl("expire.example.com", [203, 0, 113, 22], 60),
        ]);
        let session_handle: PacketSessionHandle = session.clone();
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            session_handle,
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            dns_runtime_config(
                "direct",
                vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                Vec::new(),
            ),
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        executor
            .execute_query(dns_query_request("expire.example.com", 0x2001))
            .await
            .expect("first query should succeed");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let refreshed = executor
            .execute_query(dns_query_request("expire.example.com", 0x2002))
            .await
            .expect("expired cache should trigger refresh");

        assert_eq!(session.sent_count.load(Ordering::Relaxed), 2);
        assert_eq!(
            parse_response_ips(&refreshed.raw_message).expect("refreshed response should parse"),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 22))]
        );
    }

    #[tokio::test]
    async fn dns_rule_disable_cache_bypasses_cache() {
        let session = queued_test_session(vec![
            build_dns_answer_response("bypass.example.com", [203, 0, 113, 30]),
            build_dns_answer_response("bypass.example.com", [203, 0, 113, 30]),
        ]);
        let session_handle: PacketSessionHandle = session.clone();
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            session_handle,
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            dns_runtime_config(
                "direct",
                vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                vec![DnsRule {
                    domain: vec!["bypass.example.com".into()],
                    server_tag: "direct".into(),
                    disable_cache: true,
                }],
            ),
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        executor
            .execute_query(dns_query_request("bypass.example.com", 0x3001))
            .await
            .expect("first query should succeed");
        executor
            .execute_query(dns_query_request("bypass.example.com", 0x3002))
            .await
            .expect("second query should also hit upstream");

        assert_eq!(session.sent_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn dns_executor_emits_cache_lifecycle_events() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let session = queued_test_session(vec![build_dns_answer_response(
            "trace-cache.example.com",
            [203, 0, 113, 60],
        )]);
        let session_handle: PacketSessionHandle = session.clone();
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            session_handle,
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            dns_runtime_config(
                "direct",
                vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                Vec::new(),
            ),
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        executor
            .execute_query(dns_query_request("trace-cache.example.com", 0x4001))
            .await
            .expect("first query should succeed");
        executor
            .execute_query(dns_query_request("trace-cache.example.com", 0x4002))
            .await
            .expect("second query should hit cache");

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "dns_cache_miss",
            &[("query_kind", "client_query"), ("query_name", "trace-cache.example.com")],
        );
        assert_has_event(
            &events,
            "dns_cache_store",
            &[("query_kind", "client_query"), ("winner_server", "direct")],
        );
        assert_has_event(
            &events,
            "dns_cache_hit",
            &[("query_kind", "client_query"), ("winner_server", "direct")],
        );
        assert_has_event(
            &events,
            "dns_query_finish",
            &[("query_name", "trace-cache.example.com"), ("cache_hit", "true")],
        );
    }

    #[tokio::test]
    async fn domain_resolver_uses_explicit_server_and_parses_addresses() {
        let response = build_dns_answer_response("resolver.example.com", [203, 0, 113, 9]);
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(response).expect("response should enqueue");
        let connected_destinations = Arc::new(Mutex::new(Vec::new()));
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        });
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            session,
            Arc::clone(&connected_destinations),
        );
        register_test_outbound(
            &mut registry,
            "proxy",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "remote".into(),
                disable_cache: false,
                cache_capacity: 4096,
                servers: vec![
                    DnsServer {
                        tag: "direct".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            53,
                        ),
                        dial: Dial {
                            detour: Some("direct".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                    DnsServer {
                        tag: "remote".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        dial: Dial {
                            detour: Some("proxy".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                ],
                rules: vec![DnsRule {
                    domain: vec!["resolver.example.com".into()],
                    server_tag: "remote".into(),
                    disable_cache: false,
                }],
            },
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let addresses = executor
            .resolve_host(
                Host::Domain("resolver.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", Some("direct".into())),
            )
            .await
            .expect("domain resolver should succeed");

        assert_eq!(addresses, vec![SocketAddr::from(([203, 0, 113, 9], 443))]);
        assert_eq!(
            connected_destinations.lock().await.as_slice(),
            &[Destination::new(
                Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                53
            )]
        );
    }

    #[tokio::test]
    async fn domain_resolver_cache_hit_avoids_second_exchange() {
        let session = queued_test_session(vec![build_dns_answer_response(
            "resolve-cache.example.com",
            [203, 0, 113, 40],
        )]);
        let session_handle: PacketSessionHandle = session.clone();
        let connected_destinations = Arc::new(Mutex::new(Vec::new()));
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            session_handle,
            Arc::clone(&connected_destinations),
        );
        let executor = DnsExecutor::new(
            dns_runtime_config(
                "direct",
                vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                Vec::new(),
            ),
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let first = executor
            .resolve_host(
                Host::Domain("resolve-cache.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", None),
            )
            .await
            .expect("first resolve should succeed");
        let second = executor
            .resolve_host(
                Host::Domain("resolve-cache.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", None),
            )
            .await
            .expect("second resolve should hit cache");

        assert_eq!(session.sent_count.load(Ordering::Relaxed), 1);
        assert_eq!(first, second);
        assert_eq!(connected_destinations.lock().await.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_resolution_uses_first_success_and_cancels_loser() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let (remote_session, _remote_tx) = parked_test_session();
        let remote_handle: PacketSessionHandle = remote_session.clone();
        let bootstrap_session = queued_test_session(vec![build_dns_answer_response(
            "concurrent.example.com",
            [203, 0, 113, 50],
        )]);
        let bootstrap_handle: PacketSessionHandle = bootstrap_session.clone();
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            bootstrap_handle.clone(),
            Arc::new(Mutex::new(Vec::new())),
        );
        register_test_outbound(
            &mut registry,
            "dns-egress",
            remote_handle,
            Arc::new(Mutex::new(Vec::new())),
        );
        register_test_outbound(
            &mut registry,
            "proxy",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            dns_runtime_config(
                "remote",
                vec![
                    DnsServer {
                        tag: "remote".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            53,
                        ),
                        dial: Dial {
                            detour: Some("dns-egress".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                    DnsServer {
                        tag: "bootstrap".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        dial: Dial {
                            detour: Some("direct".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                ],
                Vec::new(),
            ),
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let addresses = executor
            .resolve_host(
                Host::Domain("concurrent.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", None),
            )
            .await
            .expect("concurrent resolution should succeed");

        assert_eq!(addresses, vec![SocketAddr::from(([203, 0, 113, 50], 443))]);
        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "dns_upstream_query_won",
            &[("server", "bootstrap"), ("query_kind", "dial_side_resolve")],
        );
        assert_has_event(
            &events,
            "dns_upstream_query_cancelled",
            &[("server", "remote"), ("query_kind", "dial_side_resolve")],
        );
    }

    #[tokio::test]
    async fn concurrent_resolution_returns_clear_all_failed_error() {
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        register_test_outbound(
            &mut registry,
            "dns-egress",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        register_test_outbound(
            &mut registry,
            "proxy",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            dns_runtime_config(
                "remote",
                vec![
                    DnsServer {
                        tag: "remote".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            53,
                        ),
                        dial: Dial {
                            detour: Some("dns-egress".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                    DnsServer {
                        tag: "bootstrap".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        dial: Dial {
                            detour: Some("direct".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                ],
                Vec::new(),
            ),
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let err = executor
            .resolve_host(
                Host::Domain("all-failed.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", None),
            )
            .await
            .expect_err("all candidates should fail");

        assert!(
            err.to_string()
                .contains("all dns upstream queries failed for dial_side_resolve 'all-failed.example.com'")
        );
        assert!(err.to_string().contains("[remote,bootstrap]"));
    }

    #[tokio::test]
    async fn domain_resolver_rejects_recursive_default_path_without_safe_server() {
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "proxy",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "remote".into(),
                disable_cache: false,
                cache_capacity: 4096,
                servers: vec![DnsServer {
                    tag: "remote".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("proxy".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                rules: Vec::new(),
            },
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let err = executor
            .resolve_host(
                Host::Domain("loop.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", None),
            )
            .await
            .expect_err("recursive default resolver path should be rejected");

        assert!(err.to_string().contains("no safe dns server"));
    }

    #[tokio::test]
    async fn domain_resolver_uses_safe_final_server_when_allowed() {
        let response = build_dns_answer_response("safe-final.example.com", [203, 0, 113, 10]);
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(response).expect("response should enqueue");
        let connected_destinations = Arc::new(Mutex::new(Vec::new()));
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        });
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        register_test_outbound(
            &mut registry,
            "dns-egress",
            session,
            Arc::clone(&connected_destinations),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "remote".into(),
                disable_cache: false,
                cache_capacity: 4096,
                servers: vec![
                    DnsServer {
                        tag: "remote".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        dial: Dial {
                            detour: Some("dns-egress".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                    DnsServer {
                        tag: "bootstrap".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            53,
                        ),
                        dial: Dial {
                            detour: Some("direct".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                ],
                rules: Vec::new(),
            },
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let addresses = executor
            .resolve_host(
                Host::Domain("safe-final.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", None),
            )
            .await
            .expect("domain resolver should use safe final server");

        assert_eq!(addresses, vec![SocketAddr::from(([203, 0, 113, 10], 443))]);
        assert_eq!(
            connected_destinations.lock().await.as_slice(),
            &[Destination::new(
                Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                54
            )]
        );
    }

    #[tokio::test]
    async fn domain_resolver_skips_caller_dns_server_and_uses_safe_fallback() {
        let response = build_dns_answer_response("fallback.example.com", [203, 0, 113, 11]);
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(response).expect("response should enqueue");
        let connected_destinations = Arc::new(Mutex::new(Vec::new()));
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        });
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            session,
            Arc::clone(&connected_destinations),
        );
        register_test_outbound(
            &mut registry,
            "proxy",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "remote".into(),
                disable_cache: false,
                cache_capacity: 4096,
                servers: vec![
                    DnsServer {
                        tag: "remote".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        dial: Dial {
                            detour: Some("proxy".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                    DnsServer {
                        tag: "bootstrap".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            53,
                        ),
                        dial: Dial {
                            detour: Some("direct".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                ],
                rules: Vec::new(),
            },
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let addresses = executor
            .resolve_host(
                Host::Domain("fallback.example.com".into()),
                443,
                ResolveContext {
                    purpose: veex_core::dns::ResolvePurpose::DnsUpstreamDial,
                    caller_outbound_tag: Some("proxy".into()),
                    caller_dns_server_tag: Some("remote".into()),
                    explicit_server_tag: None,
                    disable_cache: false,
                    recursion_depth: 1,
                },
            )
            .await
            .expect("domain resolver should skip caller dns server");

        assert_eq!(addresses, vec![SocketAddr::from(([203, 0, 113, 11], 443))]);
        assert_eq!(
            connected_destinations.lock().await.as_slice(),
            &[Destination::new(
                Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                53
            )]
        );
    }

    #[tokio::test]
    async fn domain_resolver_rejects_missing_explicit_server() {
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "direct".into(),
                disable_cache: false,
                cache_capacity: 4096,
                servers: vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                rules: Vec::new(),
            },
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let err = executor
            .resolve_host(
                Host::Domain("missing.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", Some("missing".into())),
            )
            .await
            .expect_err("missing explicit resolver should fail");

        assert!(
            err.to_string()
                .contains("explicit domain_resolver points to missing dns server tag: missing")
        );
    }

    #[tokio::test]
    async fn domain_resolver_rejects_empty_answer_response() {
        let response = build_dns_empty_response("empty.example.com");
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(response).expect("response should enqueue");
        let connected_destinations = Arc::new(Mutex::new(Vec::new()));
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        });
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            session,
            connected_destinations,
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "direct".into(),
                disable_cache: false,
                cache_capacity: 4096,
                servers: vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                rules: Vec::new(),
            },
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let err = executor
            .resolve_host(
                Host::Domain("empty.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", None),
            )
            .await
            .expect_err("empty response should fail resolution");

        assert!(
            err.to_string()
                .contains("dns response did not contain usable A/AAAA answers")
        );
    }

    #[tokio::test]
    async fn domain_resolver_propagates_upstream_exchange_failure() {
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "direct".into(),
                disable_cache: false,
                cache_capacity: 4096,
                servers: vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                rules: Vec::new(),
            },
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let err = executor
            .resolve_host(
                Host::Domain("failure.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", None),
            )
            .await
            .expect_err("upstream exchange failure should surface");

        assert!(err.to_string().contains("test packet session closed"));
    }

    #[tokio::test]
    async fn domain_resolver_rejects_excessive_recursion_depth() {
        let mut registry = Vec::new();
        let default_outbound = register_default_test_outbound(
            &mut registry,
            "direct",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "direct".into(),
                disable_cache: false,
                cache_capacity: 4096,
                servers: vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                rules: Vec::new(),
            },
            finalize_catalog(registry, default_outbound),
        )
        .expect("dns executor should build");

        let err = executor
            .resolve_host(
                Host::Domain("depth.example.com".into()),
                443,
                ResolveContext::outbound_dial("direct", None).with_depth(MAX_DNS_RECURSION_DEPTH),
            )
            .await
            .expect_err("resolver should enforce recursion depth");

        assert!(err.to_string().contains("recursion depth exceeded"));
    }

    #[test]
    fn local_dns_executor_builds_with_default_outbound() {
        let default_outbound = Arc::new(TestOutbound {
            meta: OutboundMeta::new("direct", "test"),
            logger: Logger::new("direct", "test"),
            session: empty_test_session(),
            connected_destinations: Arc::new(Mutex::new(Vec::new())),
        }) as Arc<dyn ExecutionOutbound>;
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "local".into(),
                disable_cache: false,
                cache_capacity: 4096,
                servers: vec![DnsServer {
                    tag: "local".into(),
                    transport: DnsServerTransport::Local,
                    destination: Destination::new(Host::Domain("local".into()), 53),
                    dial: Dial::default(),
                }],
                rules: Vec::new(),
            },
            Arc::new(OutboundCatalog::new(HashMap::new(), default_outbound)),
        );

        assert!(executor.is_ok());
    }

    fn build_dns_answer_response(domain: &str, ip: [u8; 4]) -> Vec<u8> {
        build_dns_answer_response_with_id(domain, ip, 60, 0x1234)
    }

    fn build_dns_answer_response_with_ttl(domain: &str, ip: [u8; 4], ttl_secs: u32) -> Vec<u8> {
        build_dns_answer_response_with_id(domain, ip, ttl_secs, 0x1234)
    }

    fn build_dns_answer_response_with_id(
        domain: &str,
        ip: [u8; 4],
        ttl_secs: u32,
        query_id: u16,
    ) -> Vec<u8> {
        let query = build_a_query(domain, query_id).expect("query should build");
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ttl_secs.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&ip);
        response
    }

    fn build_dns_empty_response(domain: &str) -> Vec<u8> {
        let query = build_a_query(domain, 0x1234).expect("query should build");
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response
    }
}
