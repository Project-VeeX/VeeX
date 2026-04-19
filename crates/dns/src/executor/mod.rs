use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use veex_core::{
    dns::{DnsExecutorHandle, DnsRequest, DnsResponse, DomainResolverHandle, ResolveContext},
    portal::BoxFuture,
    types::Host,
};
use veex_execution::OutboundCatalog;

use crate::{cache::DnsCache, router::DnsRouter, types::DnsRuntimeConfig};

mod exchange;
mod logging;
mod query;
mod resolve;
mod runtime;
#[cfg(test)]
mod tests;

const DEFAULT_DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_RECURSION_DEPTH: u8 = 4;
const CLIENT_QUERY_KIND: &str = "client_query";
const RESOLVE_QUERY_KIND: &str = "dial_side_resolve";

use runtime::DnsServerRuntime;

pub struct DnsExecutor {
    router: DnsRouter,
    servers: std::collections::HashMap<String, DnsServerRuntime>,
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
        let mut servers = std::collections::HashMap::new();
        for server in config.servers {
            let tag = server.tag.clone();
            let runtime = DnsServerRuntime::new(server, &outbounds, query_timeout)?;
            if servers.insert(tag, runtime).is_some() {
                return Err(veex_core::ProxyError::config(
                    "duplicate dns server tag in runtime",
                ));
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
