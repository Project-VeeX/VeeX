use std::sync::Arc;

use veex_config::ProxyConfig;
use veex_core::{
    dns::{DnsExecutorHandle, DomainResolverHandle},
    execution::OutboundRegistry,
    ProxyError,
};
use veex_dns::DnsExecutor;

use crate::factory::lower_dns;

pub struct BuiltDnsServices {
    pub executor: Arc<dyn DnsExecutorHandle>,
    pub resolver: Arc<dyn DomainResolverHandle>,
}

pub fn build_dns_services(
    config: &ProxyConfig,
    outbounds: Arc<OutboundRegistry>,
) -> Result<Option<BuiltDnsServices>, ProxyError> {
    let Some(dns) = config.dns.as_ref() else {
        return Ok(None);
    };

    let runtime = lower_dns(dns);
    let executor = Arc::new(DnsExecutor::new(runtime, outbounds)?);
    Ok(Some(BuiltDnsServices {
        executor: executor.clone() as Arc<dyn DnsExecutorHandle>,
        resolver: executor as Arc<dyn DomainResolverHandle>,
    }))
}
