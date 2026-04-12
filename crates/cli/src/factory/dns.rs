use std::sync::Arc;

use veex_config::ProxyConfig;
use veex_core::{DnsExecutorHandle, OutboundRegistry, ProxyError};
use veex_dns::DnsExecutor;

use crate::factory::lower_dns;

pub fn build_dns_executor(
    config: &ProxyConfig,
    outbounds: Arc<OutboundRegistry>,
) -> Result<Option<Arc<dyn DnsExecutorHandle>>, ProxyError> {
    let Some(dns) = config.dns.as_ref() else {
        return Ok(None);
    };

    let runtime = lower_dns(dns);
    let executor: Arc<dyn DnsExecutorHandle> = Arc::new(DnsExecutor::new(runtime, outbounds)?);
    Ok(Some(executor))
}
