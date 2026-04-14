use std::sync::Arc;

use crate::{dns::DnsExecutorHandle, error::ProxyError};

use super::{traits::PlaneOutbound, types::OutboundRegistry};

pub(crate) fn lookup_outbound(
    registry: &OutboundRegistry,
    outbound_tag: &str,
) -> crate::Result<Arc<dyn PlaneOutbound>> {
    registry
        .get(outbound_tag)
        .ok_or_else(|| ProxyError::config(format!("missing outbound tag: {outbound_tag}")))
}

pub(crate) fn require_dns_executor(
    dns_executor: Option<&Arc<dyn DnsExecutorHandle>>,
) -> crate::Result<Arc<dyn DnsExecutorHandle>> {
    dns_executor.cloned().ok_or_else(missing_dns_executor_error)
}

pub(crate) fn missing_dns_executor_error() -> ProxyError {
    ProxyError::config("route selected 'hijack-dns' but dns executor is not configured")
}
