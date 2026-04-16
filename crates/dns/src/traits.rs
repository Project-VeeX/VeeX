use async_trait::async_trait;
use veex_core::dns::{DnsRequest, DnsResponse};

#[async_trait]
pub trait DnsUpstream: Send + Sync {
    async fn exchange(&self, req: DnsRequest) -> veex_core::Result<DnsResponse>;
}
