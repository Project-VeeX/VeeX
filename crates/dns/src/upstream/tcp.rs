use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use veex_core::{Destination, DnsRequest, DnsResponse, ExecutionOutbound, Network};

use crate::traits::DnsUpstream;

use super::{connect_detour_stream, exchange_dns_over_stream};

pub struct TcpUpstream {
    destination: Destination,
    outbound: Arc<dyn ExecutionOutbound>,
    query_timeout: Duration,
}

impl TcpUpstream {
    pub fn new(
        destination: Destination,
        outbound: Arc<dyn ExecutionOutbound>,
        query_timeout: Duration,
    ) -> Self {
        Self {
            destination,
            outbound,
            query_timeout,
        }
    }
}

#[async_trait]
impl DnsUpstream for TcpUpstream {
    async fn exchange(&self, req: DnsRequest) -> veex_core::Result<DnsResponse> {
        let mut stream =
            connect_detour_stream(&self.outbound, &req, &self.destination, Network::Tcp).await?;
        exchange_dns_over_stream(&mut *stream, &req.raw_message, self.query_timeout).await
    }
}
