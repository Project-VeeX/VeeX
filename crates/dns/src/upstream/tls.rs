use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use veex_core::{Destination, DnsRequest, DnsResponse, ExecutionOutbound, Network};
use veex_transport::TlsClientOptions;

use crate::traits::DnsUpstream;

use super::{connect_detour_stream, connect_tls_for_dns, exchange_dns_over_stream};

pub struct TlsUpstream {
    destination: Destination,
    detour: String,
    outbound: Arc<dyn ExecutionOutbound>,
    tls: TlsClientOptions,
    query_timeout: Duration,
}

impl TlsUpstream {
    pub fn new(
        destination: Destination,
        detour: String,
        outbound: Arc<dyn ExecutionOutbound>,
        tls: TlsClientOptions,
        query_timeout: Duration,
    ) -> Self {
        Self {
            destination,
            detour,
            outbound,
            tls,
            query_timeout,
        }
    }
}

#[async_trait]
impl DnsUpstream for TlsUpstream {
    async fn exchange(&self, req: DnsRequest) -> veex_core::Result<DnsResponse> {
        let stream =
            connect_detour_stream(&self.outbound, &req, &self.destination, Network::Tcp).await?;
        let mut stream =
            connect_tls_for_dns(stream, &self.destination, &self.detour, &self.tls, &req).await?;
        exchange_dns_over_stream(&mut *stream, &req.raw_message, self.query_timeout).await
    }
}
