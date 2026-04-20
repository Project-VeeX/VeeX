use std::time::Duration;

use async_trait::async_trait;
use veex_core::{
    dns::{DnsRequest, DnsResponse},
    types::{Destination, Network},
};
use veex_transport::OutboundTls;

use crate::{dialer::DnsDialer, traits::DnsUpstream};

use super::{connect_tls_for_dns, exchange_dns_over_stream};

pub struct TlsUpstream {
    destination: Destination,
    dialer: DnsDialer,
    tls: OutboundTls,
    query_timeout: Duration,
}

impl TlsUpstream {
    pub fn new(
        destination: Destination,
        dialer: DnsDialer,
        tls: OutboundTls,
        query_timeout: Duration,
    ) -> Self {
        Self {
            destination,
            dialer,
            tls,
            query_timeout,
        }
    }
}

#[async_trait]
impl DnsUpstream for TlsUpstream {
    async fn exchange(&self, req: DnsRequest) -> veex_core::Result<DnsResponse> {
        let stream = self
            .dialer
            .connect_stream(&req, &self.destination, Network::Tcp)
            .await?;
        let mut stream =
            connect_tls_for_dns(stream, &self.destination, &self.dialer, &self.tls, &req).await?;
        exchange_dns_over_stream(&mut *stream, &req.raw_message, self.query_timeout).await
    }
}
