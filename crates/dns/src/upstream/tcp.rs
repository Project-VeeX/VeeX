use std::time::Duration;

use async_trait::async_trait;
use veex_core::{Destination, DnsRequest, DnsResponse, Network};

use crate::{dialer::DnsDialer, traits::DnsUpstream};

use super::exchange_dns_over_stream;

pub struct TcpUpstream {
    destination: Destination,
    dialer: DnsDialer,
    query_timeout: Duration,
}

impl TcpUpstream {
    pub fn new(destination: Destination, dialer: DnsDialer, query_timeout: Duration) -> Self {
        Self {
            destination,
            dialer,
            query_timeout,
        }
    }
}

#[async_trait]
impl DnsUpstream for TcpUpstream {
    async fn exchange(&self, req: DnsRequest) -> veex_core::Result<DnsResponse> {
        let mut stream = self
            .dialer
            .connect_stream(&req, &self.destination, Network::Tcp)
            .await?;
        exchange_dns_over_stream(&mut *stream, &req.raw_message, self.query_timeout).await
    }
}
