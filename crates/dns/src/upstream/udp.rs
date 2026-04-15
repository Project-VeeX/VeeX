use std::time::Duration;

use async_trait::async_trait;
use veex_core::{Destination, DnsRequest, DnsResponse, Network};

use crate::{dialer::DnsDialer, traits::DnsUpstream};

use super::exchange_dns_over_packet;

pub struct UdpUpstream {
    destination: Destination,
    dialer: DnsDialer,
    query_timeout: Duration,
}

impl UdpUpstream {
    pub fn new(destination: Destination, dialer: DnsDialer, query_timeout: Duration) -> Self {
        Self {
            destination,
            dialer,
            query_timeout,
        }
    }
}

#[async_trait]
impl DnsUpstream for UdpUpstream {
    async fn exchange(&self, req: DnsRequest) -> veex_core::Result<DnsResponse> {
        let session = self
            .dialer
            .open_packet(&req, &self.destination, Network::Udp)
            .await?;
        exchange_dns_over_packet(session, &req, self.query_timeout).await
    }
}
