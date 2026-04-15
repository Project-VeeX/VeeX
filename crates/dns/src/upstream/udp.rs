use std::time::Duration;

use async_trait::async_trait;
use tokio::time::timeout;
use veex_core::{Destination, DnsRequest, DnsResponse, Network, ProxyError};

use crate::{dialer::DnsDialer, traits::DnsUpstream};

use super::log_close_result;

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

        if let Err(err) = session.send_packet(req.raw_message.clone()).await {
            log_close_result(req.session_id.unwrap_or_default(), session.close().await);
            return Err(err);
        }

        let response = match timeout(self.query_timeout, session.recv_packet()).await {
            Ok(result) => result,
            Err(_) => Err(ProxyError::timeout(format!(
                "dns upstream response timeout after {} ms",
                self.query_timeout.as_millis()
            ))),
        };
        log_close_result(req.session_id.unwrap_or_default(), session.close().await);

        response.map(DnsResponse::new)
    }
}
