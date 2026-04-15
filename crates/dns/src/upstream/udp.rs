use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::time::timeout;
use veex_core::{Destination, DnsRequest, DnsResponse, ExecutionOutbound, Network, ProxyError};

use super::{log_close_result, open_detour_packet, DnsUpstream};

pub struct UdpUpstream {
    destination: Destination,
    outbound: Arc<dyn ExecutionOutbound>,
    query_timeout: Duration,
}

impl UdpUpstream {
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
impl DnsUpstream for UdpUpstream {
    async fn exchange(&self, req: DnsRequest) -> veex_core::Result<DnsResponse> {
        let session =
            open_detour_packet(&self.outbound, &req, &self.destination, Network::Udp).await?;

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
