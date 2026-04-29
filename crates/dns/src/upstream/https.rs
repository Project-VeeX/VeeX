use std::time::Duration;

use async_trait::async_trait;
use tokio::time::timeout;
use tracing::info;
use veex_core::{
    ProxyError,
    dns::{DnsRequest, DnsResponse},
    logging::sanitize_field,
    types::{Destination, Network},
};
use veex_transport::server_name_for_tls;

use crate::{dialer::DnsDialer, http, traits::DnsUpstream, types::DnsHttpsOptions};

use super::connect_tls_for_dns;

pub struct HttpsUpstream {
    server_tag: String,
    destination: Destination,
    dialer: DnsDialer,
    options: DnsHttpsOptions,
    query_timeout: Duration,
}

impl HttpsUpstream {
    pub fn new(
        server_tag: String,
        destination: Destination,
        dialer: DnsDialer,
        options: DnsHttpsOptions,
        query_timeout: Duration,
    ) -> Self {
        Self {
            server_tag,
            destination,
            dialer,
            options,
            query_timeout,
        }
    }
}

#[async_trait]
impl DnsUpstream for HttpsUpstream {
    async fn exchange(&self, req: DnsRequest) -> veex_core::Result<DnsResponse> {
        let stream = self
            .dialer
            .connect_stream(&req, &self.destination, Network::Tcp)
            .await?;
        let mut stream = connect_tls_for_dns(
            stream,
            &self.destination,
            &self.dialer,
            &self.options.tls,
            &req,
        )
        .await?;

        let host_header =
            server_name_for_tls(&self.destination.host, &self.options.tls).map_err(ProxyError::from)?;
        let path_field = sanitize_field(&self.options.path).into_owned();
        let query_id = req.session_id.unwrap_or_default();
        info!(
            event = "dns_https_exchange_start",
            query_id,
            server = %sanitize_field(&self.server_tag),
            detour = %sanitize_field(self.dialer.detour_tag()),
            path = %path_field,
            "dns https exchange started"
        );
        http::write_doh_http1_request(
            &mut *stream,
            &host_header,
            &self.options.path,
            &self.options.headers,
            &req.raw_message,
        )
        .await?;
        let response = match timeout(
            self.query_timeout,
            http::read_doh_http1_response(&mut *stream),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(ProxyError::timeout(format!(
                    "dns upstream response timeout after {} ms",
                    self.query_timeout.as_millis()
                )));
            }
        };
        info!(
            event = "dns_https_exchange_success",
            query_id,
            server = %sanitize_field(&self.server_tag),
            detour = %sanitize_field(self.dialer.detour_tag()),
            path = %path_field,
            response_bytes = response.len() as u64,
            "dns https exchange succeeded"
        );
        Ok(DnsResponse::new(response))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use veex_core::types::{Destination, Host};
    use veex_transport::{OutboundTls, server_name_for_tls};

    use crate::types::DnsHttpsOptions;

    #[test]
    fn dns_https_host_header_reuses_transport_tls_server_name_resolution() {
        let derived = server_name_for_tls(
            &Destination::new(Host::Domain("dns.example.com".into()), 443).host,
            &DnsHttpsOptions {
                path: "/dns-query".into(),
                headers: BTreeMap::new(),
                tls: OutboundTls::default(),
            }
            .tls,
        )
        .expect("domain host should derive host header");
        assert_eq!(derived, "dns.example.com");

        let explicit = server_name_for_tls(
            &Destination::new(Host::Domain("dns.example.com".into()), 443).host,
            &DnsHttpsOptions {
                path: "/dns-query".into(),
                headers: BTreeMap::new(),
                tls: OutboundTls {
                    server_name: Some("override.example.com".into()),
                    ..OutboundTls::default()
                },
            }
            .tls,
        )
        .expect("explicit tls server_name should win");
        assert_eq!(explicit, "override.example.com");
    }
}
