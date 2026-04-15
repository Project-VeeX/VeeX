use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tokio::{net::UdpSocket, time::timeout};
use tracing::warn;
use veex_core::{read_dns_tcp_message, write_dns_tcp_message, DnsRequest, DnsResponse, ProxyError};
use veex_infra_linux::load_system_dns_servers;

use crate::{
    dialer::DnsDialer,
    traits::DnsUpstream,
    types::{DnsServer, DnsServerTransport},
};

pub mod https;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use https::HttpsUpstream;
pub use tcp::TcpUpstream;
pub use tls::TlsUpstream;
pub use udp::UdpUpstream;

pub(crate) fn build_upstream(
    server: &DnsServer,
    dialer: Option<DnsDialer>,
    query_timeout: Duration,
) -> veex_core::Result<Arc<dyn DnsUpstream>> {
    match &server.transport {
        DnsServerTransport::Local => {
            Ok(Arc::new(LocalUpstream::new(query_timeout)) as Arc<dyn DnsUpstream>)
        }
        DnsServerTransport::Udp => Ok(Arc::new(UdpUpstream::new(
            server.destination.clone(),
            require_dns_dialer(server, dialer)?,
            query_timeout,
        )) as Arc<dyn DnsUpstream>),
        DnsServerTransport::Tcp => Ok(Arc::new(TcpUpstream::new(
            server.destination.clone(),
            require_dns_dialer(server, dialer)?,
            query_timeout,
        )) as Arc<dyn DnsUpstream>),
        DnsServerTransport::Tls(tls) => Ok(Arc::new(TlsUpstream::new(
            server.destination.clone(),
            require_dns_dialer(server, dialer)?,
            tls.clone(),
            query_timeout,
        )) as Arc<dyn DnsUpstream>),
        DnsServerTransport::Https(options) => Ok(Arc::new(HttpsUpstream::new(
            server.tag.clone(),
            server.destination.clone(),
            require_dns_dialer(server, dialer)?,
            options.clone(),
            query_timeout,
        )) as Arc<dyn DnsUpstream>),
        DnsServerTransport::Unsupported(kind) => Ok(Arc::new(UnsupportedUpstream::new(
            server.tag.clone(),
            kind.clone(),
        )) as Arc<dyn DnsUpstream>),
    }
}

fn require_dns_dialer(
    server: &DnsServer,
    dialer: Option<DnsDialer>,
) -> veex_core::Result<DnsDialer> {
    dialer.ok_or_else(|| {
        ProxyError::config(format!(
            "missing dns dialer for server '{}' with transport '{}'",
            server.tag,
            server.transport.as_str()
        ))
    })
}

pub(crate) async fn exchange_dns_over_stream(
    stream: &mut dyn veex_core::AsyncStream,
    query: &[u8],
    query_timeout: Duration,
) -> veex_core::Result<DnsResponse> {
    write_dns_tcp_message(stream, query).await?;
    let response = timeout(query_timeout, read_dns_tcp_message(stream)).await;
    let response = match response {
        Ok(result) => result?,
        Err(_) => {
            return Err(ProxyError::timeout(format!(
                "dns upstream response timeout after {} ms",
                query_timeout.as_millis()
            )));
        }
    };
    let response = response.ok_or_else(|| {
        ProxyError::protocol("dns over tcp upstream closed before sending a response")
    })?;
    Ok(DnsResponse::new(response))
}

pub(crate) async fn execute_local_udp_query(
    destination: SocketAddr,
    query: &[u8],
    query_timeout: Duration,
) -> veex_core::Result<Vec<u8>> {
    let socket = UdpSocket::bind(udp_bind_addr(destination.ip()))
        .await
        .map_err(|err| ProxyError::resolve_ctx("failed to bind local dns udp socket", err))?;
    socket
        .connect(destination)
        .await
        .map_err(|err| ProxyError::resolve_ctx("failed to connect local dns udp socket", err))?;
    socket
        .send(query)
        .await
        .map_err(|err| ProxyError::resolve_ctx("failed to send local dns query", err))?;

    let mut buffer = vec![0; 2048];
    let size = match timeout(query_timeout, socket.recv(&mut buffer)).await {
        Ok(result) => result
            .map_err(|err| ProxyError::resolve_ctx("failed to receive local dns response", err))?,
        Err(_) => {
            return Err(ProxyError::timeout(format!(
                "dns upstream response timeout after {} ms",
                query_timeout.as_millis()
            )));
        }
    };
    buffer.truncate(size);
    Ok(buffer)
}

pub(crate) fn udp_bind_addr(destination: IpAddr) -> SocketAddr {
    match destination {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

pub(crate) fn log_close_result(query_id: u64, result: veex_core::Result<()>) {
    if let Err(err) = result {
        warn!(
            event = "dns_query_close_failed",
            query_id,
            error_kind = ?err.kind(),
            error = %err,
            "dns upstream session close failed"
        );
    }
}

struct LocalUpstream {
    query_timeout: Duration,
}

impl LocalUpstream {
    fn new(query_timeout: Duration) -> Self {
        Self { query_timeout }
    }
}

#[async_trait]
impl DnsUpstream for LocalUpstream {
    async fn exchange(&self, req: DnsRequest) -> veex_core::Result<DnsResponse> {
        let nameservers = load_system_dns_servers()
            .map_err(|err| ProxyError::resolve_ctx("failed to load system dns nameservers", err))?;

        if nameservers.is_empty() {
            return Err(ProxyError::resolve(
                "system dns resolver did not provide any nameserver",
            ));
        }

        let mut last_error = None;
        for nameserver in nameservers {
            let destination = SocketAddr::new(nameserver, 53);
            match execute_local_udp_query(destination, &req.raw_message, self.query_timeout).await {
                Ok(response) => return Ok(DnsResponse::new(response)),
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            ProxyError::resolve("system dns resolver did not provide any reachable nameserver")
        }))
    }
}

struct UnsupportedUpstream {
    server_tag: String,
    kind: String,
}

impl UnsupportedUpstream {
    fn new(server_tag: String, kind: String) -> Self {
        Self { server_tag, kind }
    }
}

#[async_trait]
impl DnsUpstream for UnsupportedUpstream {
    async fn exchange(&self, _req: DnsRequest) -> veex_core::Result<DnsResponse> {
        Err(ProxyError::protocol(format!(
            "dns server '{}' uses unsupported upstream type '{}'",
            self.server_tag, self.kind
        )))
    }
}
