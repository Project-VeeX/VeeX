use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::{net::UdpSocket, time::timeout};
use tracing::warn;
use veex_core::{
    read_dns_tcp_message, write_dns_tcp_message, BoxedAsyncStream, Destination, DnsRequest,
    DnsResponse, ExecutionOutbound, Network, OutboundRegistry, PacketSessionHandle, ProxyError,
    SessionContext, SessionMeta,
};
use veex_infra_linux::load_system_dns_servers;
use veex_transport::{connect_tls_stream, ConnectTraceContext, TlsClientOptions};

use crate::{DnsServer, DnsServerTransport};

pub mod https;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use https::HttpsUpstream;
pub use tcp::TcpUpstream;
pub use tls::TlsUpstream;
pub use udp::UdpUpstream;

#[async_trait]
pub trait DnsUpstream: Send + Sync {
    async fn exchange(&self, req: DnsRequest) -> veex_core::Result<DnsResponse>;
}

pub(crate) fn build_upstream(
    server: &DnsServer,
    outbounds: &Arc<OutboundRegistry>,
    query_timeout: Duration,
) -> veex_core::Result<Arc<dyn DnsUpstream>> {
    match &server.transport {
        DnsServerTransport::Local => {
            Ok(Arc::new(LocalUpstream::new(query_timeout)) as Arc<dyn DnsUpstream>)
        }
        DnsServerTransport::Udp => Ok(Arc::new(UdpUpstream::new(
            server.destination.clone(),
            require_outbound(outbounds, &server.detour)?,
            query_timeout,
        )) as Arc<dyn DnsUpstream>),
        DnsServerTransport::Tcp => Ok(Arc::new(TcpUpstream::new(
            server.destination.clone(),
            require_outbound(outbounds, &server.detour)?,
            query_timeout,
        )) as Arc<dyn DnsUpstream>),
        DnsServerTransport::Tls(tls) => Ok(Arc::new(TlsUpstream::new(
            server.destination.clone(),
            server.detour.clone(),
            require_outbound(outbounds, &server.detour)?,
            tls.clone(),
            query_timeout,
        )) as Arc<dyn DnsUpstream>),
        DnsServerTransport::Https(options) => Ok(Arc::new(HttpsUpstream::new(
            server.tag.clone(),
            server.destination.clone(),
            server.detour.clone(),
            require_outbound(outbounds, &server.detour)?,
            options.clone(),
            query_timeout,
        )) as Arc<dyn DnsUpstream>),
        DnsServerTransport::Unsupported(kind) => Ok(Arc::new(UnsupportedUpstream::new(
            server.tag.clone(),
            kind.clone(),
        )) as Arc<dyn DnsUpstream>),
    }
}

fn require_outbound(
    outbounds: &Arc<OutboundRegistry>,
    detour: &str,
) -> veex_core::Result<Arc<dyn ExecutionOutbound>> {
    outbounds
        .get(detour)
        .ok_or_else(|| ProxyError::config(format!("missing outbound tag for dns detour: {detour}")))
}

pub(crate) async fn open_detour_packet(
    outbound: &Arc<dyn ExecutionOutbound>,
    request: &DnsRequest,
    destination: &Destination,
    network: Network,
) -> veex_core::Result<PacketSessionHandle> {
    let ctx = build_request_context(request, destination.clone(), network);
    outbound.open_packet(&ctx).await
}

pub(crate) async fn connect_detour_stream(
    outbound: &Arc<dyn ExecutionOutbound>,
    request: &DnsRequest,
    destination: &Destination,
    network: Network,
) -> veex_core::Result<BoxedAsyncStream> {
    let ctx = build_request_context(request, destination.clone(), network);
    outbound.open_stream(&ctx).await
}

pub(crate) async fn connect_tls_for_dns(
    stream: BoxedAsyncStream,
    destination: &Destination,
    detour: &str,
    tls: &TlsClientOptions,
    request: &DnsRequest,
) -> veex_core::Result<BoxedAsyncStream> {
    let trace = ConnectTraceContext {
        session_id: request_query_id(request),
        outbound: detour.to_string(),
        routing_mark: None,
    };
    connect_tls_stream(
        stream,
        &destination.host,
        destination.port,
        tls,
        Some(&trace),
    )
    .await
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

fn build_request_context(
    request: &DnsRequest,
    destination: Destination,
    network: Network,
) -> SessionContext {
    let mut ctx = SessionContext::new(
        SessionMeta {
            id: request_query_id(request),
            network,
            inbound_tag: request.inbound_tag.clone(),
            peer: request.peer,
            destination,
            start: Instant::now(),
        },
        request.buffered_payload.clone(),
    );
    ctx.set_resolve_context(request.resolve_context.clone());
    ctx
}

fn request_query_id(request: &DnsRequest) -> u64 {
    request.session_id.unwrap_or_default()
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
