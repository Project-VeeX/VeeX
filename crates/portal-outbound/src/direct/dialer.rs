use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tracing::{debug, info, warn};
use veex_core::{
    ProxyError, Result,
    io::{PacketSession, PacketSessionHandle},
    logging::sanitize_field,
    portal::{BoxFuture, Dial, DialContext, Dialer, PacketDialer},
    types::Host,
};
use veex_transport::{
    ConnectTraceContext, HostResolveRequest, HostResolver, TcpAttemptConnector, TcpConnectOptions,
    connect_host_with_resolver, resolve_host,
};

use super::error::{
    io_error_with_context, last_os_error_with_context, validate_routing_mark_support,
};

pub type MarkedConnectorFuture =
    Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'static>>;
pub type MarkedConnector = dyn Fn(SocketAddr, u32) -> MarkedConnectorFuture + Send + Sync;
pub type MarkedUdpConnectorFuture =
    Pin<Box<dyn Future<Output = io::Result<UdpSocket>> + Send + 'static>>;
pub type MarkedUdpConnector = dyn Fn(SocketAddr, u32) -> MarkedUdpConnectorFuture + Send + Sync;

pub fn system_host_resolver() -> Arc<HostResolver> {
    Arc::new(|request| Box::pin(async move { resolve_host(&request.host, request.port).await }))
}

pub fn build_dialer(dial: Dial, resolver: Arc<HostResolver>) -> Result<Dialer> {
    let marked_connector = Arc::new(|address, routing_mark| {
        Box::pin(connect_marked_socket(address, routing_mark)) as MarkedConnectorFuture
    });
    build_dialer_with_connector(dial, resolver, marked_connector)
}

pub fn build_packet_dialer(dial: Dial, resolver: Arc<HostResolver>) -> Result<PacketDialer> {
    let marked_connector = Arc::new(|address, routing_mark| {
        Box::pin(connect_marked_udp_socket(address, routing_mark)) as MarkedUdpConnectorFuture
    });
    build_packet_dialer_with_connector(dial, resolver, marked_connector)
}

pub fn build_dialer_with_connector(
    dial: Dial,
    resolver: Arc<HostResolver>,
    marked_connector: Arc<MarkedConnector>,
) -> Result<Dialer> {
    validate_routing_mark_support(dial.routing_mark)?;

    Ok(Dialer::new(
        dial,
        Arc::new(move |host, port, dial, ctx| {
            let resolver = Arc::clone(&resolver);
            let marked_connector = Arc::clone(&marked_connector);
            Box::pin(async move {
                connect_destination(&host, port, resolver.as_ref(), dial, ctx, &marked_connector)
                    .await
            })
        }),
    ))
}

pub fn build_packet_dialer_with_connector(
    dial: Dial,
    resolver: Arc<HostResolver>,
    marked_connector: Arc<MarkedUdpConnector>,
) -> Result<PacketDialer> {
    validate_routing_mark_support(dial.routing_mark)?;

    Ok(PacketDialer::new(
        dial,
        Arc::new(move |host, port, dial, ctx| {
            let resolver = Arc::clone(&resolver);
            let marked_connector = Arc::clone(&marked_connector);
            Box::pin(async move {
                connect_packet_destination(
                    &host,
                    port,
                    resolver.as_ref(),
                    dial,
                    ctx,
                    &marked_connector,
                )
                .await
            })
        }),
    ))
}

async fn connect_destination(
    host: &Host,
    port: u16,
    resolver: &HostResolver,
    dial: Dial,
    ctx: DialContext,
    marked_connector: &Arc<MarkedConnector>,
) -> Result<TcpStream> {
    let resolve_context =
        dial.resolve_context(ctx.resolve_context.as_ref(), ctx.outbound_tag.clone());
    let connector = dial.routing_mark.map(|routing_mark| {
        let marked_connector = Arc::clone(marked_connector);
        Arc::new(move |address| marked_connector(address, routing_mark)) as Arc<TcpAttemptConnector>
    });

    connect_host_with_resolver(
        host,
        port,
        resolve_context,
        resolver,
        TcpConnectOptions {
            timeout: dial.connect_timeout,
            disable_keepalive: dial.disable_tcp_keep_alive,
            keepalive: dial.tcp_keep_alive,
            keepalive_interval: dial.tcp_keep_alive_interval,
            trace: Some(ConnectTraceContext {
                session_id: ctx.session_id,
                outbound: ctx.outbound_tag,
                routing_mark: dial.routing_mark,
            }),
            connector,
        },
    )
    .await
}

async fn connect_packet_destination(
    host: &Host,
    port: u16,
    resolver: &HostResolver,
    dial: Dial,
    ctx: DialContext,
    marked_connector: &Arc<MarkedUdpConnector>,
) -> Result<PacketSessionHandle> {
    let host_field = sanitize_field(&host.to_string()).into_owned();
    let addresses = resolver(HostResolveRequest {
        host: host.clone(),
        port,
        context: dial.resolve_context(ctx.resolve_context.as_ref(), ctx.outbound_tag.clone()),
    })
    .await?;
    let attempt_count = addresses.len();
    let mut last_error = None;

    for (idx, address) in addresses.into_iter().enumerate() {
        let attempt_index = (idx + 1) as u64;
        log_udp_connect_attempt(
            &ctx,
            &host_field,
            port,
            address,
            dial.routing_mark,
            attempt_index,
            dial.connect_timeout,
        );

        match connect_udp_socket(
            address,
            dial.connect_timeout,
            dial.routing_mark,
            marked_connector,
        )
        .await
        {
            Ok(socket) => {
                log_udp_connect_success(
                    &ctx,
                    &host_field,
                    port,
                    address,
                    dial.routing_mark,
                    attempt_index,
                );
                return Ok(Arc::new(DirectPacketSession::new(socket)) as PacketSessionHandle);
            }
            Err(err) => {
                log_udp_connect_failed(
                    &ctx,
                    &host_field,
                    port,
                    address,
                    dial.routing_mark,
                    attempt_index,
                    &err,
                );
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        ProxyError::dial(format!(
            "no reachable udp address for {host_field}:{port} after {attempt_count} attempts"
        ))
    }))
}

async fn connect_udp_socket(
    address: SocketAddr,
    timeout_duration: Option<Duration>,
    routing_mark: Option<u32>,
    marked_connector: &Arc<MarkedUdpConnector>,
) -> Result<UdpSocket> {
    let connect_future = async {
        match routing_mark {
            Some(mark) => marked_connector(address, mark).await,
            None => {
                let socket = UdpSocket::bind(udp_bind_addr(address)).await?;
                socket.connect(address).await?;
                Ok(socket)
            }
        }
    };

    match timeout_duration {
        Some(duration) => timeout(duration, connect_future)
            .await
            .map_err(|_| ProxyError::timeout(format!("udp connect timeout to {address}")))?
            .map_err(|err| ProxyError::dial_ctx(format!("udp connect failed to {address}"), err)),
        None => connect_future
            .await
            .map_err(|err| ProxyError::dial_ctx(format!("udp connect failed to {address}"), err)),
    }
}

pub(crate) async fn connect_marked_socket(
    address: SocketAddr,
    routing_mark: u32,
) -> io::Result<TcpStream> {
    connect_marked_socket_impl(address, routing_mark).await
}

pub(crate) async fn connect_marked_udp_socket(
    address: SocketAddr,
    routing_mark: u32,
) -> io::Result<UdpSocket> {
    connect_marked_udp_socket_impl(address, routing_mark).await
}

#[cfg(target_os = "linux")]
async fn connect_marked_socket_impl(
    address: SocketAddr,
    routing_mark: u32,
) -> io::Result<TcpStream> {
    use std::os::fd::AsRawFd;

    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(|err| {
        io_error_with_context(format!("failed to create direct socket for {address}"), err)
    })?;
    socket.set_nonblocking(true).map_err(|err| {
        io_error_with_context(
            format!("failed to switch direct socket to nonblocking mode for {address}"),
            err,
        )
    })?;
    let mark = routing_mark as libc::c_int;
    // SAFETY: the socket fd is live, the option buffer points to a valid integer,
    // and the length matches the pointed-to value size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(last_os_error_with_context(format!(
            "failed to set SO_MARK={routing_mark} for {address}"
        )));
    }

    match socket.connect(&address.into()) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(err) => {
            return Err(io_error_with_context(
                format!("direct connect failed to {address} with SO_MARK={routing_mark}"),
                err,
            ));
        }
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream).map_err(|err| {
        io_error_with_context(
            format!("failed to register marked direct socket for {address} with tokio"),
            err,
        )
    })?;
    stream.writable().await.map_err(|err| {
        io_error_with_context(
            format!("marked direct socket did not become writable for {address}"),
            err,
        )
    })?;
    if let Some(err) = stream.take_error().map_err(|err| {
        io_error_with_context(
            format!("failed to inspect marked direct socket error for {address}"),
            err,
        )
    })? {
        return Err(io_error_with_context(
            format!("direct connect failed to {address} with SO_MARK={routing_mark}"),
            err,
        ));
    }

    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
async fn connect_marked_socket_impl(
    address: SocketAddr,
    _routing_mark: u32,
) -> io::Result<TcpStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("direct outbound routing_mark is not supported on this platform for {address}"),
    ))
}

#[cfg(target_os = "linux")]
async fn connect_marked_udp_socket_impl(
    address: SocketAddr,
    routing_mark: u32,
) -> io::Result<UdpSocket> {
    use std::os::fd::AsRawFd;

    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|err| {
        io_error_with_context(
            format!("failed to create direct udp socket for {address}"),
            err,
        )
    })?;
    socket.set_nonblocking(true).map_err(|err| {
        io_error_with_context(
            format!("failed to switch direct udp socket to nonblocking mode for {address}"),
            err,
        )
    })?;
    socket.bind(&udp_bind_addr(address).into()).map_err(|err| {
        io_error_with_context(
            format!("failed to bind direct udp socket for {address}"),
            err,
        )
    })?;
    let mark = routing_mark as libc::c_int;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(last_os_error_with_context(format!(
            "failed to set SO_MARK={routing_mark} for udp {address}"
        )));
    }
    socket.connect(&address.into()).map_err(|err| {
        io_error_with_context(
            format!("direct udp connect failed to {address} with SO_MARK={routing_mark}"),
            err,
        )
    })?;

    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).map_err(|err| {
        io_error_with_context(
            format!("failed to register marked direct udp socket for {address} with tokio"),
            err,
        )
    })
}

#[cfg(not(target_os = "linux"))]
async fn connect_marked_udp_socket_impl(
    address: SocketAddr,
    _routing_mark: u32,
) -> io::Result<UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("direct outbound routing_mark is not supported on this platform for udp {address}"),
    ))
}

fn udp_bind_addr(address: SocketAddr) -> SocketAddr {
    if address.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    }
}

struct DirectPacketSession {
    socket: UdpSocket,
}

impl DirectPacketSession {
    fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }
}

impl PacketSession for DirectPacketSession {
    fn send_packet(&self, payload: Vec<u8>) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let written = self.socket.send(&payload).await?;
            if written != payload.len() {
                return Err(ProxyError::relay(format!(
                    "direct udp send truncated: wrote {written} of {} bytes",
                    payload.len()
                )));
            }
            Ok(())
        })
    }

    fn recv_packet(&self) -> BoxFuture<'_, Vec<u8>> {
        Box::pin(async move {
            let mut buf = vec![0u8; u16::MAX as usize];
            let size = self.socket.recv(&mut buf).await?;
            buf.truncate(size);
            Ok(buf)
        })
    }
}

fn log_udp_connect_attempt(
    ctx: &DialContext,
    host_field: &str,
    port: u16,
    address: SocketAddr,
    routing_mark: Option<u32>,
    attempt_index: u64,
    timeout_duration: Option<Duration>,
) {
    debug!(
        event = "udp_connect_attempt",
        session_id = ctx.session_id,
        outbound = %sanitize_field(&ctx.outbound_tag),
        host = %host_field,
        port = port as u64,
        resolved_addr = %address,
        routing_mark = ?routing_mark,
        attempt_index,
        timeout_ms = timeout_duration.map(|duration| duration.as_millis() as u64),
        network = %"udp",
        "udp connect attempt"
    );
}

fn log_udp_connect_success(
    ctx: &DialContext,
    host_field: &str,
    port: u16,
    address: SocketAddr,
    routing_mark: Option<u32>,
    attempt_index: u64,
) {
    info!(
        event = "udp_connect_success",
        session_id = ctx.session_id,
        outbound = %sanitize_field(&ctx.outbound_tag),
        host = %host_field,
        port = port as u64,
        resolved_addr = %address,
        routing_mark = ?routing_mark,
        attempt_index,
        network = %"udp",
        "udp connect success"
    );
}

fn log_udp_connect_failed(
    ctx: &DialContext,
    host_field: &str,
    port: u16,
    address: SocketAddr,
    routing_mark: Option<u32>,
    attempt_index: u64,
    err: &ProxyError,
) {
    warn!(
        event = "udp_connect_failed",
        session_id = ctx.session_id,
        outbound = %sanitize_field(&ctx.outbound_tag),
        host = %host_field,
        port = port as u64,
        resolved_addr = %address,
        routing_mark = ?routing_mark,
        attempt_index,
        network = %"udp",
        error_kind = ?err.kind(),
        error = %err,
        "udp connect failed"
    );
}
