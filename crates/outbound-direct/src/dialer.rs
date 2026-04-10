use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;
use veex_core::{Destination, Result};
use veex_transport::{
    connect_host_with_resolver, resolve_host, ConnectTraceContext, HostResolver,
    TcpAttemptConnector, TcpConnectOptions,
};

use crate::error::{io_error_with_context, last_os_error_with_context};

pub(crate) type MarkedConnectorFuture =
    Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'static>>;
pub(crate) type MarkedConnector = dyn Fn(SocketAddr, u32) -> MarkedConnectorFuture + Send + Sync;

pub(crate) fn system_host_resolver() -> Arc<HostResolver> {
    Arc::new(|host, port| Box::pin(async move { resolve_host(&host, port).await }))
}

pub(crate) async fn connect_destination(
    destination: &Destination,
    resolver: &HostResolver,
    connect_timeout: Duration,
    trace: ConnectTraceContext,
    routing_mark: Option<u32>,
    marked_connector: &Arc<MarkedConnector>,
) -> Result<TcpStream> {
    let connector = routing_mark.map(|routing_mark| {
        let marked_connector = Arc::clone(marked_connector);
        Arc::new(move |address| marked_connector(address, routing_mark)) as Arc<TcpAttemptConnector>
    });

    connect_host_with_resolver(
        &destination.host,
        destination.port,
        resolver,
        TcpConnectOptions {
            timeout: Some(connect_timeout),
            trace: Some(trace),
            connector,
        },
    )
    .await
}

pub(crate) async fn connect_marked_socket(
    address: SocketAddr,
    routing_mark: u32,
) -> io::Result<TcpStream> {
    connect_marked_socket_impl(address, routing_mark).await
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
