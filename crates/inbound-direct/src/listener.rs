use std::{
    io,
    net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    sync::Arc,
};

use tokio::net::{TcpListener, UdpSocket};
use veex_core::{Listen, Listener, ListenerFactory, PacketListener, PacketListenerFactory};

use super::error::Result;

pub fn create_direct_stream_listener(listen: Listen) -> Listener {
    let factory: Arc<ListenerFactory> =
        Arc::new(|addr| Box::pin(async move { create_direct_listener(addr).map_err(Into::into) }));
    Listener::new(listen, factory)
}

pub fn create_direct_listener(addr: SocketAddr) -> Result<TcpListener> {
    let listener = create_std_listener(addr)?;
    TcpListener::from_std(listener).map_err(Into::into)
}

pub fn create_direct_packet_listener(listen: Listen) -> PacketListener {
    let factory: Arc<PacketListenerFactory> = Arc::new(|addr| {
        Box::pin(async move { create_direct_udp_socket(addr).map_err(Into::into) })
    });
    PacketListener::new(listen, factory)
}

pub fn create_direct_udp_socket(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = create_std_udp_socket(addr)?;
    UdpSocket::from_std(socket).map_err(Into::into)
}

#[cfg(target_os = "linux")]
fn create_std_listener(addr: SocketAddr) -> io::Result<StdTcpListener> {
    veex_infra_linux::create_dual_stack_listener(addr).map_err(|err| match err {
        veex_infra_linux::TransparentError::Io(source) => source,
        other => io::Error::other(other.to_string()),
    })
}

#[cfg(not(target_os = "linux"))]
fn create_std_listener(addr: SocketAddr) -> io::Result<StdTcpListener> {
    let listener = StdTcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(target_os = "linux")]
fn create_std_udp_socket(addr: SocketAddr) -> io::Result<StdUdpSocket> {
    veex_infra_linux::create_dual_stack_udp_socket(addr)
}

#[cfg(not(target_os = "linux"))]
fn create_std_udp_socket(addr: SocketAddr) -> io::Result<StdUdpSocket> {
    let socket = StdUdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}
