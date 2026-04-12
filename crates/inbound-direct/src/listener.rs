use std::{
    io,
    net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
};

use tokio::net::{TcpListener, UdpSocket};

use super::error::Result;

pub fn create_direct_listener(addr: SocketAddr) -> Result<TcpListener> {
    let listener = create_std_listener(addr)?;
    Ok(TcpListener::from_std(listener)?)
}

pub fn create_direct_udp_socket(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = create_std_udp_socket(addr)?;
    Ok(UdpSocket::from_std(socket)?)
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
