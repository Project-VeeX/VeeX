use std::net::SocketAddr;

use tokio::net::TcpListener;
use veex_infra_linux::create_transparent_listener;

use super::error::Result;

pub fn create_tproxy_listener(addr: SocketAddr) -> Result<TcpListener> {
    let listener = create_transparent_listener(addr)?;
    TcpListener::from_std(listener).map_err(Into::into)
}
