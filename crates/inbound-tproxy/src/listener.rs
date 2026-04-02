use std::net::SocketAddr;

use tokio::net::TcpListener;
use veex_infra_linux::create_transparent_listener;

use crate::error::Result;

pub fn create_tproxy_listener(addr: SocketAddr) -> Result<TcpListener> {
    let listener = create_transparent_listener(addr)?;
    Ok(TcpListener::from_std(listener)?)
}
