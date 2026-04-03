use std::net::SocketAddr;

use tokio::net::TcpListener;
use veex_infra_linux::create_dual_stack_listener;

use crate::error::Result;

pub fn create_redirect_listener(addr: SocketAddr) -> Result<TcpListener> {
    let listener = create_dual_stack_listener(addr)?;
    Ok(TcpListener::from_std(listener)?)
}
