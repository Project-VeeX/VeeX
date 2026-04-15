use std::{net::SocketAddr, sync::Arc};

use tokio::net::TcpListener;
use veex_core::{Listen, Listener, ListenerFactory};
use veex_infra_linux::create_transparent_listener;

use super::error::Result;

pub fn create_tproxy_stream_listener(listen: Listen) -> Listener {
    let factory: Arc<ListenerFactory> =
        Arc::new(|addr| Box::pin(async move { create_tproxy_listener(addr).map_err(Into::into) }));
    Listener::new(listen, factory)
}

pub fn create_tproxy_listener(addr: SocketAddr) -> Result<TcpListener> {
    let listener = create_transparent_listener(addr)?;
    TcpListener::from_std(listener).map_err(Into::into)
}
