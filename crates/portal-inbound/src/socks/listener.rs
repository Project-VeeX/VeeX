use std::sync::Arc;

use tokio::net::TcpListener;
use veex_core::{Listen, Listener, ListenerFactory};

pub fn create_socks_listener(listen: Listen) -> Listener {
    let factory: Arc<ListenerFactory> =
        Arc::new(|addr| Box::pin(async move { Ok(TcpListener::bind(addr).await?) }));
    Listener::new(listen, factory)
}
