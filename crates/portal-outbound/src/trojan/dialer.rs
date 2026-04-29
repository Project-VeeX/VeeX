use std::sync::Arc;

use tokio::net::TcpStream;
use veex_core::portal::{Dial, Dialer};
use veex_transport::{
    HostResolver, TcpAttemptConnector, TcpConnectOptions, connect_host_with_resolver, resolve_host,
};

#[cfg_attr(not(test), allow(dead_code))]
pub fn system_host_resolver() -> Arc<HostResolver> {
    Arc::new(|request| Box::pin(async move { resolve_host(&request.host, request.port).await }))
}

pub fn system_tcp_connector() -> Arc<TcpAttemptConnector> {
    Arc::new(|address| Box::pin(async move { TcpStream::connect(address).await }))
}

pub fn build_dialer(dial: Dial, resolver: Arc<HostResolver>) -> Dialer {
    build_dialer_with_connector(dial, resolver, system_tcp_connector())
}

pub fn build_dialer_with_connector(
    dial: Dial,
    resolver: Arc<HostResolver>,
    connector: Arc<TcpAttemptConnector>,
) -> Dialer {
    Dialer::new(
        dial,
        Arc::new(move |host, port, dial, ctx| {
            let resolver = Arc::clone(&resolver);
            let connector = Arc::clone(&connector);
            Box::pin(async move {
                let mut options = TcpConnectOptions::from_dial(&dial, &ctx);
                options.connector = Some(connector);
                connect_host_with_resolver(
                    &host,
                    port,
                    dial.resolve_context(ctx.resolve_context.as_ref(), ctx.outbound_tag.clone()),
                    resolver.as_ref(),
                    options,
                )
                .await
            })
        }),
    )
}
