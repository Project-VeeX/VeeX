use std::sync::Arc;

use tokio::net::TcpStream;
use veex_core::{Dial, DialContext, Dialer, ResolveContext};
use veex_transport::{
    connect_host_with_resolver, resolve_host, ConnectTraceContext, HostResolver,
    TcpAttemptConnector, TcpConnectOptions,
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
                connect_host_with_resolver(
                    &host,
                    port,
                    build_resolve_context(&dial, &ctx),
                    resolver.as_ref(),
                    TcpConnectOptions {
                        timeout: dial.connect_timeout,
                        trace: Some(ConnectTraceContext {
                            session_id: ctx.session_id,
                            outbound: ctx.outbound_tag,
                            routing_mark: dial.routing_mark,
                        }),
                        connector: Some(connector),
                    },
                )
                .await
            })
        }),
    )
}

fn build_resolve_context(dial: &Dial, ctx: &DialContext) -> ResolveContext {
    ctx.resolve_context.clone().unwrap_or_else(|| {
        ResolveContext::outbound_dial(ctx.outbound_tag.clone(), dial.domain_resolver.clone())
    })
}
