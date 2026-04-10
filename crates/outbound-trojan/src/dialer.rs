use std::{net::IpAddr, str::FromStr, sync::Arc, time::Duration};

use tokio::net::TcpStream;
use veex_core::{BoxFuture, BoxedAsyncStream, Host, Result};
use veex_transport::{
    connect_host, connect_tls, ConnectTraceContext, TcpConnectOptions, TlsClientOptions,
};

pub(crate) type TcpConnector =
    dyn Fn(Host, u16, TcpConnectOptions) -> BoxFuture<'static, TcpStream> + Send + Sync;

pub(crate) fn system_tcp_connector() -> Arc<TcpConnector> {
    Arc::new(|host, port, options| {
        Box::pin(async move { connect_host(&host, port, options).await })
    })
}

pub(crate) fn parse_host(value: &str) -> Host {
    match IpAddr::from_str(value) {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(value.to_string()),
    }
}

pub(crate) async fn connect_server(
    server: &Host,
    server_port: u16,
    tls: &TlsClientOptions,
    connect_timeout: Duration,
    trace: &ConnectTraceContext,
    connector: &Arc<TcpConnector>,
) -> Result<BoxedAsyncStream> {
    let stream = connector(
        server.clone(),
        server_port,
        TcpConnectOptions {
            timeout: Some(connect_timeout),
            trace: Some(trace.clone()),
            connector: None,
        },
    )
    .await?;

    connect_tls(stream, server, server_port, tls, Some(trace)).await
}
