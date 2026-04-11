use std::{net::IpAddr, str::FromStr, sync::Arc};

use tokio::net::TcpStream;
use veex_core::{BoxFuture, Dial, Dialer, Host};
use veex_transport::{connect_host, ConnectTraceContext, TcpConnectOptions};

pub type TcpConnector =
    dyn Fn(Host, u16, TcpConnectOptions) -> BoxFuture<'static, TcpStream> + Send + Sync;

pub fn system_tcp_connector() -> Arc<TcpConnector> {
    Arc::new(|host, port, options| {
        Box::pin(async move { connect_host(&host, port, options).await })
    })
}

pub fn build_dialer(dial: Dial) -> Dialer {
    build_dialer_with_connector(dial, system_tcp_connector())
}

pub fn build_dialer_with_connector(dial: Dial, connector: Arc<TcpConnector>) -> Dialer {
    Dialer::new(
        dial,
        Arc::new(move |host, port, dial, ctx| {
            let connector = Arc::clone(&connector);
            Box::pin(async move {
                connector(
                    host,
                    port,
                    TcpConnectOptions {
                        timeout: dial.timeout,
                        trace: Some(ConnectTraceContext {
                            session_id: ctx.session_id,
                            outbound: ctx.outbound_tag,
                            routing_mark: dial.routing_mark,
                        }),
                        connector: None,
                    },
                )
                .await
            })
        }),
    )
}

pub(crate) fn parse_host(value: &str) -> Host {
    match IpAddr::from_str(value) {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(value.to_string()),
    }
}
