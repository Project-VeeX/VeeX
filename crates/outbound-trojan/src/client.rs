use std::{net::IpAddr, str::FromStr, time::Duration};

use tokio::io::AsyncWriteExt;
use veex_core::{BoxFuture, BoxedAsyncStream, Host, Outbound, ProxyError, Result, SessionContext};
use veex_transport::{
    connect_host, connect_tls, ConnectTraceContext, TcpConnectOptions, TlsClientOptions,
};

use crate::request::build_trojan_request;

#[derive(Clone, Debug)]
pub struct TrojanOutbound {
    tag: String,
    server: Host,
    server_port: u16,
    password: String,
    tls: TlsClientOptions,
    connect_timeout: Option<Duration>,
}

impl TrojanOutbound {
    pub fn new(
        tag: impl Into<String>,
        server: impl Into<String>,
        server_port: u16,
        password: impl Into<String>,
        tls: TlsClientOptions,
    ) -> Self {
        let server = parse_host(&server.into());
        Self {
            tag: tag.into(),
            server,
            server_port,
            password: password.into(),
            tls,
            connect_timeout: Some(Duration::from_secs(10)),
        }
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn server(&self) -> &Host {
        &self.server
    }

    pub fn server_port(&self) -> u16 {
        self.server_port
    }

    pub fn tls(&self) -> &TlsClientOptions {
        &self.tls
    }

    pub fn set_connect_timeout(&mut self, timeout: Option<Duration>) {
        self.connect_timeout = timeout;
    }

    pub fn validate(&self) -> Result<()> {
        if self.tag.trim().is_empty() {
            return Err(ProxyError::Config(
                "trojan outbound tag must not be empty".into(),
            ));
        }
        if self.password.is_empty() {
            return Err(ProxyError::Config(
                "trojan outbound password must not be empty".into(),
            ));
        }
        if self.server_port == 0 {
            return Err(ProxyError::Config(
                "trojan outbound server_port must be within 1..=65535".into(),
            ));
        }
        self.tls.validate()?;
        Ok(())
    }
}

impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn connect(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
        let this = self.clone();
        let session_id = ctx.meta.id;
        let destination = ctx.meta.destination.clone();
        let buffered_payload = ctx.state.buffered_payload.clone();

        Box::pin(async move {
            this.validate()?;
            let trace = ConnectTraceContext {
                session_id,
                outbound: this.tag.clone(),
            };

            let stream = connect_host(
                &this.server,
                this.server_port,
                TcpConnectOptions {
                    timeout: this.connect_timeout,
                    trace: Some(trace.clone()),
                },
            )
            .await?;

            let mut stream = connect_tls(stream, &this.server, &this.tls, Some(&trace)).await?;
            let request = build_trojan_request(&this.password, &destination, &buffered_payload)?;
            stream.write_all(&request).await.map_err(|err| {
                ProxyError::Protocol(format!("failed to write trojan request: {err}"))
            })?;

            Ok(stream)
        })
    }
}

fn parse_host(value: &str) -> Host {
    match IpAddr::from_str(value) {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(value.to_string()),
    }
}
