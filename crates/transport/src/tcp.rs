use std::{net::SocketAddr, time::Duration};

use tokio::{
    net::{lookup_host, TcpStream},
    time::timeout,
};
use tracing::debug;
use veex_core::{sanitize_field, Host, ProxyError, Result};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpConnectOptions {
    pub timeout: Option<Duration>,
}

pub async fn connect_host(host: &Host, port: u16, options: TcpConnectOptions) -> Result<TcpStream> {
    let addresses = resolve_host(host, port).await?;
    let mut last_error = None;
    let host_field = host.to_string();
    let host_field = sanitize_field(&host_field).into_owned();

    for (attempt_index, address) in addresses.into_iter().enumerate() {
        if let Some(duration) = options.timeout {
            debug!(
                event = "tcp_connect_attempt",
                host = %host_field,
                port,
                resolved_addr = %address,
                timeout_ms = duration.as_millis(),
                attempt_index = attempt_index + 1,
                "tcp connect attempt"
            );
        } else {
            debug!(
                event = "tcp_connect_attempt",
                host = %host_field,
                port,
                resolved_addr = %address,
                attempt_index = attempt_index + 1,
                "tcp connect attempt"
            );
        }

        match connect_socket(address, options).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error
        .unwrap_or_else(|| ProxyError::dial(format!("no reachable address for {host}:{port}"))))
}

async fn resolve_host(host: &Host, port: u16) -> Result<Vec<SocketAddr>> {
    match host {
        Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
        Host::Domain(domain) => {
            let addresses = lookup_host((domain.as_str(), port)).await.map_err(|err| {
                ProxyError::resolve_ctx(format!("failed to resolve {domain}:{port}"), err)
            })?;
            let addresses: Vec<_> = addresses.collect();
            if addresses.is_empty() {
                return Err(ProxyError::resolve(format!(
                    "resolver returned no addresses for {domain}:{port}"
                )));
            }
            Ok(addresses)
        }
    }
}

async fn connect_socket(address: SocketAddr, options: TcpConnectOptions) -> Result<TcpStream> {
    let connect_future = TcpStream::connect(address);

    match options.timeout {
        Some(duration) => timeout(duration, connect_future)
            .await
            .map_err(|_| ProxyError::timeout(format!("tcp connect timeout to {address}")))?
            .map_err(|err| ProxyError::dial_ctx(format!("tcp connect failed to {address}"), err)),
        None => connect_future
            .await
            .map_err(|err| ProxyError::dial_ctx(format!("tcp connect failed to {address}"), err)),
    }
}
