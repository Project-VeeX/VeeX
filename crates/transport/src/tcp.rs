use std::{net::SocketAddr, time::Duration};

use tokio::{
    net::{lookup_host, TcpStream},
    time::timeout,
};
use veex_core::{Host, ProxyError, Result};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpConnectOptions {
    pub timeout: Option<Duration>,
}

pub async fn connect_host(host: &Host, port: u16, options: TcpConnectOptions) -> Result<TcpStream> {
    let addresses = resolve_host(host, port).await?;
    let mut last_error = None;

    for address in addresses {
        match connect_socket(address, options).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error
        .unwrap_or_else(|| ProxyError::Dial(format!("no reachable address for {host}:{port}"))))
}

async fn resolve_host(host: &Host, port: u16) -> Result<Vec<SocketAddr>> {
    match host {
        Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
        Host::Domain(domain) => {
            let addresses = lookup_host((domain.as_str(), port)).await.map_err(|err| {
                ProxyError::Resolve(format!("failed to resolve {domain}:{port}: {err}"))
            })?;
            let addresses: Vec<_> = addresses.collect();
            if addresses.is_empty() {
                return Err(ProxyError::Resolve(format!(
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
            .map_err(|_| ProxyError::Timeout(format!("tcp connect timeout to {address}")))?
            .map_err(|err| ProxyError::Dial(format!("tcp connect failed to {address}: {err}"))),
        None => connect_future
            .await
            .map_err(|err| ProxyError::Dial(format!("tcp connect failed to {address}: {err}"))),
    }
}
