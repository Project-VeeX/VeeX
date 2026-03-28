use std::{net::SocketAddr, time::Duration};

use tokio::{net::{lookup_host, TcpStream}, time::timeout};

use crate::{
    error::{ProxyError, Result},
    traits::{BoxFuture, Outbound},
    types::{BoxedAsyncStream, Host, SessionContext},
};

#[derive(Clone, Debug)]
pub struct DirectOutbound {
    tag: String,
    connect_timeout: Option<Duration>,
}

impl DirectOutbound {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            connect_timeout: Some(Duration::from_secs(10)),
        }
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn set_connect_timeout(&mut self, timeout: Option<Duration>) {
        self.connect_timeout = timeout;
    }
}

impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn connect(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
        let destination = ctx.meta.destination.clone();
        let timeout_duration = self.connect_timeout;

        Box::pin(async move {
            let addresses = resolve_destination(&destination.host, destination.port).await?;
            let mut last_error = None;

            for address in addresses {
                match connect_socket(address, timeout_duration).await {
                    Ok(stream) => return Ok(Box::new(stream) as BoxedAsyncStream),
                    Err(err) => last_error = Some(err),
                }
            }

            Err(last_error.unwrap_or_else(|| {
                ProxyError::Dial(format!(
                    "direct outbound found no reachable address for {}",
                    destination
                ))
            }))
        })
    }
}

async fn resolve_destination(host: &Host, port: u16) -> Result<Vec<SocketAddr>> {
    match host {
        Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
        Host::Domain(domain) => {
            let addresses = lookup_host((domain.as_str(), port))
                .await
                .map_err(|err| ProxyError::Resolve(format!("failed to resolve {domain}:{port}: {err}")))?;
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

async fn connect_socket(address: SocketAddr, timeout_duration: Option<Duration>) -> Result<TcpStream> {
    let connect_future = TcpStream::connect(address);

    match timeout_duration {
        Some(duration) => timeout(duration, connect_future)
            .await
            .map_err(|_| ProxyError::Timeout(format!("direct connect timeout to {address}")))?
            .map_err(|err| ProxyError::Dial(format!("direct connect failed to {address}: {err}"))),
        None => connect_future
            .await
            .map_err(|err| ProxyError::Dial(format!("direct connect failed to {address}: {err}"))),
    }
}
