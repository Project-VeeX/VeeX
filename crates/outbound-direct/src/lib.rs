//! Direct outbound implementation kept outside `veex-core` so platform-specific
//! egress behavior can evolve without polluting core runtime abstractions.

use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::{lookup_host, TcpStream},
    time::timeout,
};
use veex_core::{
    error::{ProxyError, Result},
    traits::{BoxFuture, Outbound},
    types::{BoxedAsyncStream, Host, SessionContext},
};

type MarkedConnector = dyn Fn(SocketAddr, u32) -> BoxFuture<'static, TcpStream> + Send + Sync;

#[derive(Clone)]
pub struct DirectOutbound {
    tag: String,
    connect_timeout: Option<Duration>,
    routing_mark: Option<u32>,
    marked_connector: Arc<MarkedConnector>,
}

impl fmt::Debug for DirectOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectOutbound")
            .field("tag", &self.tag)
            .field("connect_timeout", &self.connect_timeout)
            .field("routing_mark", &self.routing_mark)
            .finish()
    }
}

impl DirectOutbound {
    pub fn new(tag: impl Into<String>, routing_mark: Option<u32>) -> Result<Self> {
        if routing_mark.is_some() && !cfg!(target_os = "linux") {
            return Err(ProxyError::Config(
                "direct outbound routing_mark is only supported on linux".into(),
            ));
        }

        Ok(Self {
            tag: tag.into(),
            connect_timeout: Some(Duration::from_secs(10)),
            routing_mark,
            marked_connector: Arc::new(|address, routing_mark| {
                Box::pin(connect_marked_socket(address, routing_mark))
            }),
        })
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
        let routing_mark = self.routing_mark;
        let marked_connector = Arc::clone(&self.marked_connector);

        Box::pin(async move {
            let addresses = resolve_destination(&destination.host, destination.port).await?;
            let mut last_error = None;

            for address in addresses {
                match connect_socket(
                    address,
                    timeout_duration,
                    routing_mark,
                    Arc::clone(&marked_connector),
                )
                .await
                {
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

async fn connect_socket(
    address: SocketAddr,
    timeout_duration: Option<Duration>,
    routing_mark: Option<u32>,
    marked_connector: Arc<MarkedConnector>,
) -> Result<TcpStream> {
    let connect_future = async move {
        match routing_mark {
            Some(routing_mark) => marked_connector(address, routing_mark).await,
            None => TcpStream::connect(address).await.map_err(|err| {
                ProxyError::Dial(format!("direct connect failed to {address}: {err}"))
            }),
        }
    };

    match timeout_duration {
        Some(duration) => timeout(duration, connect_future)
            .await
            .map_err(|_| ProxyError::Timeout(format!("direct connect timeout to {address}")))?,
        None => connect_future.await,
    }
}

async fn connect_marked_socket(address: SocketAddr, routing_mark: u32) -> Result<TcpStream> {
    connect_marked_socket_impl(address, routing_mark).await
}

#[cfg(target_os = "linux")]
async fn connect_marked_socket_impl(address: SocketAddr, routing_mark: u32) -> Result<TcpStream> {
    use std::os::fd::AsRawFd;

    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(|err| {
        ProxyError::Dial(format!(
            "failed to create direct socket for {address}: {err}"
        ))
    })?;
    socket.set_nonblocking(true).map_err(|err| {
        ProxyError::Dial(format!(
            "failed to switch direct socket to nonblocking mode for {address}: {err}"
        ))
    })?;
    let mark = routing_mark as libc::c_int;
    // SAFETY: the socket fd is live, the option buffer points to a valid integer,
    // and the length matches the pointed-to value size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(ProxyError::Dial(format!(
            "failed to set SO_MARK={routing_mark} for {address}: {}",
            std::io::Error::last_os_error()
        )));
    }

    match socket.connect(&address.into()) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(err) => {
            return Err(ProxyError::Dial(format!(
                "direct connect failed to {address} with SO_MARK={routing_mark}: {err}"
            )))
        }
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream).map_err(|err| {
        ProxyError::Dial(format!(
            "failed to register marked direct socket for {address} with tokio: {err}"
        ))
    })?;
    stream.writable().await.map_err(|err| {
        ProxyError::Dial(format!(
            "marked direct socket did not become writable for {address}: {err}"
        ))
    })?;
    if let Some(err) = stream.take_error().map_err(|err| {
        ProxyError::Dial(format!(
            "failed to inspect marked direct socket error for {address}: {err}"
        ))
    })? {
        return Err(ProxyError::Dial(format!(
            "direct connect failed to {address} with SO_MARK={routing_mark}: {err}"
        )));
    }

    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
async fn connect_marked_socket_impl(address: SocketAddr, _routing_mark: u32) -> Result<TcpStream> {
    Err(ProxyError::Config(format!(
        "direct outbound routing_mark is not supported on this platform for {address}"
    )))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::net::{TcpListener, TcpStream};
    use veex_core::{
        BoxFuture, Destination, Host, Network, Outbound, ProxyError, SessionContext, SessionMeta,
    };

    use super::DirectOutbound;

    #[test]
    fn direct_outbound_is_constructible_for_dispatcher_registration() {
        let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        let mut direct = DirectOutbound::new("direct", None).expect("direct outbound should build");
        direct.set_connect_timeout(Some(Duration::from_secs(1)));
        outbounds.insert("direct".into(), Arc::new(direct));

        assert_eq!(outbounds.len(), 1);
    }

    #[tokio::test]
    async fn direct_outbound_uses_marked_connector_when_routing_mark_is_set() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener addr should exist");
        let captured_mark = Arc::new(Mutex::new(None));
        let captured_mark_for_connector = Arc::clone(&captured_mark);
        let connector = Arc::new(move |connect_address, routing_mark| {
            let captured_mark = Arc::clone(&captured_mark_for_connector);
            Box::pin(async move {
                *captured_mark.lock().expect("mark mutex should lock") = Some(routing_mark);
                TcpStream::connect(connect_address).await.map_err(|err| {
                    ProxyError::Dial(format!(
                        "test marked connector failed to connect to {connect_address}: {err}"
                    ))
                })
            }) as BoxFuture<'static, TcpStream>
        });
        let direct = DirectOutbound {
            tag: "direct".into(),
            connect_timeout: Some(Duration::from_secs(1)),
            routing_mark: Some(9),
            marked_connector: connector,
        };
        let ctx = SessionContext::new(
            SessionMeta {
                id: 1,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: "127.0.0.1:30000".parse().expect("peer addr should parse"),
                destination: Destination::new(Host::Ip(address.ip()), address.port()),
                start: std::time::Instant::now(),
            },
            Vec::new(),
        );

        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept should succeed");
        });
        let stream = direct
            .connect(&ctx)
            .await
            .expect("marked direct outbound should connect");
        drop(stream);
        accept_task.await.expect("accept task should join");

        assert_eq!(
            *captured_mark.lock().expect("mark mutex should lock"),
            Some(9)
        );
    }
}
