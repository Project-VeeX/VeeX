use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tokio::net::TcpStream;
use tracing::{info, warn};
use veex_core::{
    sanitize_field, BoxFuture, BoxedAsyncStream, Destination, Dispatcher, Inbound, InboundMeta,
    Listener, ListenerAcceptHandler, Logger, Network, ProxyError, Result, TransparentInbound,
};
use veex_infra_linux::get_tproxy_dst;

use crate::shared::session::{build_session_bootstrap, SessionBootstrap};

use super::error::Result as TProxyResult;

type ResolveDestination = dyn Fn(&TcpStream) -> TProxyResult<Destination> + Send + Sync;

fn resolve_tproxy_destination(stream: &TcpStream) -> TProxyResult<Destination> {
    let destination = get_tproxy_dst(stream)?;
    Ok(Destination::from_ip(destination.ip(), destination.port()))
}

struct TProxyInboundState {
    next_session_id: AtomicU64,
}

pub struct TProxyInbound {
    meta: InboundMeta,
    logger: Logger,
    router: Arc<dyn Dispatcher>,
    listener: Listener,
    network: Network,
    destination_resolver: Arc<ResolveDestination>,
    state: Arc<TProxyInboundState>,
}

impl TProxyInbound {
    pub fn new(
        meta: InboundMeta,
        logger: Logger,
        router: Arc<dyn Dispatcher>,
        listener: Listener,
        network: Network,
    ) -> Result<Arc<Self>> {
        Self::new_with_resolver(
            meta,
            logger,
            router,
            listener,
            network,
            Arc::new(resolve_tproxy_destination),
        )
    }

    fn new_with_resolver(
        meta: InboundMeta,
        logger: Logger,
        router: Arc<dyn Dispatcher>,
        listener: Listener,
        network: Network,
        resolver: Arc<ResolveDestination>,
    ) -> Result<Arc<Self>> {
        let inbound = Arc::new(Self {
            meta,
            logger,
            router,
            listener,
            network,
            destination_resolver: resolver,
            state: Arc::new(TProxyInboundState {
                next_session_id: AtomicU64::new(1),
            }),
        });
        inbound.validate()?;
        inbound.bind_listener_handler()?;
        Ok(inbound)
    }

    pub fn validate(&self) -> Result<()> {
        if self.meta.tag.trim().is_empty() {
            return Err(ProxyError::config("tproxy inbound tag must not be empty"));
        }
        if self.meta.r#type.trim().is_empty() {
            return Err(ProxyError::config("tproxy inbound type must not be empty"));
        }
        if self.listener.listen().listen().trim().is_empty() {
            return Err(ProxyError::config(
                "tproxy inbound listen must not be empty",
            ));
        }
        if self.listener.listen().listen_port() == 0 {
            return Err(ProxyError::config(
                "tproxy inbound listen_port must be within 1..=65535",
            ));
        }
        self.listener.bind_addr().map(|_| ())
    }

    fn bind_listener_handler(self: &Arc<Self>) -> Result<()> {
        let inbound = Arc::clone(self);
        let handler: Arc<ListenerAcceptHandler> = Arc::new(move |stream, peer| {
            let inbound = Arc::clone(&inbound);
            Box::pin(async move {
                if let Err(err) = inbound.accept_transparent_stream(stream, peer).await {
                    inbound.log_connection_failed(peer, &err);
                }
            })
        });
        self.listener.bind_handler(handler)
    }

    fn next_session_id(&self) -> u64 {
        self.state.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    fn bootstrap_session(&self, peer: SocketAddr, destination: Destination) -> SessionBootstrap {
        let session_id = self.next_session_id();
        build_session_bootstrap(session_id, self.meta.tag.as_str(), peer, destination)
    }

    async fn handle_stream(&self, stream: TcpStream, peer: SocketAddr) -> Result<()> {
        let local_addr = stream.local_addr().ok();
        let socket_family = local_addr
            .map(|addr| if addr.is_ipv4() { "ipv4" } else { "ipv6" })
            .unwrap_or("unknown");
        let listen_field = sanitize_field(self.listener.listen().listen()).into_owned();
        let destination = match (self.destination_resolver)(&stream) {
            Ok(destination) => destination,
            Err(err) => {
                warn!(
                    event = "destination_resolve_failed",
                    inbound = %self.logger.tag_field(),
                    listen = %listen_field,
                    peer = %sanitize_field(&peer.to_string()),
                    local_addr = ?local_addr,
                    socket_family = %socket_family,
                    error = %err,
                    "tproxy destination lookup failed"
                );
                return Err(err.into());
            }
        };
        let session = self.bootstrap_session(peer, destination);
        info!(
            event = "session_start",
            session_id = session.id,
            inbound = %session.inbound_field,
            listen = %listen_field,
            peer = %session.peer_field,
            local_addr = ?local_addr,
            destination = %session.destination_field,
            socket_family = %socket_family,
            network = %self.network.as_str(),
            "tproxy session start"
        );

        let stream: BoxedAsyncStream = Box::new(stream);
        let result = self.router.dispatch(stream, session.ctx).await;
        if let Err(err) = &result {
            warn!(
                event = "session_failed",
                session_id = session.id,
                inbound = %session.inbound_field,
                listen = %listen_field,
                peer = %session.peer_field,
                local_addr = ?local_addr,
                destination = %session.destination_field,
                socket_family = %socket_family,
                error_kind = ?err.kind(),
                error = %err,
                "tproxy session failed"
            );
        }
        result
    }

    fn log_connection_failed(&self, peer: SocketAddr, err: &ProxyError) {
        let peer_field = peer.to_string();
        let peer_field = sanitize_field(&peer_field).into_owned();
        warn!(
            event = "inbound_connection_failed",
            inbound = %self.logger.tag_field(),
            peer = %peer_field,
            error_kind = ?err.kind(),
            error = %err,
            "tproxy inbound connection failed"
        );
    }
}

impl Inbound for TProxyInbound {
    fn meta(&self) -> &InboundMeta {
        &self.meta
    }

    fn logger(&self) -> &Logger {
        &self.logger
    }

    fn start(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.validate()?;
            self.listener.start().await
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.listener.close().await })
    }
}

impl TransparentInbound for TProxyInbound {
    fn accept_transparent_stream(&self, stream: TcpStream, peer: SocketAddr) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.handle_stream(stream, peer).await })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::{net::TcpListener, net::TcpStream, sync::oneshot};
    use veex_core::{
        BoxFuture, Destination, Dispatcher, Inbound, InboundMeta, Listener, ListenerFactory,
        Logger, Network,
    };

    use super::{ResolveDestination, TProxyInbound};
    use crate::TProxyError;

    struct RecordingDispatcher {
        tx: Mutex<Option<oneshot::Sender<Destination>>>,
    }

    impl Dispatcher for RecordingDispatcher {
        fn dispatch(
            &self,
            _inbound_stream: veex_core::BoxedAsyncStream,
            ctx: veex_core::SessionContext,
        ) -> BoxFuture<'_, ()> {
            let destination = ctx.meta.destination.clone();
            let tx = self.tx.lock().expect("tx mutex should lock").take();
            Box::pin(async move {
                tx.expect("sender should exist")
                    .send(destination)
                    .expect("destination should be sent");
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn tproxy_inbound_forwards_resolved_destination_to_dispatcher() {
        let listen_addr = reserve_local_port().await;
        let expected = Destination::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443);
        let resolver = fixed_resolver(expected.clone());
        let (tx, rx) = oneshot::channel();
        let dispatcher: Arc<dyn Dispatcher> = Arc::new(RecordingDispatcher {
            tx: Mutex::new(Some(tx)),
        });
        let inbound = TProxyInbound::new_with_resolver(
            InboundMeta::new("tproxy-in", "tproxy"),
            Logger::new("tproxy-in", "tproxy"),
            dispatcher,
            test_listener(
                listen_addr,
                Arc::new(|addr| {
                    let listener = std::net::TcpListener::bind(addr)?;
                    listener.set_nonblocking(true)?;
                    Ok(TcpListener::from_std(listener)?)
                }),
            ),
            Network::Tcp,
            resolver,
        )
        .expect("tproxy inbound should build");

        inbound.start().await.expect("tproxy should start");
        let _client = connect_with_retry(listen_addr).await;
        let received = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("dispatcher should receive destination")
            .expect("destination should be delivered");
        assert_eq!(received, expected);
        inbound.close().await.expect("tproxy should close");
    }

    #[test]
    fn parses_unspecified_ipv6_listen_addr() {
        let inbound = TProxyInbound::new_with_resolver(
            InboundMeta::new("tproxy-in", "tproxy"),
            Logger::new("tproxy-in", "tproxy"),
            Arc::new(RecordingDispatcher {
                tx: Mutex::new(None),
            }),
            test_listener(
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041)),
                Arc::new(|addr| {
                    let listener = std::net::TcpListener::bind(addr)?;
                    listener.set_nonblocking(true)?;
                    Ok(TcpListener::from_std(listener)?)
                }),
            ),
            Network::Tcp,
            fixed_resolver(Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)),
        )
        .expect("tproxy inbound should build");
        assert_eq!(
            inbound
                .listener
                .bind_addr()
                .expect("tproxy ipv6 listen should parse"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041))
        );
    }

    fn fixed_resolver(destination: Destination) -> Arc<ResolveDestination> {
        Arc::new(
            move |_stream: &TcpStream| -> super::TProxyResult<Destination> {
                Ok(destination.clone())
            },
        )
    }

    fn test_listener(
        addr: SocketAddr,
        factory: Arc<
            dyn Fn(SocketAddr) -> std::result::Result<TcpListener, TProxyError> + Send + Sync,
        >,
    ) -> Listener {
        let listen = veex_core::Listen::new(addr.ip().to_string(), addr.port());
        let factory: Arc<ListenerFactory> = Arc::new(move |addr| {
            let factory = Arc::clone(&factory);
            Box::pin(async move { factory(addr).map_err(Into::into) })
        });
        Listener::new(listen, factory)
    }

    async fn reserve_local_port() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("temporary listener should bind");
        listener.local_addr().expect("temporary addr should exist")
    }

    async fn connect_with_retry(addr: SocketAddr) -> TcpStream {
        for _ in 0..50 {
            if let Ok(stream) = TcpStream::connect(addr).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        panic!("listener did not become ready on {addr}");
    }
}
