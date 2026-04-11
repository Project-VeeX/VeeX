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
    build_session_bootstrap, sanitize_field, BoxFuture, BoxedAsyncStream, Destination, Host,
    Inbound, InboundMeta, InboundSink, Listener, ListenerAcceptHandler, Logger, ProxyError, Result,
    SessionBootstrap, StreamInbound,
};

use crate::DirectError;

struct DirectInboundState {
    next_session_id: AtomicU64,
}

pub struct DirectInbound {
    meta: InboundMeta,
    logger: Logger,
    sink: Arc<dyn InboundSink>,
    listener: Listener,
    override_host: Option<Host>,
    override_port: Option<u16>,
    state: Arc<DirectInboundState>,
}

impl DirectInbound {
    pub fn new(
        meta: InboundMeta,
        logger: Logger,
        sink: Arc<dyn InboundSink>,
        listener: Listener,
        override_host: Option<Host>,
        override_port: Option<u16>,
    ) -> Result<Arc<Self>> {
        let inbound = Arc::new(Self {
            meta,
            logger,
            sink,
            listener,
            override_host,
            override_port,
            state: Arc::new(DirectInboundState {
                next_session_id: AtomicU64::new(1),
            }),
        });
        inbound.validate()?;
        inbound.bind_listener_handler()?;
        Ok(inbound)
    }

    pub fn validate(&self) -> Result<()> {
        if self.meta.tag.trim().is_empty() {
            return Err(ProxyError::config("direct inbound tag must not be empty"));
        }
        if self.meta.r#type.trim().is_empty() {
            return Err(ProxyError::config("direct inbound type must not be empty"));
        }
        if self.listener.listen().listen().trim().is_empty() {
            return Err(ProxyError::config(
                "direct inbound listen must not be empty",
            ));
        }
        if self.listener.listen().listen_port() == 0 {
            return Err(ProxyError::config(
                "direct inbound listen_port must be within 1..=65535",
            ));
        }
        if matches!(self.override_host.as_ref(), Some(Host::Domain(domain)) if domain.trim().is_empty())
        {
            return Err(ProxyError::config(
                "direct inbound override_address must not be empty",
            ));
        }
        if matches!(self.override_port, Some(0)) {
            return Err(ProxyError::config(
                "direct inbound override_port must be within 1..=65535",
            ));
        }
        self.listener.bind_addr().map(|_| ())
    }

    fn bind_listener_handler(self: &Arc<Self>) -> Result<()> {
        let inbound = Arc::clone(self);
        let handler: Arc<ListenerAcceptHandler> = Arc::new(move |stream, peer| {
            let inbound = Arc::clone(&inbound);
            Box::pin(async move {
                if let Err(err) = inbound.accept_stream(stream, peer).await {
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
        build_session_bootstrap(
            self.next_session_id(),
            self.meta.tag.as_str(),
            peer,
            destination,
        )
    }

    fn resolve_destination(
        &self,
        stream: &TcpStream,
    ) -> std::result::Result<Destination, DirectError> {
        let local_addr = stream.local_addr()?;
        let mut destination = Destination::from_ip(local_addr.ip(), local_addr.port());
        if let Some(host) = &self.override_host {
            destination.host = host.clone();
        }
        if let Some(port) = self.override_port {
            destination.port = port;
        }
        Ok(destination)
    }

    async fn handle_stream(&self, stream: TcpStream, peer: SocketAddr) -> Result<()> {
        let destination = match self.resolve_destination(&stream) {
            Ok(destination) => destination,
            Err(err) => {
                warn!(
                    event = "destination_resolve_failed",
                    inbound = %self.logger.tag_field(),
                    peer = %sanitize_field(&peer.to_string()),
                    error = %err,
                    "direct inbound destination lookup failed"
                );
                return Err(err.into());
            }
        };
        let session = self.bootstrap_session(peer, destination);
        info!(
            event = "session_start",
            session_id = session.id,
            inbound = %session.inbound_field,
            peer = %session.peer_field,
            destination = %session.destination_field,
            network = %"tcp",
            "direct session start"
        );

        let stream: BoxedAsyncStream = Box::new(stream);
        let result = self.sink.submit(stream, session.ctx).await;
        if let Err(err) = &result {
            warn!(
                event = "session_failed",
                session_id = session.id,
                inbound = %session.inbound_field,
                peer = %session.peer_field,
                destination = %session.destination_field,
                error_kind = ?err.kind(),
                error = %err,
                "direct session failed"
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
            "direct inbound connection failed"
        );
    }
}

impl Inbound for DirectInbound {
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

impl StreamInbound for DirectInbound {
    fn accept_stream(&self, stream: TcpStream, peer: SocketAddr) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.handle_stream(stream, peer).await })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::{net::TcpListener, net::TcpStream, sync::oneshot};
    use veex_core::{
        BoxFuture, Destination, Host, Inbound, InboundMeta, InboundSink, Listener, ListenerFactory,
        Logger,
    };

    use super::DirectInbound;

    struct RecordingSink {
        tx: Mutex<Option<oneshot::Sender<Destination>>>,
    }

    impl InboundSink for RecordingSink {
        fn submit(
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
    async fn direct_inbound_submits_listener_destination_without_override() {
        let listen_addr = reserve_local_port().await;
        let expected = Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_addr.port());
        let (tx, rx) = oneshot::channel();
        let sink: Arc<dyn InboundSink> = Arc::new(RecordingSink {
            tx: Mutex::new(Some(tx)),
        });
        let inbound = DirectInbound::new(
            InboundMeta::new("direct-in", "direct"),
            Logger::new("direct-in", "direct"),
            sink,
            test_listener(
                listen_addr,
                Arc::new(|addr| {
                    let listener = std::net::TcpListener::bind(addr)?;
                    listener.set_nonblocking(true)?;
                    Ok(TcpListener::from_std(listener)?)
                }),
            ),
            None,
            None,
        )
        .expect("direct inbound should build");

        inbound.start().await.expect("direct should start");
        let _client = connect_with_retry(listen_addr).await;
        let received = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("sink should receive destination")
            .expect("destination should be delivered");
        assert_eq!(received, expected);
        inbound.close().await.expect("direct should close");
    }

    #[tokio::test]
    async fn direct_inbound_applies_override_address_and_port() {
        let listen_addr = reserve_local_port().await;
        let expected = Destination::from_domain("example.com", 8443);
        let (tx, rx) = oneshot::channel();
        let sink: Arc<dyn InboundSink> = Arc::new(RecordingSink {
            tx: Mutex::new(Some(tx)),
        });
        let inbound = DirectInbound::new(
            InboundMeta::new("direct-in", "direct"),
            Logger::new("direct-in", "direct"),
            sink,
            test_listener(
                listen_addr,
                Arc::new(|addr| {
                    let listener = std::net::TcpListener::bind(addr)?;
                    listener.set_nonblocking(true)?;
                    Ok(TcpListener::from_std(listener)?)
                }),
            ),
            Some(Host::Domain("example.com".into())),
            Some(8443),
        )
        .expect("direct inbound should build");

        inbound.start().await.expect("direct should start");
        let _client = connect_with_retry(listen_addr).await;
        let received = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("sink should receive destination")
            .expect("destination should be delivered");
        assert_eq!(received, expected);
        inbound.close().await.expect("direct should close");
    }

    #[tokio::test]
    async fn direct_inbound_applies_partial_port_override() {
        let listen_addr = reserve_local_port().await;
        let expected = Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 9443);
        let (tx, rx) = oneshot::channel();
        let sink: Arc<dyn InboundSink> = Arc::new(RecordingSink {
            tx: Mutex::new(Some(tx)),
        });
        let inbound = DirectInbound::new(
            InboundMeta::new("direct-in", "direct"),
            Logger::new("direct-in", "direct"),
            sink,
            test_listener(
                listen_addr,
                Arc::new(|addr| {
                    let listener = std::net::TcpListener::bind(addr)?;
                    listener.set_nonblocking(true)?;
                    Ok(TcpListener::from_std(listener)?)
                }),
            ),
            None,
            Some(9443),
        )
        .expect("direct inbound should build");

        inbound.start().await.expect("direct should start");
        let _client = connect_with_retry(listen_addr).await;
        let received = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("sink should receive destination")
            .expect("destination should be delivered");
        assert_eq!(received, expected);
        inbound.close().await.expect("direct should close");
    }

    #[test]
    fn direct_inbound_accepts_unspecified_ipv6_listen_addr() {
        let inbound = DirectInbound::new(
            InboundMeta::new("direct-in", "direct"),
            Logger::new("direct-in", "direct"),
            Arc::new(RecordingSink {
                tx: Mutex::new(None),
            }),
            test_listener(
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 9000)),
                Arc::new(|addr| {
                    let listener = std::net::TcpListener::bind(addr)?;
                    listener.set_nonblocking(true)?;
                    Ok(TcpListener::from_std(listener)?)
                }),
            ),
            None,
            None,
        )
        .expect("direct inbound should build");

        assert_eq!(
            inbound
                .listener
                .bind_addr()
                .expect("direct ipv6 listen should parse"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 9000))
        );
    }

    fn test_listener(
        addr: SocketAddr,
        factory: Arc<dyn Fn(SocketAddr) -> io::Result<TcpListener> + Send + Sync>,
    ) -> Listener {
        let listen = veex_core::Listen::new(addr.ip().to_string(), addr.port());
        let factory: Arc<ListenerFactory> = Arc::new(move |addr| {
            let factory = Arc::clone(&factory);
            Box::pin(async move { factory(addr).map_err(Into::into) })
        });
        Listener::new(listen, factory)
    }

    async fn reserve_local_port() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
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

        panic!("client should connect within retry budget");
    }
}
