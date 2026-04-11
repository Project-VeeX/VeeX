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
    sanitize_field, BoxFuture, BoxedAsyncStream, Destination, Inbound, InboundMeta, InboundSink,
    Listener, ListenerAcceptHandler, Logger, ProxyError, Result, TransparentInbound,
};
use veex_infra_linux::get_original_dst as get_original_dst_socket;

use crate::shared::session::{build_session_bootstrap, SessionBootstrap};

use super::error::RedirectError;

type ResolveOriginalDst =
    dyn Fn(&TcpStream) -> std::result::Result<Destination, RedirectError> + Send + Sync;

fn resolve_original_dst(stream: &TcpStream) -> std::result::Result<Destination, RedirectError> {
    let destination = get_original_dst_socket(stream)?;
    Ok(Destination::from_ip(destination.ip(), destination.port()))
}

struct RedirectInboundState {
    next_session_id: AtomicU64,
}

pub struct RedirectInbound {
    meta: InboundMeta,
    logger: Logger,
    sink: Arc<dyn InboundSink>,
    listener: Listener,
    original_dst_resolver: Arc<ResolveOriginalDst>,
    state: Arc<RedirectInboundState>,
}

impl RedirectInbound {
    pub fn new(
        meta: InboundMeta,
        logger: Logger,
        sink: Arc<dyn InboundSink>,
        listener: Listener,
    ) -> Result<Arc<Self>> {
        Self::new_with_resolver(meta, logger, sink, listener, Arc::new(resolve_original_dst))
    }

    fn new_with_resolver(
        meta: InboundMeta,
        logger: Logger,
        sink: Arc<dyn InboundSink>,
        listener: Listener,
        resolver: Arc<ResolveOriginalDst>,
    ) -> Result<Arc<Self>> {
        let inbound = Arc::new(Self {
            meta,
            logger,
            sink,
            listener,
            original_dst_resolver: resolver,
            state: Arc::new(RedirectInboundState {
                next_session_id: AtomicU64::new(1),
            }),
        });
        inbound.validate()?;
        inbound.bind_listener_handler()?;
        Ok(inbound)
    }

    pub fn validate(&self) -> Result<()> {
        if self.meta.tag.trim().is_empty() {
            return Err(ProxyError::config("redirect inbound tag must not be empty"));
        }
        if self.meta.r#type.trim().is_empty() {
            return Err(ProxyError::config(
                "redirect inbound type must not be empty",
            ));
        }
        if self.listener.listen().listen().trim().is_empty() {
            return Err(ProxyError::config(
                "redirect inbound listen must not be empty",
            ));
        }
        if self.listener.listen().listen_port() == 0 {
            return Err(ProxyError::config(
                "redirect inbound listen_port must be within 1..=65535",
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
        let destination = match (self.original_dst_resolver)(&stream) {
            Ok(destination) => destination,
            Err(err) => {
                warn!(
                    event = "destination_resolve_failed",
                    inbound = %self.logger.tag_field(),
                    peer = %sanitize_field(&peer.to_string()),
                    error = %err,
                    "redirect original destination lookup failed"
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
            "redirect session start"
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
                "redirect session failed"
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
            "redirect inbound connection failed"
        );
    }
}

impl Inbound for RedirectInbound {
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

impl TransparentInbound for RedirectInbound {
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
        BoxFuture, Destination, Inbound, InboundMeta, InboundSink, Listener, ListenerFactory,
        Logger,
    };

    use super::{RedirectError, RedirectInbound, ResolveOriginalDst};

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
    async fn redirect_inbound_forwards_resolved_destination_to_executor() {
        let listen_addr = reserve_local_port().await;
        let expected = Destination::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443);
        let (tx, rx) = oneshot::channel();
        let sink: Arc<dyn InboundSink> = Arc::new(RecordingSink {
            tx: Mutex::new(Some(tx)),
        });
        let resolved = expected.clone();
        let inbound = RedirectInbound::new_with_resolver(
            InboundMeta::new("redirect-in", "redirect"),
            Logger::new("redirect-in", "redirect"),
            sink,
            test_listener(
                listen_addr,
                Arc::new(|addr| {
                    let listener = std::net::TcpListener::bind(addr)?;
                    listener.set_nonblocking(true)?;
                    Ok(TcpListener::from_std(listener)?)
                }),
            ),
            fixed_resolver(resolved),
        )
        .expect("redirect inbound should build");

        inbound.start().await.expect("redirect should start");
        let _client = connect_with_retry(listen_addr).await;
        let received = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("sink should receive destination")
            .expect("destination should be delivered");
        assert_eq!(received, expected);
        inbound.close().await.expect("redirect should close");
    }

    #[tokio::test]
    async fn original_dst_on_plain_socket_fails_or_returns_listener_addr() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let expected_destination = Destination::from_ip(addr.ip(), addr.port());

        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept should succeed");
            super::resolve_original_dst(&stream)
        });

        let _client = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let result = accept_task.await.expect("accept task should join");

        match result {
            Err(RedirectError::GetSockOpt { .. })
            | Err(RedirectError::UnsupportedAddressFamily(_)) => {}
            Err(other) => panic!("unexpected original dst error: {other}"),
            Ok(destination) => assert_eq!(
                destination, expected_destination,
                "plain socket original destination should resolve to the current listener address",
            ),
        }
    }

    #[test]
    fn redirect_inbound_accepts_unspecified_ipv6_listen_addr() {
        let inbound = RedirectInbound::new_with_resolver(
            InboundMeta::new("redirect-in", "redirect"),
            Logger::new("redirect-in", "redirect"),
            Arc::new(RecordingSink {
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
            fixed_resolver(Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)),
        )
        .expect("redirect inbound should build");
        assert_eq!(
            inbound
                .listener
                .bind_addr()
                .expect("redirect ipv6 listen should parse"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041))
        );
    }

    fn fixed_resolver(destination: Destination) -> Arc<ResolveOriginalDst> {
        Arc::new(
            move |_stream: &TcpStream| -> std::result::Result<Destination, RedirectError> {
                Ok(destination.clone())
            },
        )
    }

    fn test_listener(
        addr: SocketAddr,
        factory: Arc<
            dyn Fn(SocketAddr) -> std::result::Result<TcpListener, RedirectError> + Send + Sync,
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
