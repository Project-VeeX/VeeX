use std::{
    future::pending,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tracing::{error, info, warn};
use veex_core::{
    parse_listen_addr, sanitize_field, BoxFuture, BoxedAsyncStream, Destination, Dispatcher,
    Inbound, ProxyError, Result, ShutdownSignal,
};
use veex_infra_linux::get_original_dst as get_original_dst_socket;

use crate::shared::session::{build_session_bootstrap, SessionBootstrap};

use super::{error::RedirectError, listener::create_redirect_listener};

type ResolveOriginalDst =
    dyn Fn(&TcpStream) -> std::result::Result<Destination, RedirectError> + Send + Sync;
type ListenerFactory =
    dyn Fn(SocketAddr) -> std::result::Result<TcpListener, RedirectError> + Send + Sync;

fn resolve_original_dst(stream: &TcpStream) -> std::result::Result<Destination, RedirectError> {
    let destination = get_original_dst_socket(stream)?;
    Ok(Destination::from_ip(destination.ip(), destination.port()))
}

pub struct RedirectInbound {
    tag: String,
    listen: String,
    listen_port: u16,
    next_session_id: AtomicU64,
    resolver: Arc<ResolveOriginalDst>,
    listener_factory: Arc<ListenerFactory>,
    shutdown: Option<ShutdownSignal>,
}

impl RedirectInbound {
    pub fn new(tag: impl Into<String>, listen: impl Into<String>, listen_port: u16) -> Self {
        Self::new_internal(
            tag,
            listen,
            listen_port,
            Arc::new(resolve_original_dst),
            Arc::new(create_redirect_listener),
            None,
        )
    }

    pub fn with_shutdown_signal(
        tag: impl Into<String>,
        listen: impl Into<String>,
        listen_port: u16,
        shutdown: ShutdownSignal,
    ) -> Self {
        Self::new_internal(
            tag,
            listen,
            listen_port,
            Arc::new(resolve_original_dst),
            Arc::new(create_redirect_listener),
            Some(shutdown),
        )
    }

    #[cfg(test)]
    fn new_with_hooks(
        tag: impl Into<String>,
        listen: impl Into<String>,
        listen_port: u16,
        resolver: Arc<ResolveOriginalDst>,
        listener_factory: Arc<ListenerFactory>,
    ) -> Self {
        Self::new_internal(tag, listen, listen_port, resolver, listener_factory, None)
    }

    fn new_internal(
        tag: impl Into<String>,
        listen: impl Into<String>,
        listen_port: u16,
        resolver: Arc<ResolveOriginalDst>,
        listener_factory: Arc<ListenerFactory>,
        shutdown: Option<ShutdownSignal>,
    ) -> Self {
        Self {
            tag: tag.into(),
            listen: listen.into(),
            listen_port,
            next_session_id: AtomicU64::new(1),
            resolver,
            listener_factory,
            shutdown,
        }
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn listen(&self) -> &str {
        &self.listen
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub fn validate(&self) -> Result<()> {
        if self.tag.trim().is_empty() {
            return Err(ProxyError::Config(
                "redirect inbound tag must not be empty".into(),
            ));
        }
        if self.listen.trim().is_empty() {
            return Err(ProxyError::Config(
                "redirect inbound listen must not be empty".into(),
            ));
        }
        if self.listen_port == 0 {
            return Err(ProxyError::Config(
                "redirect inbound listen_port must be within 1..=65535".into(),
            ));
        }
        let _ = self.bind_addr()?;
        Ok(())
    }

    fn bind_addr(&self) -> Result<SocketAddr> {
        parse_listen_addr(&self.listen, self.listen_port).map_err(|err| {
            ProxyError::Config(format!(
                "redirect inbound listen must be a valid socket address: {err}"
            ))
        })
    }

    fn next_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    fn bootstrap_session(&self, peer: SocketAddr, destination: Destination) -> SessionBootstrap {
        let session_id = self.next_session_id();
        build_session_bootstrap(session_id, self.tag.as_str(), peer, destination)
    }

    async fn handle_connection(
        self: Arc<Self>,
        dispatcher: Arc<dyn Dispatcher>,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<()> {
        let destination = match (self.resolver)(&stream) {
            Ok(destination) => destination,
            Err(err) => {
                warn!(
                    event = "destination_resolve_failed",
                    inbound = %sanitize_field(self.tag.as_str()),
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
        let result = dispatcher.dispatch(stream, session.ctx).await;
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

    async fn wait_for_shutdown(&self) {
        match &self.shutdown {
            Some(shutdown) => shutdown.wait().await,
            None => pending::<()>().await,
        }
    }
}

impl Inbound for RedirectInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn serve(self: Arc<Self>, dispatcher: Arc<dyn Dispatcher>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            self.validate()?;
            let listener = (self.listener_factory)(self.bind_addr()?)?;
            let mut connections = JoinSet::new();
            let mut shutting_down = false;

            loop {
                if shutting_down && connections.is_empty() {
                    break;
                }

                tokio::select! {
                    _ = self.wait_for_shutdown(), if !shutting_down => {
                        shutting_down = true;
                    }
                    accept_result = listener.accept(), if !shutting_down => {
                        let (stream, peer) = accept_result?;
                        let inbound = Arc::clone(&self);
                        let inbound_tag = sanitize_field(inbound.tag.as_str()).into_owned();
                        let dispatcher = Arc::clone(&dispatcher);

                        connections.spawn(async move {
                            if let Err(err) = inbound.handle_connection(dispatcher, stream, peer).await {
                                let peer_field = peer.to_string();
                                let peer_field = sanitize_field(&peer_field).into_owned();
                                warn!(
                                    event = "inbound_connection_failed",
                                    inbound = %inbound_tag,
                                    peer = %peer_field,
                                    error_kind = ?err.kind(),
                                    error = %err,
                                    "redirect inbound connection failed"
                                );
                            }
                        });
                    }
                    maybe_task = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(err)) = maybe_task {
                            let inbound_field = sanitize_field(self.tag.as_str()).into_owned();
                            error!(
                                event = "task_join_failed",
                                inbound = %inbound_field,
                                error = %err,
                                "redirect connection task join failed"
                            );
                            return Err(ProxyError::protocol_ctx(
                                "redirect inbound connection task join failed",
                                err,
                            ));
                        }
                    }
                }
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::{net::TcpStream, sync::oneshot};
    use veex_core::{BoxFuture, Destination, Dispatcher, Host, Inbound};

    use super::{resolve_original_dst, ListenerFactory, RedirectError, RedirectInbound};

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
    async fn redirect_inbound_forwards_resolved_destination_to_dispatcher() {
        let listen_addr = reserve_local_port().await;
        let expected = Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))), 443);
        let resolver_destination = expected.clone();
        let listener_factory: Arc<ListenerFactory> = Arc::new(|addr| {
            let listener = std::net::TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            Ok(tokio::net::TcpListener::from_std(listener)?)
        });
        let inbound = Arc::new(RedirectInbound::new_with_hooks(
            "redirect-in",
            "127.0.0.1",
            listen_addr.port(),
            Arc::new(move |_| Ok(resolver_destination.clone())),
            listener_factory,
        ));
        let (tx, rx) = oneshot::channel();
        let dispatcher: Arc<dyn Dispatcher> = Arc::new(RecordingDispatcher {
            tx: Mutex::new(Some(tx)),
        });

        let serve_task = tokio::spawn(Arc::clone(&inbound).serve(dispatcher));
        let _client = connect_with_retry(listen_addr).await;
        let received = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("dispatcher should receive destination")
            .expect("destination should be delivered");
        assert_eq!(received, expected);

        serve_task.abort();
        let _ = serve_task.await;
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
            resolve_original_dst(&stream)
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
        let inbound = RedirectInbound::new("redirect-in", "::", 1041);
        assert_eq!(
            inbound
                .bind_addr()
                .expect("redirect ipv6 listen should parse"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041))
        );
    }

    async fn reserve_local_port() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("temporary listener should bind");
        listener.local_addr().expect("temporary addr should exist")
    }

    async fn connect_with_retry(addr: SocketAddr) -> TcpStream {
        for _ in 0..50 {
            match TcpStream::connect(addr).await {
                Ok(stream) => return stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }

        panic!("listener did not become ready on {addr}");
    }
}
