use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use tokio::net::{TcpListener, TcpStream};
use veex_core::{
    BoxFuture, BoxedAsyncStream, Destination, Dispatcher, Inbound, Network, ProxyError, Result,
    SessionContext, SessionMeta,
};
use veex_observability::{log_line, LogLevel};

use crate::{error::RedirectError, original_dst::resolve_original_dst};

type ResolveOriginalDst =
    dyn Fn(&TcpStream) -> std::result::Result<Destination, RedirectError> + Send + Sync;

pub struct RedirectInbound {
    tag: String,
    listen: String,
    listen_port: u16,
    next_session_id: AtomicU64,
    resolver: Arc<ResolveOriginalDst>,
}

impl RedirectInbound {
    pub fn new(tag: impl Into<String>, listen: impl Into<String>, listen_port: u16) -> Self {
        Self::new_with_resolver(tag, listen, listen_port, Arc::new(resolve_original_dst))
    }

    fn new_with_resolver(
        tag: impl Into<String>,
        listen: impl Into<String>,
        listen_port: u16,
        resolver: Arc<ResolveOriginalDst>,
    ) -> Self {
        Self {
            tag: tag.into(),
            listen: listen.into(),
            listen_port,
            next_session_id: AtomicU64::new(1),
            resolver,
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
        Ok(())
    }

    fn bind_addr(&self) -> String {
        format!("{}:{}", self.listen, self.listen_port)
    }

    fn next_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn handle_connection(
        self: Arc<Self>,
        dispatcher: Arc<dyn Dispatcher>,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<()> {
        let session_id = self.next_session_id();
        let destination = (self.resolver)(&stream)?;
        log_line(
            LogLevel::Info,
            &format!(
                "session_id={} inbound={} peer={} original_dst={}",
                session_id, self.tag, peer, destination
            ),
        );

        let meta = SessionMeta {
            id: session_id,
            network: Network::Tcp,
            inbound_tag: self.tag.clone(),
            peer,
            destination,
            start: Instant::now(),
        };
        let ctx = SessionContext::new(meta, Vec::new());
        let stream: BoxedAsyncStream = Box::new(stream);
        dispatcher.dispatch(stream, ctx).await
    }
}

impl Inbound for RedirectInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn serve(self: Arc<Self>, dispatcher: Arc<dyn Dispatcher>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            self.validate()?;
            let listener = TcpListener::bind(self.bind_addr()).await?;

            loop {
                let (stream, peer) = listener.accept().await?;
                let inbound = Arc::clone(&self);
                let dispatcher = Arc::clone(&dispatcher);

                tokio::spawn(async move {
                    if let Err(err) = inbound.handle_connection(dispatcher, stream, peer).await {
                        log_line(
                            LogLevel::Warn,
                            &format!("inbound=redirect peer={} error={}", peer, err),
                        );
                    }
                });
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::{net::TcpStream, sync::oneshot};
    use veex_core::{BoxFuture, Destination, Dispatcher, Host, Inbound};

    use super::RedirectInbound;

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
        let inbound = Arc::new(RedirectInbound::new_with_resolver(
            "redirect-in",
            "127.0.0.1",
            listen_addr.port(),
            Arc::new(move |_| Ok(resolver_destination.clone())),
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
