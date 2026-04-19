use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::net::TcpStream;
use tracing::{info, warn};
use veex_core::{
    ProxyError, Result,
    io::BoxedAsyncStream,
    logging::{Logger, sanitize_field},
    portal::{BoxFuture, Inbound, InboundMeta, Listener, ListenerAcceptHandler, StreamInbound},
    session::{SessionBootstrap, build_session_bootstrap},
    types::Destination,
};
use veex_execution::StreamDispatch;

use super::{
    codec::Command,
    protocol::{SocksProtocolError, establish_socks_stream},
};

struct SocksInboundState {
    next_session_id: AtomicU64,
}

pub struct SocksInbound {
    meta: InboundMeta,
    logger: Logger,
    sink: Arc<dyn StreamDispatch>,
    listener: Listener,
    state: Arc<SocksInboundState>,
}

impl SocksInbound {
    pub fn new(
        meta: InboundMeta,
        logger: Logger,
        sink: Arc<dyn StreamDispatch>,
        listener: Listener,
    ) -> Result<Arc<Self>> {
        let inbound = Arc::new(Self {
            meta,
            logger,
            sink,
            listener,
            state: Arc::new(SocksInboundState {
                next_session_id: AtomicU64::new(1),
            }),
        });
        inbound.validate()?;
        inbound.bind_listener_handler()?;
        Ok(inbound)
    }

    pub fn validate(&self) -> Result<()> {
        if self.meta.tag.trim().is_empty() {
            return Err(ProxyError::config("socks inbound tag must not be empty"));
        }
        if self.meta.r#type.trim().is_empty() {
            return Err(ProxyError::config("socks inbound type must not be empty"));
        }
        if self.listener.listen().listen().trim().is_empty() {
            return Err(ProxyError::config("socks inbound listen must not be empty"));
        }
        if self.listener.listen().listen_port() == 0 {
            return Err(ProxyError::config(
                "socks inbound listen_port must be within 1..=65535",
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

    async fn handle_stream(&self, stream: TcpStream, peer: SocketAddr) -> Result<()> {
        let established = establish_socks_stream(stream).await.map_err(|err| {
            self.log_handshake_failed(peer, &err);
            ProxyError::from(err.into_inner())
        })?;
        let command = match established.command {
            Command::Connect => "connect",
        };

        let session = self.bootstrap_session(peer, established.destination);
        info!(
            event = "session_start",
            session_id = session.id,
            inbound = %session.inbound_field,
            peer = %session.peer_field,
            destination = %session.destination_field,
            command = %command,
            network = %"tcp",
            "socks session start"
        );

        let stream: BoxedAsyncStream = Box::new(established.stream);
        let result = self.sink.dispatch_stream(stream, session.ctx).await;
        if let Err(err) = &result {
            warn!(
                event = "session_failed",
                session_id = session.id,
                inbound = %session.inbound_field,
                peer = %session.peer_field,
                destination = %session.destination_field,
                error_kind = ?err.kind(),
                error = %err,
                "socks session failed"
            );
        }
        result
    }

    fn log_handshake_failed(&self, peer: SocketAddr, err: &SocksProtocolError) {
        let peer_field = peer.to_string();
        let peer_field = sanitize_field(&peer_field).into_owned();
        warn!(
            event = "handshake_failed",
            inbound = %self.logger.tag_field(),
            peer = %peer_field,
            stage = %err.stage(),
            error = %err.source_error(),
            "socks handshake failed"
        );
    }

    fn log_connection_failed(&self, peer: SocketAddr, err: &ProxyError) {
        let peer_field = sanitize_field(&peer.to_string()).into_owned();
        warn!(
            event = "inbound_connection_failed",
            inbound = %self.logger.tag_field(),
            peer = %peer_field,
            error_kind = ?err.kind(),
            error = %err,
            "socks inbound connection failed"
        );
    }
}

impl Inbound for SocksInbound {
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

impl StreamInbound for SocksInbound {
    fn accept_stream(&self, stream: TcpStream, peer: SocketAddr) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.handle_stream(stream, peer).await })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };
    use veex_core::{
        io::BoxedAsyncStream,
        logging::Logger,
        portal::{BoxFuture, Inbound, InboundMeta, Listener, ListenerFactory},
        session::SessionContext,
        types::{Destination, Listen},
    };
    use veex_execution::StreamDispatch;

    use super::SocksInbound;

    struct RecordingSink {
        tx: Mutex<Option<oneshot::Sender<Destination>>>,
    }

    impl StreamDispatch for RecordingSink {
        fn dispatch_stream(
            &self,
            _inbound_stream: BoxedAsyncStream,
            ctx: SessionContext,
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
    async fn socks_inbound_submits_request_to_sink() {
        let listen_addr = reserve_local_port().await;
        let expected = Destination::from_domain("example.com", 443);
        let (tx, rx) = oneshot::channel();
        let sink: Arc<dyn StreamDispatch> = Arc::new(RecordingSink {
            tx: Mutex::new(Some(tx)),
        });
        let inbound = SocksInbound::new(
            InboundMeta::new("socks-in", "socks"),
            Logger::new("socks-in", "socks"),
            sink,
            test_listener(listen_addr),
        )
        .expect("socks inbound should build");

        inbound.start().await.expect("socks should start");
        let mut client = connect_with_retry(listen_addr).await;
        client
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .expect("greeting should send");

        let mut greeting_reply = [0u8; 2];
        client
            .read_exact(&mut greeting_reply)
            .await
            .expect("greeting reply should read");
        assert_eq!(greeting_reply, [0x05, 0x00]);

        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xbb,
            ])
            .await
            .expect("request should send");

        let mut request_reply = [0u8; 10];
        client
            .read_exact(&mut request_reply)
            .await
            .expect("reply should read");
        assert_eq!(&request_reply[..2], &[0x05, 0x00]);

        let received = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("sink should receive destination")
            .expect("destination should be delivered");
        assert_eq!(received, expected);
        inbound.close().await.expect("socks should close");
    }

    fn test_listener(addr: SocketAddr) -> Listener {
        let listen = Listen::new(addr.ip().to_string(), addr.port());
        let factory: Arc<ListenerFactory> = Arc::new(|addr| {
            Box::pin(async move {
                let listener = std::net::TcpListener::bind(addr)?;
                listener.set_nonblocking(true)?;
                TcpListener::from_std(listener).map_err(Into::into)
            })
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
