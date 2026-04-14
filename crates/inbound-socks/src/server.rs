use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{info, warn};
use veex_core::{
    build_session_bootstrap, sanitize_field, BoxFuture, BoxedAsyncStream, Destination, Inbound,
    InboundMeta, Listener, ListenerAcceptHandler, Logger, ProxyError, Result, SessionBootstrap,
    StreamInbound, StreamSink,
};

use crate::{
    codec::{
        decode_greeting, decode_request, encode_method_selection, encode_reply, ReplyCode,
        NO_ACCEPTABLE_METHODS, NO_AUTHENTICATION,
    },
    error::SocksError,
};

struct SocksInboundState {
    next_session_id: AtomicU64,
}

pub struct SocksInbound {
    meta: InboundMeta,
    logger: Logger,
    sink: Arc<dyn StreamSink>,
    listener: Listener,
    state: Arc<SocksInboundState>,
}

impl SocksInbound {
    pub fn new(
        meta: InboundMeta,
        logger: Logger,
        sink: Arc<dyn StreamSink>,
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
                let _ = inbound.accept_stream(stream, peer).await;
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
        self.perform_handshake(stream, peer).await
    }

    async fn perform_handshake(&self, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
        let methods = read_greeting(&mut stream).await.map_err(|err| {
            self.log_handshake_failed(peer, "greeting", &err);
            ProxyError::from(err)
        })?;
        let greeting = decode_greeting(&methods).map_err(|err| {
            self.log_handshake_failed(peer, "greeting", &err);
            ProxyError::from(err)
        })?;

        if !greeting.methods.contains(&NO_AUTHENTICATION) {
            if let Err(err) = stream
                .write_all(&encode_method_selection(NO_ACCEPTABLE_METHODS))
                .await
            {
                let err = SocksError::from(err);
                self.log_handshake_failed(peer, "method_selection", &err);
                return Err(err.into());
            }

            let err = SocksError::UnsupportedAuthMethods;
            self.log_handshake_failed(peer, "method_selection", &err);
            return Err(err.into());
        }

        stream
            .write_all(&encode_method_selection(NO_AUTHENTICATION))
            .await
            .map_err(|err| {
                let err = SocksError::from(err);
                self.log_handshake_failed(peer, "method_selection", &err);
                ProxyError::from(err)
            })?;

        let request_bytes = read_request(&mut stream).await.map_err(|err| {
            self.log_handshake_failed(peer, "request_decode", &err);
            ProxyError::from(err)
        })?;
        let request = match decode_request(&request_bytes) {
            Ok(request) => request,
            Err(err @ SocksError::UnsupportedCommand(_)) => {
                if let Err(write_err) = stream
                    .write_all(&encode_reply(ReplyCode::CommandNotSupported, None))
                    .await
                {
                    let err = SocksError::from(write_err);
                    self.log_handshake_failed(peer, "request_validate", &err);
                    return Err(err.into());
                }
                self.log_handshake_failed(peer, "request_validate", &err);
                return Err(err.into());
            }
            Err(err @ SocksError::UnsupportedAddressType(_)) => {
                if let Err(write_err) = stream
                    .write_all(&encode_reply(ReplyCode::AddressTypeNotSupported, None))
                    .await
                {
                    let err = SocksError::from(write_err);
                    self.log_handshake_failed(peer, "request_validate", &err);
                    return Err(err.into());
                }
                self.log_handshake_failed(peer, "request_validate", &err);
                return Err(err.into());
            }
            Err(err) => {
                if let Err(write_err) = stream
                    .write_all(&encode_reply(ReplyCode::GeneralFailure, None))
                    .await
                {
                    let err = SocksError::from(write_err);
                    self.log_handshake_failed(peer, "request_decode", &err);
                    return Err(err.into());
                }
                self.log_handshake_failed(peer, "request_decode", &err);
                return Err(err.into());
            }
        };

        let local_addr = stream.local_addr().ok();
        stream
            .write_all(&encode_reply(ReplyCode::Succeeded, local_addr))
            .await
            .map_err(|err| {
                let err = SocksError::from(err);
                self.log_handshake_failed(peer, "request_validate", &err);
                ProxyError::from(err)
            })?;

        let session = self.bootstrap_session(peer, request.destination);
        info!(
            event = "session_start",
            session_id = session.id,
            inbound = %session.inbound_field,
            peer = %session.peer_field,
            destination = %session.destination_field,
            network = %"tcp",
            "socks session start"
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
                "socks session failed"
            );
        }
        result
    }

    fn log_handshake_failed(&self, peer: SocketAddr, stage: &'static str, err: &SocksError) {
        let peer_field = peer.to_string();
        let peer_field = sanitize_field(&peer_field).into_owned();
        warn!(
            event = "handshake_failed",
            inbound = %self.logger.tag_field(),
            peer = %peer_field,
            stage = %stage,
            error = %err,
            "socks handshake failed"
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

async fn read_greeting(stream: &mut TcpStream) -> std::result::Result<Vec<u8>, SocksError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    let mut bytes = header.to_vec();

    let method_len = header[1] as usize;
    let mut methods = vec![0u8; method_len];
    stream.read_exact(&mut methods).await?;
    bytes.extend_from_slice(&methods);
    Ok(bytes)
}

async fn read_request(stream: &mut TcpStream) -> std::result::Result<Vec<u8>, SocksError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let atyp = header[3];
    let mut bytes = header.to_vec();

    match atyp {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
            bytes.extend_from_slice(&rest);
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            bytes.extend_from_slice(&len);

            let mut domain = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut domain).await?;
            bytes.extend_from_slice(&domain);
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
            bytes.extend_from_slice(&rest);
        }
        _ => {
            let mut rest = [0u8; 2];
            stream.read_exact(&mut rest).await?;
            bytes.extend_from_slice(&rest);
        }
    }

    Ok(bytes)
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
        BoxFuture, Destination, Inbound, InboundMeta, Listener, ListenerFactory, Logger, StreamSink,
    };

    use super::SocksInbound;

    struct RecordingSink {
        tx: Mutex<Option<oneshot::Sender<Destination>>>,
    }

    impl StreamSink for RecordingSink {
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
    async fn socks_inbound_submits_request_to_sink() {
        let listen_addr = reserve_local_port().await;
        let expected = Destination::from_domain("example.com", 443);
        let (tx, rx) = oneshot::channel();
        let sink: Arc<dyn StreamSink> = Arc::new(RecordingSink {
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
        let listen = veex_core::Listen::new(addr.ip().to_string(), addr.port());
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
