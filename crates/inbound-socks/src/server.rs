use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{info, warn};
use veex_core::{
    sanitize_field, BoxFuture, BoxedAsyncStream, Destination, Dispatcher, Inbound, InboundMeta,
    Listener, ListenerAcceptHandler, Logger, Network, ProxyError, Result, SessionContext,
    SessionMeta, StreamInbound,
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
    router: Arc<dyn Dispatcher>,
    listener: Listener,
    state: Arc<SocksInboundState>,
}

struct SessionBootstrap {
    id: u64,
    ctx: SessionContext,
    inbound_field: String,
    peer_field: String,
    destination_field: String,
}

impl SocksInbound {
    pub fn new(
        meta: InboundMeta,
        logger: Logger,
        router: Arc<dyn Dispatcher>,
        listener: Listener,
    ) -> Result<Arc<Self>> {
        let inbound = Arc::new(Self {
            meta,
            logger,
            router,
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
        let session_id = self.next_session_id();
        let inbound_field = self.logger.tag_field().into_owned();
        let peer_field = peer.to_string();
        let peer_field = sanitize_field(&peer_field).into_owned();
        let destination_field = destination.to_string();
        let destination_field = sanitize_field(&destination_field).into_owned();
        let ctx = SessionContext::new(
            SessionMeta {
                id: session_id,
                network: Network::Tcp,
                inbound_tag: self.meta.tag.clone(),
                peer,
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        SessionBootstrap {
            id: session_id,
            ctx,
            inbound_field,
            peer_field,
            destination_field,
        }
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
        let result = self.router.dispatch(stream, session.ctx).await;
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
