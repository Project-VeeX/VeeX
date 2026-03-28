use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use veex_core::{
    BoxFuture, BoxedAsyncStream, Dispatcher, Inbound, Network, ProxyError, Result, SessionContext,
    SessionMeta,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    codec::{
        decode_greeting, decode_request, encode_method_selection, encode_reply, ReplyCode,
        NO_ACCEPTABLE_METHODS, NO_AUTHENTICATION,
    },
    error::SocksError,
};

#[derive(Debug)]
pub struct SocksInbound {
    tag: String,
    listen: String,
    listen_port: u16,
    next_session_id: AtomicU64,
}

impl SocksInbound {
    pub fn new(tag: impl Into<String>, listen: impl Into<String>, listen_port: u16) -> Self {
        Self {
            tag: tag.into(),
            listen: listen.into(),
            listen_port,
            next_session_id: AtomicU64::new(1),
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
            return Err(ProxyError::Config("socks inbound tag must not be empty".into()));
        }
        if self.listen.trim().is_empty() {
            return Err(ProxyError::Config("socks inbound listen must not be empty".into()));
        }
        if self.listen_port == 0 {
            return Err(ProxyError::Config(
                "socks inbound listen_port must be within 1..=65535".into(),
            ));
        }
        Ok(())
    }

    fn bind_addr(&self) -> String {
        format!("{}:{}", self.listen, self.listen_port)
    }

    async fn handle_connection(
        self: Arc<Self>,
        dispatcher: Arc<dyn Dispatcher>,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<()> {
        self.perform_handshake(stream, peer, dispatcher).await
    }

    async fn perform_handshake(
        self: Arc<Self>,
        mut stream: TcpStream,
        peer: SocketAddr,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> Result<()> {
        let methods = read_greeting(&mut stream).await?;
        let greeting = decode_greeting(&methods)?;

        if !greeting.methods.contains(&NO_AUTHENTICATION) {
            stream
                .write_all(&encode_method_selection(NO_ACCEPTABLE_METHODS))
                .await?;
            return Err(SocksError::UnsupportedAuthMethods.into());
        }

        stream
            .write_all(&encode_method_selection(NO_AUTHENTICATION))
            .await?;

        let request_bytes = read_request(&mut stream).await?;
        let request = match decode_request(&request_bytes) {
            Ok(request) => request,
            Err(err @ SocksError::UnsupportedCommand(_)) => {
                stream
                    .write_all(&encode_reply(ReplyCode::CommandNotSupported, None))
                    .await?;
                return Err(err.into());
            }
            Err(err @ SocksError::UnsupportedAddressType(_)) => {
                stream
                    .write_all(&encode_reply(ReplyCode::AddressTypeNotSupported, None))
                    .await?;
                return Err(err.into());
            }
            Err(err) => {
                stream
                    .write_all(&encode_reply(ReplyCode::GeneralFailure, None))
                    .await?;
                return Err(err.into());
            }
        };

        let local_addr = stream.local_addr().ok();
        stream
            .write_all(&encode_reply(ReplyCode::Succeeded, local_addr))
            .await?;

        let meta = SessionMeta {
            id: self.next_session_id.fetch_add(1, Ordering::Relaxed),
            network: Network::Tcp,
            inbound_tag: self.tag.clone(),
            peer,
            destination: request.destination,
            start: Instant::now(),
        };
        let ctx = SessionContext::new(meta, Vec::new());
        let stream: BoxedAsyncStream = Box::new(stream);
        dispatcher.dispatch(stream, ctx).await
    }
}

impl Inbound for SocksInbound {
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
                    let _ = inbound.handle_connection(dispatcher, stream, peer).await;
                });
            }
        })
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
            let mut tail = [0u8; 6];
            stream.read_exact(&mut tail).await?;
            bytes.extend_from_slice(&tail);
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            bytes.extend_from_slice(&len);
            let domain_len = len[0] as usize;
            let mut domain_and_port = vec![0u8; domain_len + 2];
            stream.read_exact(&mut domain_and_port).await?;
            bytes.extend_from_slice(&domain_and_port);
        }
        0x04 => {
            let mut tail = [0u8; 18];
            stream.read_exact(&mut tail).await?;
            bytes.extend_from_slice(&tail);
        }
        _ => {
            let mut port = [0u8; 2];
            let _ = stream.read_exact(&mut port).await;
        }
    }

    Ok(bytes)
}

