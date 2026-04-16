use std::{future::Future, net::SocketAddr, pin::Pin};

use tokio::net::TcpStream;

use crate::{
    error::Result,
    io::BoxedAsyncStream,
    logging::Logger,
    portal::meta::{InboundMeta, OutboundMeta},
    session::SessionContext,
};

/// A boxed future that is Send-safe, returned by trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait Outbound: Send + Sync {
    fn meta(&self) -> &OutboundMeta;
    fn logger(&self) -> &Logger;

    fn start(&self) -> BoxFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn close(&self) -> BoxFuture<'_, ()>;
}

pub trait StreamOutbound: Outbound {
    fn connect_stream(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream>;
}

pub trait ProxyOutbound: Outbound {
    fn connect_proxy_stream(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream>;
}

pub trait Inbound: Send + Sync {
    fn meta(&self) -> &InboundMeta;
    fn logger(&self) -> &Logger;
    fn start(&self) -> BoxFuture<'_, ()>;
    fn close(&self) -> BoxFuture<'_, ()>;
}

pub trait StreamInbound: Inbound {
    fn accept_stream(&self, stream: TcpStream, peer: SocketAddr) -> BoxFuture<'_, ()>;
}

pub trait TransparentInbound: Inbound {
    fn accept_transparent_stream(&self, stream: TcpStream, peer: SocketAddr) -> BoxFuture<'_, ()>;
}
