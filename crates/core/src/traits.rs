use std::{future::Future, net::SocketAddr, pin::Pin};

use tokio::net::TcpStream;

use crate::{
    error::{ProxyError, Result},
    logging::Logger,
    plane::packet::session::PacketSessionHandle,
    service::{InboundMeta, OutboundMeta},
    types::{BoxedAsyncStream, SessionContext},
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

/// Connector for dispatching a session to an outbound.
///
/// Both the stream and packet dispatchers use this trait to connect
/// to outbounds; packet support is optional and defaults to error.
pub trait OutboundConnector: Outbound {
    fn connect(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream>;

    fn connect_packet(&self, ctx: &SessionContext) -> BoxFuture<'_, PacketSessionHandle> {
        let outbound_tag = self.meta().tag.clone();
        let network = ctx.meta.network;
        Box::pin(async move {
            Err(ProxyError::protocol(format!(
                "outbound '{}' does not support packet execution for {}",
                outbound_tag,
                network.as_str()
            )))
        })
    }
}
