use std::{fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

use tokio::net::TcpStream;

use crate::{
    dns::ResolveContext, error::Result, plane::packet::io::PacketSessionHandle, types::Host,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Dial {
    pub timeout: Option<Duration>,
    pub routing_mark: Option<u32>,
    pub domain_resolver: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DialContext {
    pub session_id: u64,
    pub outbound_tag: String,
    pub resolve_context: Option<ResolveContext>,
}

type DialFuture = Pin<Box<dyn Future<Output = Result<TcpStream>> + Send + 'static>>;
type PacketDialFuture = Pin<Box<dyn Future<Output = Result<PacketSessionHandle>> + Send + 'static>>;

pub type DialConnect = dyn Fn(Host, u16, Dial, DialContext) -> DialFuture + Send + Sync;
pub type PacketConnect = dyn Fn(Host, u16, Dial, DialContext) -> PacketDialFuture + Send + Sync;

#[derive(Clone)]
pub struct Dialer {
    dial: Dial,
    connector: Arc<DialConnect>,
}

impl fmt::Debug for Dialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dialer").field("dial", &self.dial).finish()
    }
}

impl Dialer {
    pub fn new(dial: Dial, connector: Arc<DialConnect>) -> Self {
        Self { dial, connector }
    }

    pub fn dial(&self) -> &Dial {
        &self.dial
    }

    pub async fn connect(&self, host: &Host, port: u16, ctx: DialContext) -> Result<TcpStream> {
        (self.connector)(host.clone(), port, self.dial.clone(), ctx).await
    }
}

#[derive(Clone)]
pub struct PacketDialer {
    dial: Dial,
    connector: Arc<PacketConnect>,
}

impl fmt::Debug for PacketDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketDialer")
            .field("dial", &self.dial)
            .finish()
    }
}

impl PacketDialer {
    pub fn new(dial: Dial, connector: Arc<PacketConnect>) -> Self {
        Self { dial, connector }
    }

    pub fn dial(&self) -> &Dial {
        &self.dial
    }

    pub async fn connect(
        &self,
        host: &Host,
        port: u16,
        ctx: DialContext,
    ) -> Result<PacketSessionHandle> {
        (self.connector)(host.clone(), port, self.dial.clone(), ctx).await
    }
}
