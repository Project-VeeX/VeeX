use std::{fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

use tokio::net::TcpStream;

use crate::{
    dns::ResolveContext, error::Result, io::PacketSessionHandle, session::SessionContext,
    types::Host,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Dial {
    pub detour: Option<String>,
    pub connect_timeout: Option<Duration>,
    pub routing_mark: Option<u32>,
    pub disable_tcp_keep_alive: bool,
    pub tcp_keep_alive: Option<Duration>,
    pub tcp_keep_alive_interval: Option<Duration>,
    pub domain_resolver: Option<String>,
    pub domain_resolver_disable_cache: bool,
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

    pub fn routing_mark(&self) -> Option<u32> {
        self.dial.routing_mark
    }

    pub fn context(
        &self,
        session: &SessionContext,
        outbound_tag: impl Into<String>,
    ) -> DialContext {
        build_dial_context(&self.dial, session, outbound_tag.into())
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

    pub fn context(
        &self,
        session: &SessionContext,
        outbound_tag: impl Into<String>,
    ) -> DialContext {
        build_dial_context(&self.dial, session, outbound_tag.into())
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

fn build_dial_context(dial: &Dial, session: &SessionContext, outbound_tag: String) -> DialContext {
    DialContext {
        session_id: session.meta.id,
        outbound_tag: outbound_tag.clone(),
        resolve_context: Some(ResolveContext::from_outbound_policy(
            session.state.resolve_context.as_ref(),
            outbound_tag,
            dial.domain_resolver.clone(),
        )
        .with_disable_cache(dial.domain_resolver_disable_cache)),
    }
}
