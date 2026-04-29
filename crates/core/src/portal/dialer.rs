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

impl Dial {
    pub fn explicit_detour_tag(&self) -> Option<&str> {
        self.detour.as_deref()
    }

    pub fn detour_tag(&self) -> &str {
        self.detour.as_deref().unwrap_or("direct")
    }

    pub fn resolve_context(
        &self,
        existing: Option<&ResolveContext>,
        outbound_tag: impl Into<String>,
    ) -> ResolveContext {
        let mut context = ResolveContext::from_outbound_policy(
            existing,
            outbound_tag,
            self.domain_resolver.clone(),
        );
        if self.domain_resolver_disable_cache {
            context = context.with_disable_cache(true);
        }
        context
    }

    pub fn dns_upstream_resolve_context(
        &self,
        parent: &ResolveContext,
        outbound_tag: impl Into<String>,
        dns_server_tag: impl Into<String>,
    ) -> ResolveContext {
        let mut context = parent.for_dns_upstream_dial(
            outbound_tag,
            dns_server_tag,
            self.domain_resolver.clone(),
        );
        if self.domain_resolver_disable_cache {
            context = context.with_disable_cache(true);
        }
        context
    }
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
        resolve_context: Some(
            dial.resolve_context(session.state.resolve_context.as_ref(), outbound_tag),
        ),
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::ResolveContext;

    use super::Dial;

    #[test]
    fn dial_resolve_context_applies_fresh_outbound_policy() {
        let context = Dial {
            domain_resolver: Some("bootstrap".into()),
            domain_resolver_disable_cache: true,
            ..Dial::default()
        }
        .resolve_context(None, "proxy");

        assert_eq!(
            context,
            ResolveContext::outbound_dial("proxy", Some("bootstrap".into()))
                .with_disable_cache(true)
        );
    }

    #[test]
    fn dial_resolve_context_preserves_inherited_policy() {
        let inherited = ResolveContext::outbound_dial("parent", Some("bootstrap".into()))
            .with_disable_cache(true)
            .with_depth(2);

        let context = Dial {
            domain_resolver: Some("ignored".into()),
            ..Dial::default()
        }
        .resolve_context(Some(&inherited), "proxy");

        assert_eq!(context, inherited);
    }

    #[test]
    fn dial_resolve_context_does_not_clear_inherited_disable_cache() {
        let inherited = ResolveContext::outbound_dial("parent", Some("bootstrap".into()))
            .with_disable_cache(true);

        let context = Dial::default().resolve_context(Some(&inherited), "proxy");

        assert!(context.disable_cache);
        assert_eq!(context, inherited);
    }

    #[test]
    fn dial_dns_upstream_resolve_context_uses_dns_upstream_semantics() {
        let parent = ResolveContext::outbound_dial("proxy", None).with_depth(1);

        let context = Dial {
            domain_resolver: Some("bootstrap".into()),
            domain_resolver_disable_cache: true,
            ..Dial::default()
        }
        .dns_upstream_resolve_context(&parent, "direct", "bootstrap");

        assert_eq!(context.purpose, crate::dns::ResolvePurpose::DnsUpstreamDial);
        assert_eq!(context.caller_outbound_tag.as_deref(), Some("direct"));
        assert_eq!(context.caller_dns_server_tag.as_deref(), Some("bootstrap"));
        assert_eq!(context.explicit_server_tag.as_deref(), Some("bootstrap"));
        assert!(context.disable_cache);
        assert_eq!(context.recursion_depth, 2);
    }

    #[test]
    fn dial_detour_tag_defaults_to_direct() {
        assert_eq!(Dial::default().detour_tag(), "direct");
        assert_eq!(Dial::default().explicit_detour_tag(), None);
        assert_eq!(
            Dial {
                detour: Some("proxy".into()),
                ..Dial::default()
            }
            .detour_tag(),
            "proxy"
        );
        assert_eq!(
            Dial {
                detour: Some("proxy".into()),
                ..Dial::default()
            }
            .explicit_detour_tag(),
            Some("proxy")
        );
    }
}
