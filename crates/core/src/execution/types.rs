use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};

use crate::{
    dns::ResolveContext,
    error::ProxyError,
    router::RouteReason,
    types::{Destination, Network},
};

use super::traits::ExecutionOutbound;

/// Immutable metadata for a session.
///
/// This is wrapped in `Arc` within `SessionContext` because the same
/// metadata may need to be accessed from multiple tasks during the
/// session lifecycle while ensuring consistency.
#[derive(Clone, Debug)]
pub struct SessionMeta {
    /// Unique session identifier, assigned at session creation.
    pub id: u64,
    /// Network protocol for this execution path.
    pub network: Network,
    /// Tag of the inbound that accepted this session.
    pub inbound_tag: String,
    /// Client peer's socket address.
    pub peer: SocketAddr,
    /// Destination the client wants to reach.
    pub destination: Destination,
    /// Session start time, used for duration calculations.
    pub start: Instant,
}

/// Routing decision for a session.
///
/// Tracks which outbound was selected and why. Starts empty and is
/// populated by the router before dispatch.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionRoute {
    /// Tag of the selected outbound, if routing has occurred.
    pub selected_outbound: Option<String>,
    /// Reason for the route decision, if routing has occurred.
    pub reason: Option<RouteReason>,
}

impl SessionRoute {
    pub fn selected(selected_outbound: impl Into<String>, reason: RouteReason) -> Self {
        Self {
            selected_outbound: Some(selected_outbound.into()),
            reason: Some(reason),
        }
    }
}

/// Mutable session state.
///
/// Contains buffered payload data accumulated before routing decision is made.
/// This allows the relay to handle pipelined or pre-loaded request data.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionState {
    /// Payload data received from the client before the outbound was selected.
    pub buffered_payload: Vec<u8>,
    /// Optional resolver context propagated into nested dial-side resolution.
    pub resolve_context: Option<ResolveContext>,
}

/// Complete session context, combining immutable metadata with mutable routing and state.
///
/// `meta` is wrapped in `Arc` to allow sharing across tasks while maintaining
/// identity. `route` and `state` are owned directly and updated during the session.
#[derive(Clone, Debug)]
pub struct SessionContext {
    /// Immutable session metadata, shared via Arc for multi-task access.
    pub meta: Arc<SessionMeta>,
    /// Routing decision for this session.
    pub route: SessionRoute,
    /// Mutable session state, including buffered payload.
    pub state: SessionState,
}

impl SessionContext {
    pub fn new(meta: SessionMeta, buffered_payload: Vec<u8>) -> Self {
        Self {
            meta: Arc::new(meta),
            route: SessionRoute::default(),
            state: SessionState {
                buffered_payload,
                resolve_context: None,
            },
        }
    }

    pub fn set_route(&mut self, selected_outbound: impl Into<String>, reason: RouteReason) {
        self.route = SessionRoute::selected(selected_outbound, reason);
    }

    pub fn set_resolve_context(&mut self, context: Option<ResolveContext>) {
        self.state.resolve_context = context;
    }
}

/// Builder for a finalized outbound registry.
#[derive(Default)]
pub struct OutboundRegistryBuilder {
    outbounds: Vec<Arc<dyn ExecutionOutbound>>,
    index_by_tag: HashMap<String, usize>,
}

impl OutboundRegistryBuilder {
    pub fn register(&mut self, outbound: Arc<dyn ExecutionOutbound>) -> crate::Result<()> {
        let tag = outbound.meta().tag.clone();
        if self.index_by_tag.contains_key(&tag) {
            return Err(ProxyError::config(format!(
                "duplicate outbound tag in registry: {tag}"
            )));
        }

        let index = self.outbounds.len();
        self.outbounds.push(outbound);
        self.index_by_tag.insert(tag, index);
        Ok(())
    }

    pub fn finalize(self, default_outbound: Arc<dyn ExecutionOutbound>) -> OutboundRegistry {
        OutboundRegistry {
            outbounds: self.outbounds,
            index_by_tag: self.index_by_tag,
            default_outbound,
        }
    }
}

/// Registry of dispatch-capable outbounds indexed by tag.
pub struct OutboundRegistry {
    outbounds: Vec<Arc<dyn ExecutionOutbound>>,
    index_by_tag: HashMap<String, usize>,
    default_outbound: Arc<dyn ExecutionOutbound>,
}

impl OutboundRegistry {
    pub fn get(&self, tag: &str) -> Option<Arc<dyn ExecutionOutbound>> {
        self.index_by_tag
            .get(tag)
            .and_then(|index| self.outbounds.get(*index))
            .map(Arc::clone)
    }

    pub fn default_outbound(&self) -> Arc<dyn ExecutionOutbound> {
        Arc::clone(&self.default_outbound)
    }

    pub fn require(&self, tag: &str) -> crate::Result<Arc<dyn ExecutionOutbound>> {
        self.get(tag)
            .ok_or_else(|| ProxyError::config(format!("missing outbound tag: {tag}")))
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.index_by_tag.contains_key(tag)
    }

    pub fn len(&self) -> usize {
        self.outbounds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.outbounds.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Arc<dyn ExecutionOutbound>> + '_ {
        self.outbounds.iter()
    }

    pub fn lifecycle_iter(&self) -> impl Iterator<Item = &Arc<dyn ExecutionOutbound>> + '_ {
        let default_outbound = (!self
            .outbounds
            .iter()
            .any(|outbound| Arc::ptr_eq(outbound, &self.default_outbound)))
        .then_some(&self.default_outbound);

        self.outbounds.iter().chain(default_outbound)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Instant,
    };

    use crate::{
        execution::stream::io::BoxedAsyncStream,
        logging::Logger,
        portal::{meta::OutboundMeta, traits::BoxFuture},
        types::{Destination, Host, Network},
        ExecutionOutbound, Outbound, ProxyError,
    };

    use super::{OutboundRegistryBuilder, SessionContext, SessionMeta};
    use crate::router::RouteReason;

    struct TestOutbound {
        meta: OutboundMeta,
        logger: Logger,
    }

    impl TestOutbound {
        fn new(tag: &str) -> Self {
            Self {
                meta: OutboundMeta::new(tag, "direct"),
                logger: Logger::new(tag, "direct"),
            }
        }
    }

    impl Outbound for TestOutbound {
        fn meta(&self) -> &OutboundMeta {
            &self.meta
        }

        fn logger(&self) -> &Logger {
            &self.logger
        }

        fn close(&self) -> BoxFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    impl ExecutionOutbound for TestOutbound {
        fn open_stream(&self, _ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("unused")) })
        }
    }

    #[test]
    fn session_context_starts_with_empty_route_and_buffered_payload_state() {
        let ctx = SessionContext::new(
            SessionMeta {
                id: 1,
                network: Network::Tcp,
                inbound_tag: "test".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 30000)),
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 443),
                start: Instant::now(),
            },
            b"ping".to_vec(),
        );

        assert_eq!(ctx.route.selected_outbound, None);
        assert_eq!(ctx.route.reason, None);
        assert_eq!(ctx.state.buffered_payload, b"ping");
    }

    #[test]
    fn session_context_route_can_be_set_after_construction() {
        let mut ctx = SessionContext::new(
            SessionMeta {
                id: 1,
                network: Network::Tcp,
                inbound_tag: "test".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 30000)),
                destination: Destination::from_domain("example.com", 443),
                start: Instant::now(),
            },
            Vec::new(),
        );

        ctx.set_route("proxy", RouteReason::Final);

        assert_eq!(ctx.route.selected_outbound.as_deref(), Some("proxy"));
        assert_eq!(ctx.route.reason, Some(RouteReason::Final));
    }

    #[test]
    fn registry_resolves_missing_detour_to_default_outbound() {
        let default_outbound: Arc<dyn ExecutionOutbound> = Arc::new(TestOutbound::new("direct"));
        let registry = OutboundRegistryBuilder::default().finalize(Arc::clone(&default_outbound));

        let resolved = registry.default_outbound();

        assert!(Arc::ptr_eq(&resolved, &default_outbound));
    }

    #[test]
    fn registry_resolves_explicit_detour_without_using_default() {
        let explicit_outbound: Arc<dyn ExecutionOutbound> = Arc::new(TestOutbound::new("proxy"));
        let mut registry = OutboundRegistryBuilder::default();
        registry
            .register(Arc::clone(&explicit_outbound))
            .expect("explicit outbound should register");
        let registry = registry.finalize(Arc::new(TestOutbound::new("direct")));

        let resolved = registry
            .require("proxy")
            .expect("explicit detour should resolve");

        assert!(Arc::ptr_eq(&resolved, &explicit_outbound));
    }

    #[test]
    fn registry_rejects_missing_explicit_detour() {
        let registry =
            OutboundRegistryBuilder::default().finalize(Arc::new(TestOutbound::new("direct")));

        let err = match registry.require("missing") {
            Ok(_) => panic!("missing explicit detour should remain an error"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("missing outbound tag: missing"));
    }

    #[test]
    fn lifecycle_iter_does_not_duplicate_registered_default_outbound() {
        let default_outbound: Arc<dyn ExecutionOutbound> = Arc::new(TestOutbound::new("direct"));
        let mut registry = OutboundRegistryBuilder::default();
        registry
            .register(Arc::clone(&default_outbound))
            .expect("default outbound should register");
        let registry = registry.finalize(default_outbound);

        assert_eq!(registry.lifecycle_iter().count(), 1);
    }
}
