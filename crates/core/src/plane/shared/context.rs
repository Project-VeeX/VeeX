use std::{net::SocketAddr, sync::Arc, time::Instant};

use crate::{
    dns::ResolveContext,
    types::{Destination, Network},
};

/// The reason a particular route decision was made.
///
/// This is used for observability and logging to understand why
/// a session was routed to a specific outbound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteReason {
    /// Routed by the user-defined route.rules chain.
    Rule,
    /// Routed by the default final action after no rule produced a final action.
    Final,
}

impl RouteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Final => "final",
        }
    }
}

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

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Instant,
    };

    use crate::types::{Destination, Host, Network};

    use super::{RouteReason, SessionContext, SessionMeta};

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
}
