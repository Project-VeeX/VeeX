use std::{net::SocketAddr, sync::Arc, time::Instant};

use crate::{
    dns::ResolveContext,
    logging::sanitize_field,
    types::{Destination, Network},
};

/// Immutable metadata carried across a session execution path.
#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub id: u64,
    pub network: Network,
    pub inbound_tag: String,
    pub peer: SocketAddr,
    pub destination: Destination,
    pub start: Instant,
}

/// Routing decision recorded onto a session after dispatch selection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionRoute {
    pub selected_outbound: Option<String>,
}

impl SessionRoute {
    pub fn selected(selected_outbound: impl Into<String>) -> Self {
        Self {
            selected_outbound: Some(selected_outbound.into()),
        }
    }
}

/// Mutable execution state accumulated alongside the session metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionState {
    pub buffered_payload: Vec<u8>,
    pub resolve_context: Option<ResolveContext>,
}

/// Session semantic handoff shared by routing, execution, portal, and outbound code.
#[derive(Clone, Debug)]
pub struct SessionContext {
    pub meta: Arc<SessionMeta>,
    pub route: SessionRoute,
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

    pub fn set_route(&mut self, selected_outbound: impl Into<String>) {
        self.route = SessionRoute::selected(selected_outbound);
    }

    pub fn set_resolve_context(&mut self, context: Option<ResolveContext>) {
        self.state.resolve_context = context;
    }
}

#[derive(Clone, Debug)]
pub struct SessionBootstrap {
    pub id: u64,
    pub ctx: SessionContext,
    pub inbound_field: String,
    pub peer_field: String,
    pub destination_field: String,
}

pub fn build_session_bootstrap(
    session_id: u64,
    inbound_tag: &str,
    peer: SocketAddr,
    destination: Destination,
) -> SessionBootstrap {
    let inbound_field = sanitize_field(inbound_tag).into_owned();
    let peer_field = sanitize_field(&peer.to_string()).into_owned();
    let destination_field = sanitize_field(&destination.to_string()).into_owned();
    let ctx = SessionContext::new(
        SessionMeta {
            id: session_id,
            network: Network::Tcp,
            inbound_tag: inbound_tag.to_string(),
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

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Instant,
    };

    use crate::types::{Destination, Host};

    use super::{SessionContext, SessionMeta};
    use crate::types::Network;

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

        ctx.set_route("proxy");

        assert_eq!(ctx.route.selected_outbound.as_deref(), Some("proxy"));
    }
}
