use std::{net::SocketAddr, time::Instant};

use veex_core::{sanitize_field, Destination, Network, SessionContext, SessionMeta};

pub(crate) struct SessionBootstrap {
    pub(crate) id: u64,
    pub(crate) ctx: SessionContext,
    pub(crate) inbound_field: String,
    pub(crate) peer_field: String,
    pub(crate) destination_field: String,
}

pub(crate) fn build_session_bootstrap(
    session_id: u64,
    inbound_tag: &str,
    peer: SocketAddr,
    destination: Destination,
) -> SessionBootstrap {
    let inbound_field = sanitize_field(inbound_tag).into_owned();
    let peer_field = peer.to_string();
    let peer_field = sanitize_field(&peer_field).into_owned();
    let destination_field = destination.to_string();
    let destination_field = sanitize_field(&destination_field).into_owned();
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
