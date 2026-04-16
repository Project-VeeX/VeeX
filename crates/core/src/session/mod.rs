use std::{net::SocketAddr, time::Instant};

use crate::{
    execution::types::{SessionContext, SessionMeta},
    logging::sanitize_field,
    types::{Destination, Network},
};

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
