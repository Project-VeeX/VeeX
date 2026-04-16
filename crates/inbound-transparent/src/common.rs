use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
};

use veex_core::{
    build_session_bootstrap, Destination, InboundMeta, Listener, ProxyError, Result,
    SessionBootstrap,
};

#[derive(Debug, Default)]
pub(super) struct TransparentInboundState {
    pub(super) next_session_id: AtomicU64,
}

pub(super) fn validate_transparent_inbound(
    meta: &InboundMeta,
    listener: &Listener,
    inbound_kind: &str,
) -> Result<()> {
    if meta.tag.trim().is_empty() {
        return Err(ProxyError::config(format!(
            "{inbound_kind} inbound tag must not be empty"
        )));
    }
    if meta.r#type.trim().is_empty() {
        return Err(ProxyError::config(format!(
            "{inbound_kind} inbound type must not be empty"
        )));
    }
    if listener.listen().listen().trim().is_empty() {
        return Err(ProxyError::config(format!(
            "{inbound_kind} inbound listen must not be empty"
        )));
    }
    if listener.listen().listen_port() == 0 {
        return Err(ProxyError::config(format!(
            "{inbound_kind} inbound listen_port must be within 1..=65535"
        )));
    }
    listener.bind_addr().map(|_| ())
}

pub(super) fn build_transparent_session(
    state: &TransparentInboundState,
    inbound_tag: &str,
    peer: SocketAddr,
    destination: Destination,
) -> SessionBootstrap {
    build_session_bootstrap(
        state.next_session_id.fetch_add(1, Ordering::Relaxed),
        inbound_tag,
        peer,
        destination,
    )
}
