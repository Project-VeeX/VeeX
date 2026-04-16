use std::net::SocketAddr;

use tokio::net::TcpStream;
use veex_core::{Destination, Host, InboundMeta, Listener, PacketListener, ProxyError, Result};

use crate::DirectError;

pub(super) fn validate_stream_inbound(
    meta: &InboundMeta,
    listener: &Listener,
    override_host: &Option<Host>,
    override_port: Option<u16>,
) -> Result<()> {
    validate_direct_inbound(meta, "direct inbound", override_host, override_port)?;
    validate_listen_fields(
        listener.listen().listen(),
        listener.listen().listen_port(),
        "direct inbound listen",
        "direct inbound listen_port",
    )?;
    listener.bind_addr().map(|_| ())
}

pub(super) fn validate_packet_inbound(
    meta: &InboundMeta,
    listener: &PacketListener,
    override_host: &Option<Host>,
    override_port: Option<u16>,
) -> Result<()> {
    validate_direct_inbound(meta, "direct udp inbound", override_host, override_port)?;
    validate_listen_fields(
        listener.listen().listen(),
        listener.listen().listen_port(),
        "direct udp inbound listen",
        "direct udp inbound listen_port",
    )?;
    listener.bind_addr().map(|_| ())
}

pub(super) fn resolve_stream_destination(
    stream: &TcpStream,
    override_host: &Option<Host>,
    override_port: Option<u16>,
) -> std::result::Result<Destination, DirectError> {
    let local_addr = stream.local_addr()?;
    Ok(resolve_local_destination(
        local_addr,
        override_host,
        override_port,
    ))
}

pub(super) fn resolve_local_destination(
    local_addr: SocketAddr,
    override_host: &Option<Host>,
    override_port: Option<u16>,
) -> Destination {
    apply_destination_override(
        Destination::from_ip(local_addr.ip(), local_addr.port()),
        override_host,
        override_port,
    )
}

fn validate_direct_inbound(
    meta: &InboundMeta,
    inbound_kind: &str,
    override_host: &Option<Host>,
    override_port: Option<u16>,
) -> Result<()> {
    if meta.tag.trim().is_empty() {
        return Err(ProxyError::config(format!(
            "{inbound_kind} tag must not be empty"
        )));
    }
    if meta.r#type.trim().is_empty() {
        return Err(ProxyError::config(format!(
            "{inbound_kind} type must not be empty"
        )));
    }
    if matches!(override_host.as_ref(), Some(Host::Domain(domain)) if domain.trim().is_empty()) {
        return Err(ProxyError::config(format!(
            "{inbound_kind} override_address must not be empty"
        )));
    }
    if matches!(override_port, Some(0)) {
        return Err(ProxyError::config(format!(
            "{inbound_kind} override_port must be within 1..=65535"
        )));
    }
    Ok(())
}

fn validate_listen_fields(
    listen: &str,
    listen_port: u16,
    empty_listen_message: &str,
    invalid_port_message: &str,
) -> Result<()> {
    if listen.trim().is_empty() {
        return Err(ProxyError::config(format!(
            "{empty_listen_message} must not be empty"
        )));
    }
    if listen_port == 0 {
        return Err(ProxyError::config(format!(
            "{invalid_port_message} must be within 1..=65535"
        )));
    }
    Ok(())
}

fn apply_destination_override(
    mut destination: Destination,
    override_host: &Option<Host>,
    override_port: Option<u16>,
) -> Destination {
    if let Some(host) = override_host {
        destination.host = host.clone();
    }
    if let Some(port) = override_port {
        destination.port = port;
    }
    destination
}
