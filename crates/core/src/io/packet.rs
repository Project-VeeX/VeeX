use std::{fmt, net::SocketAddr, sync::Arc};

use crate::{
    portal::traits::BoxFuture,
    types::{Destination, Network},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketFrame {
    pub metadata: PacketMetadata,
    pub payload: Vec<u8>,
}

impl PacketFrame {
    pub fn new(metadata: PacketMetadata, payload: Vec<u8>) -> Self {
        Self { metadata, payload }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketMetadata {
    pub inbound_tag: String,
    pub peer: SocketAddr,
    pub destination: Destination,
    pub network: Network,
}

impl PacketMetadata {
    pub fn new(
        inbound_tag: impl Into<String>,
        peer: SocketAddr,
        destination: Destination,
        network: Network,
    ) -> Self {
        Self {
            inbound_tag: inbound_tag.into(),
            peer,
            destination,
            network,
        }
    }

    pub fn association_key(&self) -> PacketAssociationKey {
        PacketAssociationKey {
            inbound_tag: self.inbound_tag.clone(),
            peer: self.peer,
            destination: self.destination.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PacketAssociationKey {
    pub inbound_tag: String,
    pub peer: SocketAddr,
    pub destination: Destination,
}

impl fmt::Display for PacketAssociationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "inbound={} peer={} destination={}",
            self.inbound_tag, self.peer, self.destination
        )
    }
}

pub trait PacketSession: Send + Sync {
    fn send_packet(&self, payload: Vec<u8>) -> BoxFuture<'_, ()>;
    fn recv_packet(&self) -> BoxFuture<'_, Vec<u8>>;

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

pub type PacketSessionHandle = Arc<dyn PacketSession>;

/// Thin reverse-path writer view.
///
/// The direct UDP inbound implementation backs this with `Arc<UdpSocket>` and plain `send_to`.
/// Packet dispatch owns association/session logic; the writer only sends bytes back to a client peer.
pub trait PacketWriter: Send + Sync {
    fn send_to(&self, peer: SocketAddr, payload: Vec<u8>) -> BoxFuture<'_, ()>;
}

pub struct PacketCarrier {
    pub frame: PacketFrame,
    pub writer: Arc<dyn PacketWriter>,
}

impl PacketCarrier {
    pub fn new(frame: PacketFrame, writer: Arc<dyn PacketWriter>) -> Self {
        Self { frame, writer }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::types::{Destination, Host, Network};

    use super::{PacketAssociationKey, PacketMetadata};

    #[test]
    fn metadata_builds_association_key_without_losing_destination() {
        let metadata = PacketMetadata::new(
            "direct-in",
            SocketAddr::from(([127, 0, 0, 1], 50000)),
            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
            Network::Udp,
        );

        assert_eq!(
            metadata.association_key(),
            PacketAssociationKey {
                inbound_tag: "direct-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 50000)),
                destination: Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            }
        );
    }
}
