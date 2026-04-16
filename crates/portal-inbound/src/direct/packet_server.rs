use std::{net::SocketAddr, sync::Arc};

use tracing::{debug, info, warn};
use veex_core::{
    io::{PacketFrame, PacketMetadata, PacketWriter},
    logging::{sanitize_field, Logger},
    portal::{
        BoxFuture, Inbound, InboundMeta, PacketListener, PacketListenerReceive,
        PacketListenerReceiveHandler,
    },
    types::{Destination, Host, Network},
    ProxyError, Result,
};
use veex_execution::PacketDispatch;

use super::common::{resolve_local_destination, validate_packet_inbound};

pub struct DirectUdpInbound {
    meta: InboundMeta,
    logger: Logger,
    sink: Arc<dyn PacketDispatch>,
    listener: PacketListener,
    override_host: Option<Host>,
    override_port: Option<u16>,
}

impl DirectUdpInbound {
    pub fn new(
        meta: InboundMeta,
        logger: Logger,
        sink: Arc<dyn PacketDispatch>,
        listener: PacketListener,
        override_host: Option<Host>,
        override_port: Option<u16>,
    ) -> Result<Arc<Self>> {
        let inbound = Arc::new(Self {
            meta,
            logger,
            sink,
            listener,
            override_host,
            override_port,
        });
        inbound.validate()?;
        inbound.bind_listener_handler()?;
        Ok(inbound)
    }

    pub fn validate(&self) -> Result<()> {
        validate_packet_inbound(
            &self.meta,
            &self.listener,
            &self.override_host,
            self.override_port,
        )
    }

    fn bind_listener_handler(self: &Arc<Self>) -> Result<()> {
        let inbound = Arc::clone(self);
        let handler: Arc<PacketListenerReceiveHandler> = Arc::new(move |receive| {
            let inbound = Arc::clone(&inbound);
            Box::pin(async move {
                let peer = receive.peer;
                if let Err(err) = inbound.handle_receive(receive).await {
                    inbound.log_packet_failed(peer, &err);
                }
            })
        });
        self.listener.bind_handler(handler)
    }

    async fn handle_receive(&self, receive: PacketListenerReceive) -> Result<()> {
        let destination =
            resolve_local_destination(receive.local_addr, &self.override_host, self.override_port);
        let destination_field = sanitize_field(&destination.to_string()).into_owned();
        handle_packet(
            Arc::clone(&self.sink),
            receive.writer,
            self.meta.tag.clone(),
            self.logger.clone(),
            receive.peer,
            receive.payload,
            destination,
            destination_field,
        )
        .await
    }

    fn log_packet_failed(&self, peer: SocketAddr, err: &ProxyError) {
        log_packet_failed(&self.logger, peer, err);
    }
}

impl Inbound for DirectUdpInbound {
    fn meta(&self) -> &InboundMeta {
        &self.meta
    }

    fn logger(&self) -> &Logger {
        &self.logger
    }

    fn start(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.validate()?;
            self.listener.start().await
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.listener.close().await })
    }
}

async fn handle_packet(
    sink: Arc<dyn PacketDispatch>,
    writer: Arc<dyn PacketWriter>,
    inbound_tag: String,
    logger: Logger,
    peer: SocketAddr,
    payload: Vec<u8>,
    destination: Destination,
    destination_field: String,
) -> Result<()> {
    let peer_field = sanitize_field(&peer.to_string()).into_owned();
    debug!(
        event = "packet_receive",
        inbound = %logger.tag_field(),
        peer = %peer_field,
        destination = %destination_field,
        payload_len = payload.len() as u64,
        network = %"udp",
        "direct udp packet received"
    );

    let packet = PacketFrame::new(
        PacketMetadata::new(inbound_tag, peer, destination, Network::Udp),
        payload,
    );
    let result = sink.dispatch_packet(packet, writer).await;
    if result.is_ok() {
        info!(
            event = "packet_forwarded",
            inbound = %logger.tag_field(),
            peer = %peer_field,
            destination = %destination_field,
            network = %"udp",
            "direct udp packet forwarded"
        );
    }
    result
}

fn log_packet_failed(logger: &Logger, peer: SocketAddr, err: &ProxyError) {
    let peer_field = sanitize_field(&peer.to_string()).into_owned();
    warn!(
        event = "packet_forward_failed",
        inbound = %logger.tag_field(),
        peer = %peer_field,
        network = %"udp",
        error_kind = ?err.kind(),
        error = %err,
        "direct udp packet forwarding failed"
    );
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::{net::UdpSocket, sync::oneshot};
    use veex_core::{
        io::{PacketFrame, PacketWriter},
        logging::Logger,
        portal::{BoxFuture, Inbound, InboundMeta},
        types::{Destination, Host, Listen},
    };
    use veex_execution::PacketDispatch;

    use super::super::create_direct_packet_listener;
    use super::DirectUdpInbound;

    struct RecordingPacketSink {
        tx: Mutex<Option<oneshot::Sender<PacketFrame>>>,
    }

    impl PacketDispatch for RecordingPacketSink {
        fn dispatch_packet(
            &self,
            packet: PacketFrame,
            _writer: Arc<dyn PacketWriter>,
        ) -> BoxFuture<'_, ()> {
            let tx = self.tx.lock().expect("tx mutex should lock").take();
            Box::pin(async move {
                tx.expect("sender should exist")
                    .send(packet)
                    .expect("packet should be delivered");
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn direct_udp_inbound_submits_listener_destination_without_override() {
        let listen_addr = reserve_udp_port().await;
        let (tx, rx) = oneshot::channel();
        let sink: Arc<dyn PacketDispatch> = Arc::new(RecordingPacketSink {
            tx: Mutex::new(Some(tx)),
        });
        let inbound = DirectUdpInbound::new(
            InboundMeta::new("direct-in", "direct"),
            Logger::new("direct-in", "direct"),
            sink,
            create_direct_packet_listener(Listen::new("127.0.0.1", listen_addr.port())),
            None,
            None,
        )
        .expect("udp direct inbound should build");

        inbound
            .start()
            .await
            .expect("udp direct inbound should start");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("udp client should bind");
        client
            .send_to(b"ping", listen_addr)
            .await
            .expect("udp client should send");

        let packet = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("packet should arrive")
            .expect("packet should be delivered");
        assert_eq!(
            packet.metadata.destination,
            Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_addr.port())
        );
        assert_eq!(packet.payload, b"ping");

        inbound
            .close()
            .await
            .expect("udp direct inbound should close");
    }

    #[tokio::test]
    async fn direct_udp_inbound_applies_override_address_and_port() {
        let listen_addr = reserve_udp_port().await;
        let (tx, rx) = oneshot::channel();
        let sink: Arc<dyn PacketDispatch> = Arc::new(RecordingPacketSink {
            tx: Mutex::new(Some(tx)),
        });
        let inbound = DirectUdpInbound::new(
            InboundMeta::new("direct-in", "direct"),
            Logger::new("direct-in", "direct"),
            sink,
            create_direct_packet_listener(Listen::new("127.0.0.1", listen_addr.port())),
            Some(Host::Domain("dns.example".into())),
            Some(53),
        )
        .expect("udp direct inbound should build");

        inbound
            .start()
            .await
            .expect("udp direct inbound should start");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("udp client should bind");
        client
            .send_to(b"ping", listen_addr)
            .await
            .expect("udp client should send");

        let packet = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("packet should arrive")
            .expect("packet should be delivered");
        assert_eq!(
            packet.metadata.destination,
            Destination::from_domain("dns.example", 53)
        );

        inbound
            .close()
            .await
            .expect("udp direct inbound should close");
    }

    async fn reserve_udp_port() -> SocketAddr {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("temporary udp socket should bind");
        socket
            .local_addr()
            .expect("temporary udp addr should exist")
    }
}
