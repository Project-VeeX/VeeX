use std::{net::SocketAddr, sync::Arc};

use tokio::{
    net::UdpSocket,
    sync::{oneshot, Mutex},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, info, warn};
use veex_core::{
    sanitize_field, BoxFuture, Destination, Host, Inbound, InboundMeta, Listen, Logger, Network,
    PacketFrame, PacketMetadata, PacketSink, PacketWriter, ProxyError, Result,
};

use crate::{create_direct_udp_socket, DirectError};

#[derive(Default)]
struct DirectUdpInboundState {
    close_tx: Mutex<Option<oneshot::Sender<()>>>,
    task: Mutex<Option<JoinHandle<Result<()>>>>,
}

pub struct DirectUdpInbound {
    meta: InboundMeta,
    logger: Logger,
    sink: Arc<dyn PacketSink>,
    listen: Listen,
    override_host: Option<Host>,
    override_port: Option<u16>,
    state: Arc<DirectUdpInboundState>,
}

impl DirectUdpInbound {
    pub fn new(
        meta: InboundMeta,
        logger: Logger,
        sink: Arc<dyn PacketSink>,
        listen: Listen,
        override_host: Option<Host>,
        override_port: Option<u16>,
    ) -> Result<Arc<Self>> {
        let inbound = Arc::new(Self {
            meta,
            logger,
            sink,
            listen,
            override_host,
            override_port,
            state: Arc::new(DirectUdpInboundState::default()),
        });
        inbound.validate()?;
        Ok(inbound)
    }

    pub fn validate(&self) -> Result<()> {
        if self.meta.tag.trim().is_empty() {
            return Err(ProxyError::config(
                "direct udp inbound tag must not be empty",
            ));
        }
        if self.meta.r#type.trim().is_empty() {
            return Err(ProxyError::config(
                "direct udp inbound type must not be empty",
            ));
        }
        if self.listen.listen().trim().is_empty() {
            return Err(ProxyError::config(
                "direct udp inbound listen must not be empty",
            ));
        }
        if self.listen.listen_port() == 0 {
            return Err(ProxyError::config(
                "direct udp inbound listen_port must be within 1..=65535",
            ));
        }
        if matches!(self.override_host.as_ref(), Some(Host::Domain(domain)) if domain.trim().is_empty())
        {
            return Err(ProxyError::config(
                "direct udp inbound override_address must not be empty",
            ));
        }
        if matches!(self.override_port, Some(0)) {
            return Err(ProxyError::config(
                "direct udp inbound override_port must be within 1..=65535",
            ));
        }
        self.listen.parse_addr().map(|_| ()).map_err(|err| {
            ProxyError::config(format!("listen must be a valid socket address: {err}"))
        })
    }

    fn resolve_destination(
        &self,
        local_addr: SocketAddr,
    ) -> std::result::Result<Destination, DirectError> {
        let mut destination = Destination::from_ip(local_addr.ip(), local_addr.port());
        if let Some(host) = &self.override_host {
            destination.host = host.clone();
        }
        if let Some(port) = self.override_port {
            destination.port = port;
        }
        Ok(destination)
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

            let mut task_guard = self.state.task.lock().await;
            if task_guard.is_some() {
                return Ok(());
            }

            let bind_addr = self.listen.parse_addr().map_err(|err| {
                ProxyError::config(format!("listen must be a valid socket address: {err}"))
            })?;
            let socket = Arc::new(create_direct_udp_socket(bind_addr).map_err(ProxyError::from)?);
            let local_addr = socket.local_addr()?;
            let destination = self.resolve_destination(local_addr)?;
            let writer: Arc<dyn PacketWriter> = Arc::new(DirectUdpWriter {
                socket: Arc::clone(&socket),
            });
            let sink = Arc::clone(&self.sink);
            let inbound_tag = self.meta.tag.clone();
            let logger = self.logger.clone();
            let destination_field = sanitize_field(&destination.to_string()).into_owned();
            let (close_tx, mut close_rx) = oneshot::channel();

            let task = tokio::spawn(async move {
                let mut packet_tasks = JoinSet::new();
                let mut buf = vec![0u8; u16::MAX as usize];
                let mut shutting_down = false;

                loop {
                    if shutting_down && packet_tasks.is_empty() {
                        break;
                    }

                    tokio::select! {
                        _ = &mut close_rx, if !shutting_down => {
                            shutting_down = true;
                        }
                        recv_result = socket.recv_from(&mut buf), if !shutting_down => {
                            let (size, peer) = recv_result?;
                            let payload = buf[..size].to_vec();
                            let sink = Arc::clone(&sink);
                            let writer = Arc::clone(&writer);
                            let inbound_tag = inbound_tag.clone();
                            let logger = logger.clone();
                            let logger_for_error = logger.clone();
                            let destination = destination.clone();
                            let destination_field = destination_field.clone();
                            packet_tasks.spawn(async move {
                                if let Err(err) = handle_packet(
                                    sink,
                                    writer,
                                    inbound_tag,
                                    logger,
                                    peer,
                                    payload,
                                    destination,
                                    destination_field,
                                ).await {
                                    log_packet_failed(&logger_for_error, peer, &err);
                                }
                            });
                        }
                        maybe_task = packet_tasks.join_next(), if !packet_tasks.is_empty() => {
                            if let Some(Err(err)) = maybe_task {
                                return Err(ProxyError::protocol_ctx(
                                    "direct udp packet task join failed",
                                    err,
                                ));
                            }
                        }
                    }
                }

                Ok(())
            });

            *self.state.close_tx.lock().await = Some(close_tx);
            *task_guard = Some(task);
            Ok(())
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let close_tx = self.state.close_tx.lock().await.take();
            if let Some(close_tx) = close_tx {
                let _ = close_tx.send(());
            }

            let Some(task) = self.state.task.lock().await.take() else {
                return Ok(());
            };

            match task.await {
                Ok(result) => result,
                Err(err) => Err(ProxyError::protocol_ctx(
                    "direct udp listener task join failed",
                    err,
                )),
            }
        })
    }
}

struct DirectUdpWriter {
    socket: Arc<UdpSocket>,
}

impl PacketWriter for DirectUdpWriter {
    fn send_to(&self, peer: SocketAddr, payload: Vec<u8>) -> BoxFuture<'_, ()> {
        // This is intentionally a thin `Arc<UdpSocket> + send_to` writer view.
        // Multiple associations may share the same inbound socket for reverse writes.
        Box::pin(async move {
            self.socket.send_to(&payload, peer).await?;
            Ok(())
        })
    }
}

async fn handle_packet(
    sink: Arc<dyn PacketSink>,
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
    let result = sink.submit_packet(packet, writer).await;
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
        BoxFuture, Destination, Host, Inbound, InboundMeta, Listen, Logger, PacketFrame,
        PacketSink, PacketWriter,
    };

    use super::DirectUdpInbound;

    struct RecordingPacketSink {
        tx: Mutex<Option<oneshot::Sender<PacketFrame>>>,
    }

    impl PacketSink for RecordingPacketSink {
        fn submit_packet(
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
        let sink: Arc<dyn PacketSink> = Arc::new(RecordingPacketSink {
            tx: Mutex::new(Some(tx)),
        });
        let inbound = DirectUdpInbound::new(
            InboundMeta::new("direct-in", "direct"),
            Logger::new("direct-in", "direct"),
            sink,
            Listen::new("127.0.0.1", listen_addr.port()),
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
        let sink: Arc<dyn PacketSink> = Arc::new(RecordingPacketSink {
            tx: Mutex::new(Some(tx)),
        });
        let inbound = DirectUdpInbound::new(
            InboundMeta::new("direct-in", "direct"),
            Logger::new("direct-in", "direct"),
            sink,
            Listen::new("127.0.0.1", listen_addr.port()),
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
