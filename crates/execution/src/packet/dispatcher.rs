use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use veex_core::{
    ProxyError,
    dns::DnsExecutorHandle,
    io::{PacketAssociationKey, PacketCarrier, PacketFrame, PacketMetadata, PacketWriter},
    session::SessionContext,
    types::Network,
};
use veex_router::{RouteFinalAction, RouteReason, RouteResult};

use crate::{
    ExecutionFuture, OutboundCatalog,
    packet::{
        association::{
            PacketAssociation, PacketSessionShutdownReason, log_packet_association_close_error,
            log_packet_association_hit, log_packet_session_close,
        },
        dns::hijack_packet_dns,
    },
    traits::DnsHijack,
};

const DEFAULT_PACKET_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatcher for packet/UDP execution.
///
/// This path is intentionally independent from the stream dispatcher and owns
/// association lifecycle, packet outbound session binding, and reverse packet flow.
pub struct PacketDispatcher {
    outbounds: Arc<OutboundCatalog>,
    dns_executor: Option<Arc<dyn DnsExecutorHandle>>,
    associations: Arc<Mutex<HashMap<PacketAssociationKey, Arc<PacketAssociation>>>>,
    idle_timeout: Duration,
}

impl PacketDispatcher {
    pub fn new(outbounds: Arc<OutboundCatalog>) -> Self {
        Self::with_dns_executor_and_idle_timeout(outbounds, None, DEFAULT_PACKET_IDLE_TIMEOUT)
    }

    pub fn with_dns_executor(
        outbounds: Arc<OutboundCatalog>,
        dns_executor: Option<Arc<dyn DnsExecutorHandle>>,
    ) -> Self {
        Self::with_dns_executor_and_idle_timeout(
            outbounds,
            dns_executor,
            DEFAULT_PACKET_IDLE_TIMEOUT,
        )
    }

    pub fn with_idle_timeout(outbounds: Arc<OutboundCatalog>, idle_timeout: Duration) -> Self {
        Self::with_dns_executor_and_idle_timeout(outbounds, None, idle_timeout)
    }

    pub fn with_dns_executor_and_idle_timeout(
        outbounds: Arc<OutboundCatalog>,
        dns_executor: Option<Arc<dyn DnsExecutorHandle>>,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            outbounds,
            dns_executor,
            associations: Arc::new(Mutex::new(HashMap::new())),
            idle_timeout,
        }
    }

    fn association(&self, key: &PacketAssociationKey) -> Option<Arc<PacketAssociation>> {
        lock_unpoisoned(&self.associations).get(key).map(Arc::clone)
    }

    fn insert_association(
        &self,
        association: Arc<PacketAssociation>,
    ) -> Result<Arc<PacketAssociation>, Arc<PacketAssociation>> {
        let mut associations = lock_unpoisoned(&self.associations);
        if let Some(existing) = associations.get(association.key()) {
            return Err(Arc::clone(existing));
        }
        associations.insert(association.key().clone(), Arc::clone(&association));
        Ok(association)
    }

    fn remove_association(&self, key: &PacketAssociationKey, association_id: u64) {
        remove_association_from_map(&self.associations, key, association_id);
    }

    fn association_count(&self) -> usize {
        lock_unpoisoned(&self.associations).len()
    }

    pub async fn shutdown(&self) {
        let associations = {
            let associations = lock_unpoisoned(&self.associations);
            associations.values().cloned().collect::<Vec<_>>()
        };
        for association in &associations {
            association.shutdown(PacketSessionShutdownReason::DispatcherShutdown);
        }
        for _ in 0..50 {
            if self.association_count() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn create_association(
        &self,
        mut ctx: SessionContext,
        metadata: &PacketMetadata,
        writer: Arc<dyn PacketWriter>,
        outbound_tag: String,
        route_reason: RouteReason,
    ) -> veex_core::Result<Arc<PacketAssociation>> {
        ctx.set_route(outbound_tag.clone());
        let outbound = self.outbounds.require(&outbound_tag)?;
        let session = outbound.open_packet(&ctx).await?;
        Ok(PacketAssociation::new(
            ctx.meta.id,
            metadata.association_key(),
            outbound_tag,
            route_reason,
            session,
            writer,
        ))
    }

    fn spawn_reverse_loop(&self, association: Arc<PacketAssociation>) {
        let idle_timeout = self.idle_timeout;
        let associations = Arc::clone(&self.associations);

        tokio::spawn(async move {
            let close_reason = association.run_reverse_loop(idle_timeout).await;
            remove_association_from_map(&associations, association.key(), association.id());
            if let Err(err) = association.session().close().await {
                log_packet_association_close_error(&association, &err);
            }
            log_packet_session_close(&association, &close_reason);
        });
    }

    pub(crate) async fn dispatch_associated(&self, packet: PacketFrame) -> veex_core::Result<bool> {
        if packet.metadata.network != Network::Udp {
            return Err(ProxyError::protocol(format!(
                "packet dispatcher only accepts udp packets, got {}",
                packet.metadata.network.as_str()
            )));
        }

        let association_key = packet.metadata.association_key();
        let Some(association) = self.association(&association_key) else {
            return Ok(false);
        };
        log_packet_association_hit(&association);

        if let Err(err) = association.send(packet.payload).await {
            association.shutdown(PacketSessionShutdownReason::ForwardError);
            self.remove_association(association.key(), association.id());
            return Err(err);
        }

        Ok(true)
    }

    pub(crate) async fn dispatch_routed(
        &self,
        routed: RouteResult<PacketCarrier>,
    ) -> veex_core::Result<()> {
        let RouteResult {
            ctx,
            decision,
            input,
        } = routed;
        let PacketCarrier {
            frame: packet,
            writer,
        } = input;

        if packet.metadata.network != Network::Udp {
            return Err(ProxyError::protocol(format!(
                "packet dispatcher only accepts udp packets, got {}",
                packet.metadata.network.as_str()
            )));
        }

        log_packet_session_start(&ctx);

        match &decision.final_action {
            RouteFinalAction::Route(target) => {
                log_route_select(&ctx, &target.outbound_tag, decision.reason);
                let association = match self.insert_association(
                    self.create_association(
                        ctx,
                        &packet.metadata,
                        writer,
                        target.outbound_tag.clone(),
                        decision.reason,
                    )
                    .await?,
                ) {
                    Ok(created) => {
                        self.spawn_reverse_loop(Arc::clone(&created));
                        created
                    }
                    Err(existing) => {
                        log_packet_association_hit(&existing);
                        existing
                    }
                };

                if let Err(err) = association.send(packet.payload).await {
                    association.shutdown(PacketSessionShutdownReason::ForwardError);
                    self.remove_association(association.key(), association.id());
                    return Err(err);
                }

                Ok(())
            }
            RouteFinalAction::HijackDns => {
                self.hijack((ctx.meta.id, packet, writer), decision.reason)
                    .await
            }
        }
    }
}

impl DnsHijack for PacketDispatcher {
    type Input = (u64, PacketFrame, Arc<dyn PacketWriter>);

    fn dns_executor(&self) -> Option<&Arc<dyn DnsExecutorHandle>> {
        self.dns_executor.as_ref()
    }

    fn hijack_with_executor(
        &self,
        executor: Arc<dyn DnsExecutorHandle>,
        (session_id, packet, writer): Self::Input,
        route_reason: RouteReason,
    ) -> ExecutionFuture<'_, ()> {
        Box::pin(async move {
            hijack_packet_dns(&executor, session_id, packet, writer, route_reason).await
        })
    }
}

fn log_packet_session_start(ctx: &SessionContext) {
    tracing::info!(
        event = "packet_session_start",
        session_id = ctx.meta.id,
        inbound = %veex_core::logging::sanitize_field(ctx.meta.inbound_tag.as_str()),
        peer = %veex_core::logging::sanitize_field(&ctx.meta.peer.to_string()),
        destination = %veex_core::logging::sanitize_field(&ctx.meta.destination.to_string()),
        network = ctx.meta.network.as_str(),
        "packet session start"
    );
}

fn log_route_select(ctx: &SessionContext, outbound_tag: &str, route_reason: RouteReason) {
    tracing::info!(
        event = "route_select",
        session_id = ctx.meta.id,
        inbound = %veex_core::logging::sanitize_field(ctx.meta.inbound_tag.as_str()),
        peer = %veex_core::logging::sanitize_field(&ctx.meta.peer.to_string()),
        destination = %veex_core::logging::sanitize_field(&ctx.meta.destination.to_string()),
        outbound = %veex_core::logging::sanitize_field(outbound_tag),
        route_reason = %route_reason.as_str(),
        default_final = matches!(route_reason, RouteReason::Final),
        network = ctx.meta.network.as_str(),
        "route selected"
    );
}

fn remove_association_from_map(
    associations: &Mutex<HashMap<PacketAssociationKey, Arc<PacketAssociation>>>,
    key: &PacketAssociationKey,
    association_id: u64,
) {
    let mut associations = lock_unpoisoned(associations);
    if matches!(associations.get(key), Some(existing) if existing.id() == association_id) {
        associations.remove(key);
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use tokio::sync::{Mutex as AsyncMutex, mpsc};
    use veex_test_tracing::{assert_has_event, captured_events, install_test_subscriber};

    use veex_core::{
        ProxyError,
        dns::{DnsExecutorHandle, DnsRequest, DnsResponse},
        io::{
            BoxedAsyncStream, PacketCarrier, PacketFrame, PacketMetadata, PacketSession,
            PacketSessionHandle, PacketWriter,
        },
        logging::Logger,
        portal::{BoxFuture, Outbound, OutboundMeta},
        session::{SessionContext, SessionMeta},
        types::{Destination, Host, Network},
    };
    use veex_router::{RouteDecision, RouteFinalAction, RouteReason, RouteResult};

    use crate::{ExecutionFuture, ExecutionOutbound, OutboundCatalog};

    use super::PacketDispatcher;

    type RecordedPacketWrites = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

    struct TestPacketSession {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        recv: AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        send_error: Mutex<Option<ProxyError>>,
        close_count: AtomicUsize,
    }

    impl PacketSession for TestPacketSession {
        fn send_packet(&self, payload: Vec<u8>) -> BoxFuture<'_, ()> {
            let sent = Arc::clone(&self.sent);
            let err = self
                .send_error
                .lock()
                .expect("send error mutex should lock")
                .take();
            Box::pin(async move {
                if let Some(err) = err {
                    return Err(err);
                }
                sent.lock().expect("sent mutex should lock").push(payload);
                Ok(())
            })
        }

        fn recv_packet(&self) -> BoxFuture<'_, Vec<u8>> {
            Box::pin(async move {
                self.recv
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or(ProxyError::Shutdown)
            })
        }

        fn close(&self) -> BoxFuture<'_, ()> {
            self.close_count.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    struct RecordingWriter {
        sent: RecordedPacketWrites,
        send_error: Mutex<Option<ProxyError>>,
    }

    impl PacketWriter for RecordingWriter {
        fn send_to(&self, peer: SocketAddr, payload: Vec<u8>) -> BoxFuture<'_, ()> {
            let sent = Arc::clone(&self.sent);
            let err = self
                .send_error
                .lock()
                .expect("writer error mutex should lock")
                .take();
            Box::pin(async move {
                if let Some(err) = err {
                    return Err(err);
                }
                sent.lock()
                    .expect("writer mutex should lock")
                    .push((peer, payload));
                Ok(())
            })
        }
    }

    struct TestDispatchOutbound {
        meta: OutboundMeta,
        logger: Logger,
        connect_count: AtomicUsize,
        session: PacketSessionHandle,
    }

    impl TestDispatchOutbound {
        fn new(tag: &str, session: PacketSessionHandle) -> Self {
            Self {
                meta: OutboundMeta::new(tag, "test"),
                logger: Logger::new(tag, "test"),
                connect_count: AtomicUsize::new(0),
                session,
            }
        }
    }

    impl Outbound for TestDispatchOutbound {
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

    impl ExecutionOutbound for TestDispatchOutbound {
        fn tag(&self) -> &str {
            &self.meta.tag
        }

        fn open_stream(&self, _ctx: &SessionContext) -> ExecutionFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("stream path is not used in this test")) })
        }

        fn open_packet(&self, _ctx: &SessionContext) -> ExecutionFuture<'_, PacketSessionHandle> {
            self.connect_count.fetch_add(1, Ordering::Relaxed);
            let session = Arc::clone(&self.session);
            Box::pin(async move { Ok(session) })
        }
    }

    struct TestDnsExecutor {
        responses: Arc<Mutex<Vec<Vec<u8>>>>,
        query_count: AtomicUsize,
    }

    impl DnsExecutorHandle for TestDnsExecutor {
        fn execute_query(&self, _request: DnsRequest) -> BoxFuture<'_, DnsResponse> {
            self.query_count.fetch_add(1, Ordering::Relaxed);
            let responses = Arc::clone(&self.responses);
            Box::pin(async move {
                let mut responses = responses.lock().expect("responses mutex should lock");
                if responses.is_empty() {
                    return Err(ProxyError::protocol("missing dns test response"));
                }
                Ok(DnsResponse::new(responses.remove(0)))
            })
        }
    }

    fn empty_test_session() -> PacketSessionHandle {
        let (_upstream_tx, upstream_rx) = mpsc::unbounded_channel();
        Arc::new(TestPacketSession {
            sent: Arc::new(Mutex::new(Vec::new())),
            recv: AsyncMutex::new(upstream_rx),
            send_error: Mutex::new(None),
            close_count: AtomicUsize::new(0),
        })
    }

    fn finalized_catalog(outbound: Arc<dyn ExecutionOutbound>) -> Arc<OutboundCatalog> {
        let mut outbounds = HashMap::new();
        outbounds.insert(outbound.tag().to_string(), Arc::clone(&outbound));
        Arc::new(OutboundCatalog::new(outbounds, outbound))
    }

    fn empty_catalog() -> Arc<OutboundCatalog> {
        finalized_catalog(
            Arc::new(TestDispatchOutbound::new("direct", empty_test_session()))
                as Arc<dyn ExecutionOutbound>,
        )
    }

    #[tokio::test]
    async fn packet_dispatcher_reuses_association_and_reverses_packets() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (upstream_tx, upstream_rx) = mpsc::unbounded_channel();
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            sent: Arc::clone(&sent),
            recv: AsyncMutex::new(upstream_rx),
            send_error: Mutex::new(None),
            close_count: AtomicUsize::new(0),
        });
        let outbound = Arc::new(TestDispatchOutbound::new("direct", session));
        let dispatcher = PacketDispatcher::with_idle_timeout(
            finalized_catalog(outbound.clone() as Arc<dyn ExecutionOutbound>),
            Duration::from_secs(1),
        );
        let writer_sent = Arc::new(Mutex::new(Vec::new()));
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::clone(&writer_sent),
            send_error: Mutex::new(None),
        });
        let metadata = PacketMetadata::new(
            "direct-in",
            SocketAddr::from(([127, 0, 0, 1], 53000)),
            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
            Network::Udp,
        );

        dispatcher
            .dispatch_routed(RouteResult {
                ctx: SessionContext::new(
                    SessionMeta {
                        id: 1,
                        network: Network::Udp,
                        inbound_tag: "direct-in".into(),
                        peer: SocketAddr::from(([127, 0, 0, 1], 53000)),
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            5353,
                        ),
                        start: std::time::Instant::now(),
                    },
                    Vec::new(),
                ),
                decision: RouteDecision::route("direct", RouteReason::Final),
                input: PacketCarrier::new(
                    PacketFrame::new(metadata.clone(), b"ping".to_vec()),
                    Arc::clone(&writer),
                ),
            })
            .await
            .expect("first packet should dispatch");
        upstream_tx
            .send(b"pong".to_vec())
            .expect("upstream payload should enqueue");
        wait_for(|| {
            writer_sent
                .lock()
                .expect("writer mutex should lock")
                .iter()
                .any(|(_, payload)| payload == b"pong")
        })
        .await;
        let reused = dispatcher
            .dispatch_associated(PacketFrame::new(metadata, b"pang".to_vec()))
            .await
            .expect("second packet should reuse association");
        assert!(reused, "second packet should reuse an existing association");

        assert_eq!(outbound.connect_count.load(Ordering::Relaxed), 1);
        assert_eq!(
            sent.lock().expect("sent mutex should lock").as_slice(),
            &[b"ping".to_vec(), b"pang".to_vec()]
        );
        assert_eq!(
            writer_sent
                .lock()
                .expect("writer mutex should lock")
                .as_slice(),
            &[(SocketAddr::from(([127, 0, 0, 1], 53000)), b"pong".to_vec())]
        );

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "packet_session_start",
            &[
                ("session_id", "1"),
                ("inbound", "direct-in"),
                ("network", "udp"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "route_select",
            &[
                ("session_id", "1"),
                ("inbound", "direct-in"),
                ("outbound", "direct"),
                ("network", "udp"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "packet_association_create",
            &[
                ("inbound", "direct-in"),
                ("outbound", "direct"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "packet_association_hit",
            &[
                ("inbound", "direct-in"),
                ("outbound", "direct"),
                ("route_reason", "final"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "packet_forward_send",
            &[
                ("inbound", "direct-in"),
                ("outbound", "direct"),
                ("route_reason", "final"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "packet_reverse_recv",
            &[
                ("inbound", "direct-in"),
                ("outbound", "direct"),
                ("route_reason", "final"),
                ("level", "DEBUG"),
            ],
        );
    }

    #[tokio::test]
    async fn packet_dispatcher_closes_idle_association() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let (_upstream_tx, upstream_rx) = mpsc::unbounded_channel();
        let session = Arc::new(TestPacketSession {
            sent: Arc::new(Mutex::new(Vec::new())),
            recv: AsyncMutex::new(upstream_rx),
            send_error: Mutex::new(None),
            close_count: AtomicUsize::new(0),
        });
        let outbound = Arc::new(TestDispatchOutbound::new(
            "direct",
            session.clone() as PacketSessionHandle,
        ));
        let dispatcher = PacketDispatcher::with_idle_timeout(
            finalized_catalog(outbound as Arc<dyn ExecutionOutbound>),
            Duration::from_millis(50),
        );
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::new(Mutex::new(Vec::new())),
            send_error: Mutex::new(None),
        });

        dispatcher
            .dispatch_routed(RouteResult {
                ctx: SessionContext::new(
                    SessionMeta {
                        id: 1,
                        network: Network::Udp,
                        inbound_tag: "direct-in".into(),
                        peer: SocketAddr::from(([127, 0, 0, 1], 53001)),
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            5353,
                        ),
                        start: std::time::Instant::now(),
                    },
                    Vec::new(),
                ),
                decision: RouteDecision::route("direct", RouteReason::Final),
                input: PacketCarrier::new(
                    PacketFrame::new(
                        PacketMetadata::new(
                            "direct-in",
                            SocketAddr::from(([127, 0, 0, 1], 53001)),
                            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
                            Network::Udp,
                        ),
                        b"ping".to_vec(),
                    ),
                    writer,
                ),
            })
            .await
            .expect("packet should dispatch");
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(session.close_count.load(Ordering::Relaxed), 1);
        assert_eq!(dispatcher.association_count(), 0);

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "packet_session_idle_reclaimed",
            &[("route_reason", "final"), ("level", "INFO")],
        );
        assert_has_event(
            &events,
            "packet_session_closed",
            &[
                ("close_reason", "idle"),
                ("route_reason", "final"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "packet_association_close",
            &[
                ("close_reason", "idle"),
                ("route_reason", "final"),
                ("level", "INFO"),
            ],
        );
    }

    #[tokio::test]
    async fn packet_dispatcher_hands_hijack_dns_to_executor_without_association() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let dispatcher = PacketDispatcher::with_dns_executor(
            empty_catalog(),
            Some(Arc::new(TestDnsExecutor {
                responses: Arc::new(Mutex::new(vec![b"dns-response".to_vec()])),
                query_count: AtomicUsize::new(0),
            }) as Arc<dyn DnsExecutorHandle>),
        );
        let writer_sent = Arc::new(Mutex::new(Vec::new()));
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::clone(&writer_sent),
            send_error: Mutex::new(None),
        });

        dispatcher
            .dispatch_routed(RouteResult {
                ctx: SessionContext::new(
                    SessionMeta {
                        id: 1,
                        network: Network::Udp,
                        inbound_tag: "dns-in".into(),
                        peer: SocketAddr::from(([127, 0, 0, 1], 53053)),
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            53,
                        ),
                        start: std::time::Instant::now(),
                    },
                    Vec::new(),
                ),
                decision: RouteDecision {
                    final_action: RouteFinalAction::HijackDns,
                    reason: RouteReason::Rule,
                },
                input: PacketCarrier::new(
                    PacketFrame::new(
                        PacketMetadata::new(
                            "dns-in",
                            SocketAddr::from(([127, 0, 0, 1], 53053)),
                            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                            Network::Udp,
                        ),
                        b"dns-query".to_vec(),
                    ),
                    writer,
                ),
            })
            .await
            .expect("dns hijack should succeed");

        assert_eq!(
            writer_sent
                .lock()
                .expect("writer mutex should lock")
                .as_slice(),
            &[(
                SocketAddr::from(([127, 0, 0, 1], 53053)),
                b"dns-response".to_vec()
            )]
        );

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "packet_hijack_dns",
            &[
                ("session_id", "1"),
                ("inbound", "dns-in"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "packet_hijack_dns_complete",
            &[
                ("session_id", "1"),
                ("inbound", "dns-in"),
                ("level", "INFO"),
            ],
        );
        assert!(
            !events.iter().any(|event| {
                event.fields.get("event").map(String::as_str) == Some("packet_association_create")
            }),
            "dns hijack should not create a forward association: {events:?}"
        );
    }

    #[tokio::test]
    async fn packet_dispatcher_shutdown_closes_active_associations() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let (_upstream_tx, upstream_rx) = mpsc::unbounded_channel();
        let session = Arc::new(TestPacketSession {
            sent: Arc::new(Mutex::new(Vec::new())),
            recv: AsyncMutex::new(upstream_rx),
            send_error: Mutex::new(None),
            close_count: AtomicUsize::new(0),
        });
        let outbound = Arc::new(TestDispatchOutbound::new(
            "direct",
            session.clone() as PacketSessionHandle,
        ));
        let dispatcher = PacketDispatcher::with_idle_timeout(
            finalized_catalog(outbound as Arc<dyn ExecutionOutbound>),
            Duration::from_secs(5),
        );
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::new(Mutex::new(Vec::new())),
            send_error: Mutex::new(None),
        });

        dispatcher
            .dispatch_routed(RouteResult {
                ctx: SessionContext::new(
                    SessionMeta {
                        id: 1,
                        network: Network::Udp,
                        inbound_tag: "direct-in".into(),
                        peer: SocketAddr::from(([127, 0, 0, 1], 53011)),
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            5353,
                        ),
                        start: std::time::Instant::now(),
                    },
                    Vec::new(),
                ),
                decision: RouteDecision::route("direct", RouteReason::Final),
                input: PacketCarrier::new(
                    PacketFrame::new(
                        PacketMetadata::new(
                            "direct-in",
                            SocketAddr::from(([127, 0, 0, 1], 53011)),
                            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
                            Network::Udp,
                        ),
                        b"ping".to_vec(),
                    ),
                    writer,
                ),
            })
            .await
            .expect("packet should dispatch");

        dispatcher.shutdown().await;

        assert_eq!(dispatcher.association_count(), 0);
        assert_eq!(session.close_count.load(Ordering::Relaxed), 1);

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "packet_session_shutdown",
            &[
                ("shutdown_reason", "dispatcher_shutdown"),
                ("route_reason", "final"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "packet_session_closed",
            &[
                ("close_reason", "shutdown"),
                ("route_reason", "final"),
                ("level", "INFO"),
            ],
        );
    }

    #[tokio::test]
    async fn packet_dispatcher_forward_send_failure_shuts_down_association() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let (_upstream_tx, upstream_rx) = mpsc::unbounded_channel();
        let session = Arc::new(TestPacketSession {
            sent: Arc::new(Mutex::new(Vec::new())),
            recv: AsyncMutex::new(upstream_rx),
            send_error: Mutex::new(Some(ProxyError::dial("udp send init failed"))),
            close_count: AtomicUsize::new(0),
        });
        let outbound = Arc::new(TestDispatchOutbound::new(
            "direct",
            session.clone() as PacketSessionHandle,
        ));
        let dispatcher = PacketDispatcher::with_idle_timeout(
            finalized_catalog(outbound as Arc<dyn ExecutionOutbound>),
            Duration::from_secs(5),
        );
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::new(Mutex::new(Vec::new())),
            send_error: Mutex::new(None),
        });

        let err = dispatcher
            .dispatch_routed(RouteResult {
                ctx: SessionContext::new(
                    SessionMeta {
                        id: 1,
                        network: Network::Udp,
                        inbound_tag: "direct-in".into(),
                        peer: SocketAddr::from(([127, 0, 0, 1], 53012)),
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            5353,
                        ),
                        start: std::time::Instant::now(),
                    },
                    Vec::new(),
                ),
                decision: RouteDecision::route("direct", RouteReason::Final),
                input: PacketCarrier::new(
                    PacketFrame::new(
                        PacketMetadata::new(
                            "direct-in",
                            SocketAddr::from(([127, 0, 0, 1], 53012)),
                            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
                            Network::Udp,
                        ),
                        b"ping".to_vec(),
                    ),
                    writer,
                ),
            })
            .await
            .expect_err("forward send failure should surface");
        assert_eq!(err.kind(), veex_core::ErrorKind::Dial);

        wait_for(|| {
            dispatcher.association_count() == 0 && session.close_count.load(Ordering::Relaxed) == 1
        })
        .await;

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "packet_forward_failed",
            &[
                ("route_reason", "final"),
                ("error_kind", "dial"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "packet_session_shutdown",
            &[
                ("shutdown_reason", "forward_error"),
                ("route_reason", "final"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "packet_session_closed",
            &[
                ("close_reason", "shutdown"),
                ("route_reason", "final"),
                ("level", "INFO"),
            ],
        );
    }

    #[tokio::test]
    async fn packet_dispatcher_reverse_failure_does_not_leak_association() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let (upstream_tx, upstream_rx) = mpsc::unbounded_channel();
        let session = Arc::new(TestPacketSession {
            sent: Arc::new(Mutex::new(Vec::new())),
            recv: AsyncMutex::new(upstream_rx),
            send_error: Mutex::new(None),
            close_count: AtomicUsize::new(0),
        });
        let outbound = Arc::new(TestDispatchOutbound::new(
            "direct",
            session.clone() as PacketSessionHandle,
        ));
        let dispatcher = PacketDispatcher::with_idle_timeout(
            finalized_catalog(outbound as Arc<dyn ExecutionOutbound>),
            Duration::from_secs(5),
        );
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::new(Mutex::new(Vec::new())),
            send_error: Mutex::new(Some(ProxyError::from(std::io::Error::other(
                "client socket closed",
            )))),
        });

        dispatcher
            .dispatch_routed(RouteResult {
                ctx: SessionContext::new(
                    SessionMeta {
                        id: 1,
                        network: Network::Udp,
                        inbound_tag: "direct-in".into(),
                        peer: SocketAddr::from(([127, 0, 0, 1], 53013)),
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            5353,
                        ),
                        start: std::time::Instant::now(),
                    },
                    Vec::new(),
                ),
                decision: RouteDecision::route("direct", RouteReason::Final),
                input: PacketCarrier::new(
                    PacketFrame::new(
                        PacketMetadata::new(
                            "direct-in",
                            SocketAddr::from(([127, 0, 0, 1], 53013)),
                            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
                            Network::Udp,
                        ),
                        b"ping".to_vec(),
                    ),
                    writer,
                ),
            })
            .await
            .expect("packet should dispatch");

        upstream_tx
            .send(b"pong".to_vec())
            .expect("upstream payload should enqueue");
        wait_for(|| {
            dispatcher.association_count() == 0 && session.close_count.load(Ordering::Relaxed) == 1
        })
        .await;

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "packet_reverse_recv",
            &[("route_reason", "final"), ("level", "DEBUG")],
        );
        assert_has_event(
            &events,
            "packet_reverse_failed",
            &[
                ("failure_stage", "write_back"),
                ("error_kind", "io"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "packet_session_closed",
            &[
                ("close_reason", "client_write_error"),
                ("error_kind", "io"),
                ("level", "WARN"),
            ],
        );
    }

    #[tokio::test]
    async fn packet_dispatcher_hijack_dns_without_executor_is_a_config_error() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let dispatcher = PacketDispatcher::with_dns_executor(empty_catalog(), None);
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::new(Mutex::new(Vec::new())),
            send_error: Mutex::new(None),
        });

        let err = dispatcher
            .dispatch_routed(RouteResult {
                ctx: SessionContext::new(
                    SessionMeta {
                        id: 1,
                        network: Network::Udp,
                        inbound_tag: "dns-in".into(),
                        peer: SocketAddr::from(([127, 0, 0, 1], 53054)),
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            53,
                        ),
                        start: std::time::Instant::now(),
                    },
                    Vec::new(),
                ),
                decision: RouteDecision {
                    final_action: RouteFinalAction::HijackDns,
                    reason: RouteReason::Rule,
                },
                input: PacketCarrier::new(
                    PacketFrame::new(
                        PacketMetadata::new(
                            "dns-in",
                            SocketAddr::from(([127, 0, 0, 1], 53054)),
                            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                            Network::Udp,
                        ),
                        b"dns-query".to_vec(),
                    ),
                    writer,
                ),
            })
            .await
            .expect_err("dns hijack without executor should fail");
        assert_eq!(err.kind(), veex_core::ErrorKind::Config);
        assert_eq!(dispatcher.association_count(), 0);

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "packet_session_start",
            &[
                ("session_id", "1"),
                ("inbound", "dns-in"),
                ("level", "INFO"),
            ],
        );
        assert!(
            !events.iter().any(|event| {
                event.fields.get("event").map(String::as_str) == Some("packet_association_create")
            }),
            "failed hijack should not create packet associations: {events:?}"
        );
    }

    async fn wait_for(predicate: impl Fn() -> bool) {
        for _ in 0..50 {
            if predicate() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        panic!("condition was not met within retry budget");
    }
}
