use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use crate::{
    dns::DnsExecutorHandle,
    error::ProxyError,
    execution::{
        packet::{
            association::{
                log_packet_association_close, log_packet_association_close_error,
                log_packet_association_hit, PacketAssociation,
            },
            dns::hijack_packet_dns,
            io::{PacketAssociationKey, PacketFrame, PacketMetadata, PacketWriter},
        },
        traits::{DnsHijack, PacketDispatch},
        OutboundRegistry,
    },
    portal::traits::BoxFuture,
    routing::{RouteFinalAction, RouteReason, Router},
    session::{SessionContext, SessionMeta},
    types::Network,
};

const DEFAULT_PACKET_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatcher for packet/UDP execution.
///
/// This path is intentionally independent from the stream dispatcher and owns
/// association lifecycle, packet outbound session binding, and reverse packet flow.
pub struct PacketDispatcher {
    router: Router,
    outbounds: Arc<OutboundRegistry>,
    dns_executor: Option<Arc<dyn DnsExecutorHandle>>,
    associations: Arc<Mutex<HashMap<PacketAssociationKey, Arc<PacketAssociation>>>>,
    next_association_id: AtomicU64,
    idle_timeout: Duration,
}

impl PacketDispatcher {
    pub fn new(router: Router, outbounds: Arc<OutboundRegistry>) -> Self {
        Self::with_dns_executor_and_idle_timeout(
            router,
            outbounds,
            None,
            DEFAULT_PACKET_IDLE_TIMEOUT,
        )
    }

    pub fn with_dns_executor(
        router: Router,
        outbounds: Arc<OutboundRegistry>,
        dns_executor: Option<Arc<dyn DnsExecutorHandle>>,
    ) -> Self {
        Self::with_dns_executor_and_idle_timeout(
            router,
            outbounds,
            dns_executor,
            DEFAULT_PACKET_IDLE_TIMEOUT,
        )
    }

    pub fn with_idle_timeout(
        router: Router,
        outbounds: Arc<OutboundRegistry>,
        idle_timeout: Duration,
    ) -> Self {
        Self::with_dns_executor_and_idle_timeout(router, outbounds, None, idle_timeout)
    }

    pub fn with_dns_executor_and_idle_timeout(
        router: Router,
        outbounds: Arc<OutboundRegistry>,
        dns_executor: Option<Arc<dyn DnsExecutorHandle>>,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            router,
            outbounds,
            dns_executor,
            associations: Arc::new(Mutex::new(HashMap::new())),
            next_association_id: AtomicU64::new(1),
            idle_timeout,
        }
    }

    fn next_association_id(&self) -> u64 {
        self.next_association_id.fetch_add(1, Ordering::Relaxed)
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

    async fn create_association(
        &self,
        mut ctx: SessionContext,
        metadata: &PacketMetadata,
        writer: Arc<dyn PacketWriter>,
        outbound_tag: String,
        route_reason: RouteReason,
    ) -> crate::Result<Arc<PacketAssociation>> {
        ctx.set_route(outbound_tag.clone(), route_reason);
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
            log_packet_association_close(&association, &close_reason);
        });
    }

    async fn dispatch_packet_impl(
        &self,
        packet: PacketFrame,
        writer: Arc<dyn PacketWriter>,
    ) -> crate::Result<()> {
        if packet.metadata.network != Network::Udp {
            return Err(ProxyError::protocol(format!(
                "packet dispatcher only accepts udp packets, got {}",
                packet.metadata.network.as_str()
            )));
        }

        // Route selection is intentionally a first-packet-only decision.
        // Once an association exists, later packets must reuse the bound outbound session
        // and must never re-enter the router.
        let association_key = packet.metadata.association_key();
        let association = match self.association(&association_key) {
            Some(existing) => {
                log_packet_association_hit(&existing);
                existing
            }
            None => {
                let ctx = self.build_session_context(&packet.metadata);
                let decision = self.router.select(&ctx);

                match &decision.final_action {
                    RouteFinalAction::Route(target) => {
                        log_route_select(&ctx, &target.outbound_tag, decision.reason);
                        match self.insert_association(
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
                        }
                    }
                    RouteFinalAction::HijackDns => {
                        return self
                            .hijack((ctx.meta.id, packet, writer), decision.reason)
                            .await;
                    }
                }
            }
        };

        if let Err(err) = association.send(packet.payload).await {
            association.shutdown();
            self.remove_association(association.key(), association.id());
            let _ = association.session().close().await;
            return Err(err);
        }

        Ok(())
    }

    fn build_session_context(&self, metadata: &PacketMetadata) -> SessionContext {
        SessionContext::new(
            SessionMeta {
                id: self.next_association_id(),
                network: metadata.network,
                inbound_tag: metadata.inbound_tag.clone(),
                peer: metadata.peer,
                destination: metadata.destination.clone(),
                start: Instant::now(),
            },
            Vec::new(),
        )
    }
}

impl PacketDispatch for PacketDispatcher {
    fn dispatch_packet(
        &self,
        packet: PacketFrame,
        writer: Arc<dyn PacketWriter>,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.dispatch_packet_impl(packet, writer).await })
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
    ) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            hijack_packet_dns(&executor, session_id, packet, writer, route_reason).await
        })
    }
}

fn log_route_select(ctx: &SessionContext, outbound_tag: &str, route_reason: RouteReason) {
    tracing::info!(
        event = "route_select",
        session_id = ctx.meta.id,
        inbound = %crate::logging::sanitize_field(ctx.meta.inbound_tag.as_str()),
        peer = %crate::logging::sanitize_field(&ctx.meta.peer.to_string()),
        destination = %crate::logging::sanitize_field(&ctx.meta.destination.to_string()),
        outbound = %crate::logging::sanitize_field(outbound_tag),
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
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    use tokio::sync::{mpsc, Mutex as AsyncMutex};
    use veex_test_tracing::{assert_has_event, captured_events, install_test_subscriber};

    use crate::{
        dns::{DnsExecutorHandle, DnsRequest, DnsResponse},
        logging::Logger,
        routing::{RouteAction, RouteFinalAction, RouteRule},
        types::Host,
        BoxFuture, BoxedAsyncStream, Destination, ExecutionOutbound, Network, Outbound,
        OutboundMeta, OutboundRegistry, OutboundRegistryBuilder, PacketDispatch, PacketFrame,
        PacketMetadata, PacketSession, PacketSessionHandle, PacketWriter, ProxyError,
        SessionContext,
    };

    use super::PacketDispatcher;

    type RecordedPacketWrites = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

    struct TestPacketSession {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        recv: AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    }

    impl PacketSession for TestPacketSession {
        fn send_packet(&self, payload: Vec<u8>) -> BoxFuture<'_, ()> {
            let sent = Arc::clone(&self.sent);
            Box::pin(async move {
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
    }

    struct RecordingWriter {
        sent: RecordedPacketWrites,
    }

    impl PacketWriter for RecordingWriter {
        fn send_to(&self, peer: SocketAddr, payload: Vec<u8>) -> BoxFuture<'_, ()> {
            let sent = Arc::clone(&self.sent);
            Box::pin(async move {
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
        fn open_stream(&self, _ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("stream path is not used in this test")) })
        }

        fn open_packet(&self, _ctx: &SessionContext) -> BoxFuture<'_, PacketSessionHandle> {
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
        })
    }

    fn finalized_registry(outbound: Arc<dyn ExecutionOutbound>) -> Arc<OutboundRegistry> {
        let mut builder = OutboundRegistryBuilder::default();
        builder
            .register(Arc::clone(&outbound))
            .expect("registry should accept outbound");
        Arc::new(builder.finalize(outbound))
    }

    fn empty_registry() -> Arc<OutboundRegistry> {
        finalized_registry(
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
        });
        let outbound = Arc::new(TestDispatchOutbound::new("direct", session));
        let dispatcher = PacketDispatcher::with_idle_timeout(
            crate::Router::with_default_outbound("direct"),
            finalized_registry(outbound.clone() as Arc<dyn ExecutionOutbound>),
            Duration::from_secs(1),
        );
        let writer_sent = Arc::new(Mutex::new(Vec::new()));
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::clone(&writer_sent),
        });
        let metadata = PacketMetadata::new(
            "direct-in",
            SocketAddr::from(([127, 0, 0, 1], 53000)),
            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
            Network::Udp,
        );

        dispatcher
            .dispatch_packet(
                PacketFrame::new(metadata.clone(), b"ping".to_vec()),
                Arc::clone(&writer),
            )
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
        dispatcher
            .dispatch_packet(PacketFrame::new(metadata, b"pang".to_vec()), writer)
            .await
            .expect("second packet should reuse association");

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
    }

    #[tokio::test]
    async fn packet_dispatcher_closes_idle_association() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let (_upstream_tx, upstream_rx) = mpsc::unbounded_channel();
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            sent: Arc::new(Mutex::new(Vec::new())),
            recv: AsyncMutex::new(upstream_rx),
        });
        let outbound = Arc::new(TestDispatchOutbound::new("direct", session));
        let dispatcher = PacketDispatcher::with_idle_timeout(
            crate::Router::with_default_outbound("direct"),
            finalized_registry(outbound as Arc<dyn ExecutionOutbound>),
            Duration::from_millis(50),
        );
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::new(Mutex::new(Vec::new())),
        });

        dispatcher
            .dispatch_packet(
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
            )
            .await
            .expect("packet should dispatch");
        tokio::time::sleep(Duration::from_millis(120)).await;

        let events = captured_events(&trace_buffer);
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
            crate::Router::with_default_outbound("direct").with_rule(RouteRule {
                inbound: vec!["dns-in".into()],
                action: RouteAction::Final(RouteFinalAction::HijackDns),
                ..RouteRule::new("unused")
            }),
            empty_registry(),
            Some(Arc::new(TestDnsExecutor {
                responses: Arc::new(Mutex::new(vec![b"dns-response".to_vec()])),
                query_count: AtomicUsize::new(0),
            }) as Arc<dyn DnsExecutorHandle>),
        );
        let writer_sent = Arc::new(Mutex::new(Vec::new()));
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::clone(&writer_sent),
        });

        dispatcher
            .dispatch_packet(
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
            )
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
