use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::{
    dispatcher::OutboundRegistry,
    dns::DnsExecutorHandle,
    error::ProxyError,
    logging::sanitize_field,
    packet::{
        PacketAssociationKey, PacketFrame, PacketMetadata, PacketSessionHandle, PacketWriter,
    },
    router::{RouteFinalAction, Router},
    traits::BoxFuture,
    types::{Network, RouteReason, SessionContext, SessionMeta},
};

const DEFAULT_PACKET_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub trait PacketSink: Send + Sync {
    fn submit_packet(
        &self,
        packet: PacketFrame,
        writer: Arc<dyn PacketWriter>,
    ) -> BoxFuture<'_, ()>;
}

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

struct PacketAssociation {
    id: u64,
    key: PacketAssociationKey,
    outbound_tag: String,
    route_reason: RouteReason,
    session: PacketSessionHandle,
    writer: Arc<dyn PacketWriter>,
    last_activity: Mutex<Instant>,
    activity: Notify,
    closed: AtomicBool,
    close_notify: Notify,
}

#[derive(Clone, Debug)]
struct PacketAssociationTrace {
    association_id: u64,
    inbound_field: String,
    outbound_field: String,
    peer_field: String,
    destination_field: String,
    route_reason: RouteReason,
}

#[derive(Debug)]
enum PacketAssociationCloseReason {
    Idle,
    UpstreamError(ProxyError),
    ClientWriteError(ProxyError),
    Shutdown,
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
        if let Some(existing) = associations.get(&association.key) {
            return Err(Arc::clone(existing));
        }
        associations.insert(association.key.clone(), Arc::clone(&association));
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
        let outbound = self
            .outbounds
            .get(&outbound_tag)
            .ok_or_else(|| ProxyError::config(format!("missing outbound tag: {outbound_tag}")))?;
        let session = outbound.connect_packet(&ctx).await?;
        let association = Arc::new(PacketAssociation {
            id: ctx.meta.id,
            key: metadata.association_key(),
            outbound_tag,
            route_reason,
            session,
            writer,
            last_activity: Mutex::new(Instant::now()),
            activity: Notify::new(),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        });

        log_packet_association_create(&PacketAssociationTrace::from_association(&association));
        Ok(association)
    }

    async fn hijack_dns(
        &self,
        packet: PacketFrame,
        writer: Arc<dyn PacketWriter>,
        route_reason: RouteReason,
    ) -> crate::Result<()> {
        let executor = self.dns_executor.as_ref().ok_or_else(|| {
            ProxyError::config("route selected 'hijack-dns' but dns executor is not configured")
        })?;
        let inbound = sanitize_field(&packet.metadata.inbound_tag).into_owned();
        let peer = sanitize_field(&packet.metadata.peer.to_string()).into_owned();
        let destination = sanitize_field(&packet.metadata.destination.to_string()).into_owned();
        info!(
            event = "packet_hijack_dns",
            inbound = %inbound,
            peer = %peer,
            destination = %destination,
            route_reason = %route_reason.as_str(),
            "packet handed off to dns executor"
        );

        let peer_addr = packet.metadata.peer;
        let response = match executor.execute_query(packet).await {
            Ok(response) => response,
            Err(err) => {
                warn!(
                    event = "packet_hijack_dns_failed",
                    inbound = %inbound,
                    peer = %peer,
                    destination = %destination,
                    route_reason = %route_reason.as_str(),
                    error_kind = ?err.kind(),
                    error = %err,
                    "dns executor failed"
                );
                return Err(err);
            }
        };

        if let Err(err) = writer.send_to(peer_addr, response).await {
            warn!(
                event = "packet_hijack_dns_write_failed",
                inbound = %inbound,
                peer = %peer,
                destination = %destination,
                route_reason = %route_reason.as_str(),
                error_kind = ?err.kind(),
                error = %err,
                "dns response write-back failed"
            );
            return Err(err);
        }

        info!(
            event = "packet_hijack_dns_complete",
            inbound = %inbound,
            peer = %peer,
            destination = %destination,
            route_reason = %route_reason.as_str(),
            "dns response written back to client"
        );
        Ok(())
    }

    fn spawn_reverse_loop(&self, association: Arc<PacketAssociation>) {
        let idle_timeout = self.idle_timeout;
        let associations = Arc::clone(&self.associations);

        tokio::spawn(async move {
            let close_reason = association.run_reverse_loop(idle_timeout).await;
            remove_association_from_map(&associations, &association.key, association.id);
            if let Err(err) = association.session.close().await {
                warn!(
                    event = "packet_association_close_error",
                    association_id = association.id,
                    inbound = %sanitize_field(&association.key.inbound_tag),
                    destination = %sanitize_field(&association.key.destination.to_string()),
                    error_kind = ?err.kind(),
                    error = %err,
                    "packet association close failed"
                );
            }
            log_packet_association_close(
                &PacketAssociationTrace::from_association(&association),
                &close_reason,
            );
        });
    }

    async fn submit_packet_impl(
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
                log_packet_association_hit(&PacketAssociationTrace::from_association(&existing));
                existing
            }
            None => {
                let session_id = self.next_association_id();
                let ctx = SessionContext::new(
                    SessionMeta {
                        id: session_id,
                        network: packet.metadata.network,
                        inbound_tag: packet.metadata.inbound_tag.clone(),
                        peer: packet.metadata.peer,
                        destination: packet.metadata.destination.clone(),
                        start: Instant::now(),
                    },
                    Vec::new(),
                );
                let decision = self.router.select(&ctx);

                match &decision.final_action {
                    RouteFinalAction::Route(target) => match self.insert_association(
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
                            log_packet_association_hit(&PacketAssociationTrace::from_association(
                                &existing,
                            ));
                            existing
                        }
                    },
                    RouteFinalAction::HijackDns => {
                        return self.hijack_dns(packet, writer, decision.reason).await;
                    }
                }
            }
        };

        if let Err(err) = association.send(packet.payload).await {
            association.shutdown();
            self.remove_association(&association.key, association.id);
            let _ = association.session.close().await;
            return Err(err);
        }

        Ok(())
    }
}

impl PacketSink for PacketDispatcher {
    fn submit_packet(
        &self,
        packet: PacketFrame,
        writer: Arc<dyn PacketWriter>,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.submit_packet_impl(packet, writer).await })
    }
}

impl PacketAssociation {
    async fn send(&self, payload: Vec<u8>) -> crate::Result<()> {
        self.touch();
        let result = self.session.send_packet(payload).await;
        if result.is_ok() {
            self.touch();
        }
        result
    }

    async fn run_reverse_loop(&self, idle_timeout: Duration) -> PacketAssociationCloseReason {
        loop {
            if self.is_closed() {
                return PacketAssociationCloseReason::Shutdown;
            }

            let idle_wait = tokio::time::sleep(self.remaining_idle(idle_timeout));
            let close_wait = self.close_notify.notified();
            tokio::pin!(idle_wait);
            tokio::pin!(close_wait);

            tokio::select! {
                _ = &mut close_wait => {
                    if self.is_closed() {
                        return PacketAssociationCloseReason::Shutdown;
                    }
                }
                _ = self.activity.notified() => {}
                recv_result = self.session.recv_packet() => {
                    match recv_result {
                        Ok(payload) => {
                            self.touch();
                            let trace = PacketAssociationTrace::from_association(self);
                            log_packet_reverse(&trace, payload.len());
                            if let Err(err) = self.writer.send_to(self.key.peer, payload).await {
                                return PacketAssociationCloseReason::ClientWriteError(err);
                            }
                        }
                        Err(err) => return PacketAssociationCloseReason::UpstreamError(err),
                    }
                }
                _ = &mut idle_wait => {
                    if self.is_idle(idle_timeout) {
                        return PacketAssociationCloseReason::Idle;
                    }
                }
            }
        }
    }

    fn remaining_idle(&self, idle_timeout: Duration) -> Duration {
        idle_timeout.saturating_sub(self.last_activity().elapsed())
    }

    fn is_idle(&self, idle_timeout: Duration) -> bool {
        self.last_activity().elapsed() >= idle_timeout
    }

    fn touch(&self) {
        *lock_unpoisoned(&self.last_activity) = Instant::now();
        self.activity.notify_waiters();
    }

    fn shutdown(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.close_notify.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn last_activity(&self) -> Instant {
        *lock_unpoisoned(&self.last_activity)
    }
}

impl PacketAssociationTrace {
    fn from_association(association: &PacketAssociation) -> Self {
        Self {
            association_id: association.id,
            inbound_field: sanitize_field(&association.key.inbound_tag).into_owned(),
            outbound_field: sanitize_field(&association.outbound_tag).into_owned(),
            peer_field: sanitize_field(&association.key.peer.to_string()).into_owned(),
            destination_field: sanitize_field(&association.key.destination.to_string())
                .into_owned(),
            route_reason: association.route_reason,
        }
    }
}

impl PacketAssociationCloseReason {
    fn label(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::UpstreamError(_) => "upstream_error",
            Self::ClientWriteError(_) => "client_write_error",
            Self::Shutdown => "shutdown",
        }
    }

    fn error(&self) -> Option<&ProxyError> {
        match self {
            Self::Idle => None,
            Self::Shutdown => None,
            Self::UpstreamError(err) | Self::ClientWriteError(err) => Some(err),
        }
    }
}

fn remove_association_from_map(
    associations: &Mutex<HashMap<PacketAssociationKey, Arc<PacketAssociation>>>,
    key: &PacketAssociationKey,
    association_id: u64,
) {
    let mut associations = lock_unpoisoned(associations);
    if matches!(associations.get(key), Some(existing) if existing.id == association_id) {
        associations.remove(key);
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn log_packet_association_create(trace: &PacketAssociationTrace) {
    info!(
        event = "packet_association_create",
        association_id = trace.association_id,
        inbound = %trace.inbound_field,
        outbound = %trace.outbound_field,
        peer = %trace.peer_field,
        destination = %trace.destination_field,
        route_reason = %trace.route_reason.as_str(),
        "packet association created"
    );
}

fn log_packet_association_hit(trace: &PacketAssociationTrace) {
    debug!(
        event = "packet_association_hit",
        association_id = trace.association_id,
        inbound = %trace.inbound_field,
        outbound = %trace.outbound_field,
        peer = %trace.peer_field,
        destination = %trace.destination_field,
        "packet association hit"
    );
}

fn log_packet_reverse(trace: &PacketAssociationTrace, payload_len: usize) {
    debug!(
        event = "packet_reverse_write",
        association_id = trace.association_id,
        inbound = %trace.inbound_field,
        outbound = %trace.outbound_field,
        peer = %trace.peer_field,
        destination = %trace.destination_field,
        payload_len = payload_len as u64,
        "packet reverse write"
    );
}

fn log_packet_association_close(
    trace: &PacketAssociationTrace,
    close_reason: &PacketAssociationCloseReason,
) {
    if let Some(err) = close_reason.error() {
        log_packet_association_close_error(trace, close_reason.label(), err);
    } else {
        info!(
            event = "packet_association_close",
            association_id = trace.association_id,
            inbound = %trace.inbound_field,
            outbound = %trace.outbound_field,
            peer = %trace.peer_field,
            destination = %trace.destination_field,
            close_reason = close_reason.label(),
            "packet association closed"
        );
    }
}

fn log_packet_association_close_error(
    trace: &PacketAssociationTrace,
    close_reason: &str,
    err: &ProxyError,
) {
    warn!(
        event = "packet_association_close",
        association_id = trace.association_id,
        inbound = %trace.inbound_field,
        outbound = %trace.outbound_field,
        peer = %trace.peer_field,
        destination = %trace.destination_field,
        close_reason,
        error_kind = ?err.kind(),
        error = %err,
        "packet association closed"
    );
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
        dispatcher::{OutboundConnector, OutboundRegistry},
        dns::DnsExecutorHandle,
        logging::Logger,
        packet::{PacketFrame, PacketMetadata, PacketSession, PacketSessionHandle},
        router::{RouteAction, RouteFinalAction, RouteRule},
        service::OutboundMeta,
        traits::Outbound,
        types::{Destination, Host, Network},
        ProxyError,
    };

    use super::{PacketDispatcher, PacketSink, PacketWriter};

    struct TestPacketSession {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        recv: AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    }

    impl PacketSession for TestPacketSession {
        fn send_packet(&self, payload: Vec<u8>) -> crate::traits::BoxFuture<'_, ()> {
            let sent = Arc::clone(&self.sent);
            Box::pin(async move {
                sent.lock().expect("sent mutex should lock").push(payload);
                Ok(())
            })
        }

        fn recv_packet(&self) -> crate::traits::BoxFuture<'_, Vec<u8>> {
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
        sent: Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>,
    }

    impl PacketWriter for RecordingWriter {
        fn send_to(&self, peer: SocketAddr, payload: Vec<u8>) -> crate::traits::BoxFuture<'_, ()> {
            let sent = Arc::clone(&self.sent);
            Box::pin(async move {
                sent.lock()
                    .expect("writer mutex should lock")
                    .push((peer, payload));
                Ok(())
            })
        }
    }

    struct TestOutboundConnector {
        meta: OutboundMeta,
        logger: Logger,
        connect_count: AtomicUsize,
        session: PacketSessionHandle,
    }

    impl TestOutboundConnector {
        fn new(tag: &str, session: PacketSessionHandle) -> Self {
            Self {
                meta: OutboundMeta::new(tag, "test"),
                logger: Logger::new(tag, "test"),
                connect_count: AtomicUsize::new(0),
                session,
            }
        }
    }

    impl Outbound for TestOutboundConnector {
        fn meta(&self) -> &OutboundMeta {
            &self.meta
        }

        fn logger(&self) -> &Logger {
            &self.logger
        }

        fn close(&self) -> crate::traits::BoxFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    impl OutboundConnector for TestOutboundConnector {
        fn connect(
            &self,
            _ctx: &crate::types::SessionContext,
        ) -> crate::traits::BoxFuture<'_, crate::types::BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("stream path is not used in this test")) })
        }

        fn connect_packet(
            &self,
            _ctx: &crate::types::SessionContext,
        ) -> crate::traits::BoxFuture<'_, PacketSessionHandle> {
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
        fn execute_query(&self, _packet: PacketFrame) -> crate::traits::BoxFuture<'_, Vec<u8>> {
            self.query_count.fetch_add(1, Ordering::Relaxed);
            let responses = Arc::clone(&self.responses);
            Box::pin(async move {
                let mut responses = responses.lock().expect("responses mutex should lock");
                if responses.is_empty() {
                    return Err(ProxyError::protocol("missing dns test response"));
                }
                Ok(responses.remove(0))
            })
        }
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
        let outbound = Arc::new(TestOutboundConnector::new("direct", session));
        let mut registry = OutboundRegistry::default();
        registry
            .register(outbound.clone() as Arc<dyn OutboundConnector>)
            .expect("registry should accept outbound");
        let dispatcher = PacketDispatcher::with_idle_timeout(
            crate::Router::with_default_outbound("direct"),
            Arc::new(registry),
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
            .submit_packet(
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
            .submit_packet(PacketFrame::new(metadata, b"pang".to_vec()), writer)
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
        let outbound = Arc::new(TestOutboundConnector::new("direct", session));
        let mut registry = OutboundRegistry::default();
        registry
            .register(outbound as Arc<dyn OutboundConnector>)
            .expect("registry should accept outbound");
        let dispatcher = PacketDispatcher::with_idle_timeout(
            crate::Router::with_default_outbound("direct"),
            Arc::new(registry),
            Duration::from_millis(50),
        );
        let writer: Arc<dyn PacketWriter> = Arc::new(RecordingWriter {
            sent: Arc::new(Mutex::new(Vec::new())),
        });

        dispatcher
            .submit_packet(
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
            &[("close_reason", "idle"), ("level", "INFO")],
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
            Arc::new(OutboundRegistry::default()),
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
            .submit_packet(
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
            &[("inbound", "dns-in"), ("level", "INFO")],
        );
        assert_has_event(
            &events,
            "packet_hijack_dns_complete",
            &[("inbound", "dns-in"), ("level", "INFO")],
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
