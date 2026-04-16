use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use tokio::sync::Notify;
use tracing::{debug, info, warn};

use veex_core::{
    io::{PacketAssociationKey, PacketSessionHandle, PacketWriter},
    logging::sanitize_field,
    routing::RouteReason,
    ProxyError,
};

/// Packet-side forwarding state, roughly parallel to stream relay state.
///
/// A packet association binds one client flow key to one outbound packet session and owns
/// reverse-path forwarding, activity tracking, and close tracing.
pub(crate) struct PacketAssociation {
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

#[derive(Debug)]
pub(crate) enum PacketAssociationCloseReason {
    Idle,
    UpstreamError(ProxyError),
    ClientWriteError(ProxyError),
    Shutdown,
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

impl PacketAssociation {
    pub(crate) fn new(
        id: u64,
        key: PacketAssociationKey,
        outbound_tag: String,
        route_reason: RouteReason,
        session: PacketSessionHandle,
        writer: Arc<dyn PacketWriter>,
    ) -> Arc<Self> {
        let association = Arc::new(Self {
            id,
            key,
            outbound_tag,
            route_reason,
            session,
            writer,
            last_activity: Mutex::new(Instant::now()),
            activity: Notify::new(),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        });
        log_packet_association_create(&association);
        association
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn key(&self) -> &PacketAssociationKey {
        &self.key
    }

    pub(crate) fn session(&self) -> &PacketSessionHandle {
        &self.session
    }

    pub(crate) async fn send(&self, payload: Vec<u8>) -> veex_core::Result<()> {
        self.touch();
        let result = self.session.send_packet(payload).await;
        if result.is_ok() {
            self.touch();
        }
        result
    }

    pub(crate) async fn run_reverse_loop(
        &self,
        idle_timeout: Duration,
    ) -> PacketAssociationCloseReason {
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
                            log_packet_reverse(self, payload.len());
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

    pub(crate) fn shutdown(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.close_notify.notify_waiters();
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

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn last_activity(&self) -> Instant {
        *lock_unpoisoned(&self.last_activity)
    }
}

pub(crate) fn log_packet_association_hit(association: &PacketAssociation) {
    let trace = PacketAssociationTrace::from_association(association);
    debug!(
        event = "packet_association_hit",
        association_id = trace.association_id,
        inbound = %trace.inbound_field,
        outbound = %trace.outbound_field,
        peer = %trace.peer_field,
        destination = %trace.destination_field,
        route_reason = %trace.route_reason.as_str(),
        "packet association hit"
    );
}

pub(crate) fn log_packet_association_close_error(
    association: &PacketAssociation,
    err: &ProxyError,
) {
    let trace = PacketAssociationTrace::from_association(association);
    warn!(
        event = "packet_association_close_error",
        association_id = trace.association_id,
        inbound = %trace.inbound_field,
        outbound = %trace.outbound_field,
        peer = %trace.peer_field,
        destination = %trace.destination_field,
        route_reason = %trace.route_reason.as_str(),
        error_kind = ?err.kind(),
        error = %err,
        "packet association close failed"
    );
}

pub(crate) fn log_packet_association_close(
    association: &PacketAssociation,
    close_reason: &PacketAssociationCloseReason,
) {
    let trace = PacketAssociationTrace::from_association(association);
    if let Some(err) = close_reason.error() {
        warn!(
            event = "packet_association_close",
            association_id = trace.association_id,
            inbound = %trace.inbound_field,
            outbound = %trace.outbound_field,
            peer = %trace.peer_field,
            destination = %trace.destination_field,
            close_reason = close_reason.label(),
            route_reason = %trace.route_reason.as_str(),
            error_kind = ?err.kind(),
            error = %err,
            "packet association closed"
        );
    } else {
        info!(
            event = "packet_association_close",
            association_id = trace.association_id,
            inbound = %trace.inbound_field,
            outbound = %trace.outbound_field,
            peer = %trace.peer_field,
            destination = %trace.destination_field,
            close_reason = close_reason.label(),
            route_reason = %trace.route_reason.as_str(),
            "packet association closed"
        );
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

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn log_packet_association_create(association: &PacketAssociation) {
    let trace = PacketAssociationTrace::from_association(association);
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

fn log_packet_reverse(association: &PacketAssociation, payload_len: usize) {
    let trace = PacketAssociationTrace::from_association(association);
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
