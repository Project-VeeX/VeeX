use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use thiserror::Error;

use crate::{
    execution::{
        traits::{PacketDispatch, StreamDispatch},
        PacketDispatcher, StreamDispatcher,
    },
    io::{BoxedAsyncStream, PacketCarrier, PacketFrame, PacketWriter, StreamCarrier},
    portal::traits::BoxFuture,
    session::{SessionContext, SessionMeta},
};

use super::{RouteDecision, Router};

pub struct RouteResult<I> {
    pub ctx: SessionContext,
    pub decision: RouteDecision,
    pub input: I,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Proxy(#[from] crate::ProxyError),
}

impl From<RouteError> for crate::ProxyError {
    fn from(err: RouteError) -> Self {
        match err {
            RouteError::Proxy(err) => err,
        }
    }
}

pub struct RoutedStreamDispatch {
    router: Router,
    executor: Arc<StreamDispatcher>,
}

impl RoutedStreamDispatch {
    pub fn new(router: Router, executor: Arc<StreamDispatcher>) -> Self {
        Self { router, executor }
    }
}

impl StreamDispatch for RoutedStreamDispatch {
    fn dispatch_stream(
        &self,
        inbound_stream: BoxedAsyncStream,
        ctx: SessionContext,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let routed = self
                .router
                .route_stream(StreamCarrier::new(inbound_stream), ctx)
                .await?;
            self.executor.dispatch_routed(routed).await
        })
    }
}

pub struct RoutedPacketDispatch {
    router: Router,
    executor: Arc<PacketDispatcher>,
    next_session_id: AtomicU64,
}

impl RoutedPacketDispatch {
    pub fn new(router: Router, executor: Arc<PacketDispatcher>) -> Self {
        Self {
            router,
            executor,
            next_session_id: AtomicU64::new(1),
        }
    }

    fn next_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    fn build_session_context(&self, packet: &PacketFrame) -> SessionContext {
        SessionContext::new(
            SessionMeta {
                id: self.next_session_id(),
                network: packet.metadata.network,
                inbound_tag: packet.metadata.inbound_tag.clone(),
                peer: packet.metadata.peer,
                destination: packet.metadata.destination.clone(),
                start: Instant::now(),
            },
            Vec::new(),
        )
    }
}

impl PacketDispatch for RoutedPacketDispatch {
    fn dispatch_packet(
        &self,
        packet: PacketFrame,
        writer: Arc<dyn PacketWriter>,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.executor.dispatch_associated(packet.clone()).await? {
                return Ok(());
            }

            let ctx = self.build_session_context(&packet);
            let routed = self
                .router
                .route_packet(PacketCarrier::new(packet, writer), ctx)
                .await?;

            self.executor.dispatch_routed(routed).await
        })
    }
}
