use std::future::Future;

use thiserror::Error;
use tracing::{error, info, warn};
use veex_config::ProxyConfig;
use veex_core::{sanitize_field, OutboundRegistry, ProxyError};

use crate::bootstrap::{build_runtime_state, BootstrapError, RuntimeState};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime bootstrap failed: {0}")]
    Bootstrap(#[from] BootstrapError),
    #[error("shutdown wait failed: {message}")]
    ShutdownWait { message: String },
    #[error("runtime inbound task `{inbound}` failed: {source}")]
    Task {
        inbound: String,
        #[source]
        source: ProxyError,
    },
    #[error("runtime outbound task `{outbound}` failed: {source}")]
    OutboundTask {
        outbound: String,
        #[source]
        source: ProxyError,
    },
}

impl RuntimeError {
    fn shutdown_wait(message: impl Into<String>) -> Self {
        Self::ShutdownWait {
            message: message.into(),
        }
    }

    fn task(inbound: impl Into<String>, source: ProxyError) -> Self {
        Self::Task {
            inbound: inbound.into(),
            source,
        }
    }

    fn outbound_task(outbound: impl Into<String>, source: ProxyError) -> Self {
        Self::OutboundTask {
            outbound: outbound.into(),
            source,
        }
    }
}

pub async fn run_with_shutdown<F>(config: &ProxyConfig, shutdown: F) -> Result<(), RuntimeError>
where
    F: Future<Output = std::result::Result<(), String>>,
{
    let state = build_runtime_state(config)?;
    let RuntimeState {
        inbounds,
        outbounds,
    } = state;

    info!(
        event = "runtime_start",
        inbounds = config.inbounds.len(),
        outbounds = config.outbounds.len(),
        final_outbound = %sanitize_field(config.route.final_outbound.as_str()),
        "runtime start"
    );

    start_outbounds(&outbounds).await?;
    start_inbounds(&inbounds).await?;

    tokio::pin!(shutdown);
    shutdown.await.map_err(RuntimeError::shutdown_wait)?;

    info!(
        event = "shutdown_begin",
        remaining_inbounds = inbounds.len(),
        remaining_outbounds = outbounds.len(),
        "shutdown begin"
    );

    close_inbounds(&inbounds).await?;
    close_outbounds(&outbounds).await?;

    info!(event = "shutdown_complete", "shutdown complete");
    Ok(())
}

async fn start_inbounds(
    inbounds: &[std::sync::Arc<dyn veex_core::Inbound>],
) -> Result<(), RuntimeError> {
    for inbound in inbounds {
        let inbound_tag = inbound.meta().tag.clone();
        let inbound_field = sanitize_field(&inbound_tag).into_owned();
        info!(
            event = "service_start",
            inbound = %inbound_field,
            "starting inbound service"
        );
        if let Err(err) = inbound.start().await {
            warn!(
                event = "inbound_service_failed",
                inbound = %inbound_field,
                error_kind = ?err.kind(),
                error = %err,
                "inbound service failed"
            );
            return Err(RuntimeError::task(inbound_tag, err));
        }
    }

    Ok(())
}

async fn start_outbounds(outbounds: &OutboundRegistry) -> Result<(), RuntimeError> {
    for outbound in outbounds.lifecycle_iter() {
        let outbound_tag = outbound.meta().tag.clone();
        let outbound_field = sanitize_field(&outbound_tag).into_owned();
        info!(
            event = "service_start",
            outbound = %outbound_field,
            "starting outbound service"
        );
        if let Err(err) = outbound.start().await {
            warn!(
                event = "outbound_service_failed",
                outbound = %outbound_field,
                error_kind = ?err.kind(),
                error = %err,
                "outbound service failed"
            );
            return Err(RuntimeError::outbound_task(outbound_tag, err));
        }
    }

    Ok(())
}

async fn close_inbounds(
    inbounds: &[std::sync::Arc<dyn veex_core::Inbound>],
) -> Result<(), RuntimeError> {
    for inbound in inbounds {
        let inbound_tag = inbound.meta().tag.clone();
        let inbound_field = sanitize_field(&inbound_tag).into_owned();
        if let Err(err) = inbound.close().await {
            warn!(
                event = "inbound_service_failed",
                inbound = %inbound_field,
                error_kind = ?err.kind(),
                error = %err,
                "inbound service failed during close"
            );
            return Err(RuntimeError::task(inbound_tag, err));
        }
    }

    Ok(())
}

async fn close_outbounds(outbounds: &OutboundRegistry) -> Result<(), RuntimeError> {
    for outbound in outbounds.lifecycle_iter() {
        let outbound_tag = outbound.meta().tag.clone();
        let outbound_field = sanitize_field(&outbound_tag).into_owned();
        if let Err(err) = outbound.close().await {
            error!(
                event = "outbound_service_failed",
                outbound = %outbound_field,
                error_kind = ?err.kind(),
                error = %err,
                "outbound service failed during close"
            );
            return Err(RuntimeError::outbound_task(outbound_tag, err));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
        sync::Arc,
        task::{Context, Poll},
        time::Instant,
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use veex_core::{
        BoxFuture, BoxedAsyncStream, Destination, ErrorKind, ExecutionOutbound, Host, Logger,
        Network, Outbound, OutboundMeta, OutboundRegistry, OutboundRegistryBuilder, ProxyError,
        SessionContext, SessionMeta,
    };

    use super::{close_outbounds, start_outbounds};

    struct ClosedStream;

    impl AsyncRead for ClosedStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ClosedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct TestDispatchOutbound {
        meta: OutboundMeta,
        logger: Logger,
        closed: AtomicBool,
    }

    impl TestDispatchOutbound {
        fn new(tag: impl Into<String>) -> Self {
            let tag = tag.into();
            Self {
                meta: OutboundMeta::new(tag.clone(), "test"),
                logger: Logger::new(tag, "test"),
                closed: AtomicBool::new(false),
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

        fn start(&self) -> BoxFuture<'_, ()> {
            self.closed.store(false, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }

        fn close(&self) -> BoxFuture<'_, ()> {
            self.closed.store(true, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    impl ExecutionOutbound for TestDispatchOutbound {
        fn open_stream(&self, _ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
            let closed = self.closed.load(Ordering::Relaxed);
            Box::pin(async move {
                if closed {
                    return Err(ProxyError::Shutdown);
                }

                Ok(Box::new(ClosedStream) as BoxedAsyncStream)
            })
        }
    }

    fn test_context() -> SessionContext {
        SessionContext::new(
            SessionMeta {
                id: 101,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: "127.0.0.1:30000".parse().expect("peer addr should parse"),
                destination: Destination::new(Host::Domain("example.com".into()), 443),
                start: Instant::now(),
            },
            Vec::new(),
        )
    }

    fn finalized_registry(outbound: Arc<dyn ExecutionOutbound>) -> OutboundRegistry {
        let mut builder = OutboundRegistryBuilder::default();
        builder
            .register(Arc::clone(&outbound))
            .expect("outbound should register");
        builder.finalize(outbound)
    }

    #[tokio::test]
    async fn runtime_close_outbounds_is_visible_to_dispatch_view() {
        let registry = finalized_registry(Arc::new(TestDispatchOutbound::new("direct")));

        close_outbounds(&registry)
            .await
            .expect("runtime close should succeed");

        let outbound = registry
            .get("direct")
            .expect("registry should return dispatch view");
        let err = match outbound.open_stream(&test_context()).await {
            Ok(_) => panic!("dispatch view should observe runtime close"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::Shutdown);
    }

    #[tokio::test]
    async fn runtime_start_outbounds_reopens_dispatch_view() {
        let registry = finalized_registry(Arc::new(TestDispatchOutbound::new("direct")));

        close_outbounds(&registry)
            .await
            .expect("runtime close should succeed");
        start_outbounds(&registry)
            .await
            .expect("runtime start should succeed");

        let outbound = registry
            .get("direct")
            .expect("registry should return dispatch view");
        outbound
            .open_stream(&test_context())
            .await
            .expect("dispatch view should reuse same runtime object after start");
    }

    #[tokio::test]
    async fn runtime_close_outbounds_is_idempotent() {
        let registry = finalized_registry(Arc::new(TestDispatchOutbound::new("direct")));

        close_outbounds(&registry)
            .await
            .expect("first runtime close should succeed");
        close_outbounds(&registry)
            .await
            .expect("second runtime close should succeed");
    }
}
