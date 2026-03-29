use std::{collections::HashMap, sync::Arc};

use veex_observability::{emit_session_summary, log_line, LogLevel, SessionSummary};

use crate::{
    error::ProxyError,
    relay::relay_bidirectional,
    router::Router,
    traits::{BoxFuture, Dispatcher, Outbound},
    types::{BoxedAsyncStream, RouteReason, SessionContext},
};

pub struct SimpleDispatcher {
    router: Router,
    outbounds: HashMap<String, Arc<dyn Outbound>>,
}

impl SimpleDispatcher {
    pub fn new(router: Router, outbounds: HashMap<String, Arc<dyn Outbound>>) -> Self {
        Self { router, outbounds }
    }
}

impl Dispatcher for SimpleDispatcher {
    fn dispatch(&self, inbound_stream: BoxedAsyncStream, ctx: SessionContext) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut ctx = ctx;
            let decision = self.router.select(&ctx);
            ctx.set_route(decision.outbound_tag.clone(), decision.reason);

            let route_reason = ctx.route.reason.unwrap_or(RouteReason::Final);
            let outbound_tag = ctx
                .route
                .selected_outbound
                .clone()
                .unwrap_or_else(|| decision.outbound_tag.clone());

            if route_reason != RouteReason::Final {
                log_line(
                    LogLevel::Info,
                    &format!(
                        "event=route_select session_id={} inbound={} outbound={} reason={} dest={}",
                        ctx.meta.id,
                        ctx.meta.inbound_tag,
                        outbound_tag,
                        route_reason.as_str(),
                        ctx.meta.destination,
                    ),
                );
            }
            let outbound = self.outbounds.get(&outbound_tag).ok_or_else(|| {
                ProxyError::Config(format!("missing outbound tag: {outbound_tag}"))
            })?;

            let result: crate::Result<_> = async {
                let outbound_stream = outbound.connect(&ctx).await?;
                let stats = relay_bidirectional(inbound_stream, outbound_stream).await?;
                Ok(stats)
            }
            .await;

            let summary = match &result {
                Ok(stats) => SessionSummary::success(
                    ctx.meta.id,
                    ctx.meta.inbound_tag.as_str(),
                    outbound_tag.as_str(),
                    ctx.meta.peer.to_string(),
                    ctx.meta.destination.to_string(),
                    stats.bytes_up,
                    stats.bytes_down,
                    ctx.meta.start.elapsed(),
                ),
                Err(err) => SessionSummary::failure(
                    ctx.meta.id,
                    ctx.meta.inbound_tag.as_str(),
                    outbound_tag.as_str(),
                    ctx.meta.peer.to_string(),
                    ctx.meta.destination.to_string(),
                    0,
                    0,
                    ctx.meta.start.elapsed(),
                    err.kind(),
                ),
            };

            emit_session_summary(&summary);
            result.map(|_| ())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::Instant,
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::SimpleDispatcher;
    use crate::{
        traits::{Dispatcher, Outbound},
        BoxFuture, BoxedAsyncStream, Destination, Network, RouteReason, Router, SessionContext,
        SessionMeta, SessionRoute, SessionState,
    };

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

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CapturedContext {
        route: SessionRoute,
        state: SessionState,
    }

    struct CaptureOutbound {
        tag: String,
        captured: Arc<Mutex<Option<CapturedContext>>>,
    }

    impl CaptureOutbound {
        fn new(tag: impl Into<String>) -> (Self, Arc<Mutex<Option<CapturedContext>>>) {
            let captured = Arc::new(Mutex::new(None));
            (
                Self {
                    tag: tag.into(),
                    captured: Arc::clone(&captured),
                },
                captured,
            )
        }
    }

    impl Outbound for CaptureOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }

        fn connect(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
            let captured = Arc::clone(&self.captured);
            let route = ctx.route.clone();
            let state = ctx.state.clone();

            Box::pin(async move {
                *captured.lock().expect("capture lock poisoned") =
                    Some(CapturedContext { route, state });
                let stream: BoxedAsyncStream = Box::new(ClosedStream);
                Ok(stream)
            })
        }
    }

    #[tokio::test]
    async fn dispatcher_writes_route_and_passes_state_to_outbound() {
        let (outbound, captured) = CaptureOutbound::new("proxy");
        let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        outbounds.insert("proxy".into(), Arc::new(outbound));
        let dispatcher = SimpleDispatcher::new(Router::new("proxy", "direct"), outbounds);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 7,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: std::net::SocketAddr::from(([127, 0, 0, 1], 30000)),
                destination: Destination::from_domain("example.com", 443),
                start: Instant::now(),
            },
            b"hello".to_vec(),
        );

        dispatcher
            .dispatch(Box::new(ClosedStream), ctx)
            .await
            .expect("dispatch should succeed");

        let captured = captured
            .lock()
            .expect("capture lock poisoned")
            .clone()
            .expect("outbound should receive session context");
        assert_eq!(captured.route.selected_outbound.as_deref(), Some("proxy"));
        assert_eq!(captured.route.reason, Some(RouteReason::Final));
        assert_eq!(captured.state.buffered_payload, b"hello");
    }
}
