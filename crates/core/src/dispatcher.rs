use std::{collections::HashMap, sync::Arc};

use tracing::{info, warn};
use veex_observability::SessionSummary;

use crate::{
    error::ProxyError,
    logging::sanitize_field,
    relay::{relay_bidirectional_with_trace, RelayTraceContext},
    router::Router,
    traits::{BoxFuture, Dispatcher, Outbound},
    types::{BoxedAsyncStream, RouteReason, SessionContext},
};

pub struct SimpleDispatcher {
    router: Router,
    outbounds: HashMap<String, Arc<dyn Outbound>>,
}

#[derive(Clone, Debug)]
struct DispatchTraceContext {
    session_id: u64,
    inbound_field: String,
    outbound_field: String,
    peer_field: String,
    destination_field: String,
    route_reason: RouteReason,
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
            let execution = self.router.execute(inbound_stream, &mut ctx).await;
            let decision = execution.decision;
            ctx.set_route(decision.outbound_tag.clone(), decision.reason);

            let route_reason = ctx.route.reason.unwrap_or(RouteReason::Final);
            let outbound_tag = ctx
                .route
                .selected_outbound
                .clone()
                .unwrap_or_else(|| decision.outbound_tag.clone());
            let trace = DispatchTraceContext::new(&ctx, outbound_tag.as_str(), route_reason);
            let inbound_stream = execution.stream;

            // Dispatcher owns session-scoped lifecycle events. Lower-level transport,
            // outbound, and relay details stay in their respective modules.
            log_route_select(&trace, ctx.meta.network.as_str());
            let outbound = self.outbounds.get(&outbound_tag).ok_or_else(|| {
                ProxyError::config(format!("missing outbound tag: {outbound_tag}"))
            })?;

            let (summary, result) = match outbound.connect(&ctx).await {
                Ok(outbound_stream) => {
                    log_relay_start(&trace);
                    match relay_bidirectional_with_trace(
                        inbound_stream,
                        outbound_stream,
                        Some(RelayTraceContext {
                            session_id: ctx.meta.id,
                        }),
                    )
                    .await
                    {
                        Ok(stats) => (
                            SessionSummary::success(
                                trace.session_id,
                                trace.inbound_field.as_str(),
                                trace.outbound_field.as_str(),
                                trace.peer_field.as_str(),
                                trace.destination_field.as_str(),
                                stats.bytes_up,
                                stats.bytes_down,
                                ctx.meta.start.elapsed(),
                            ),
                            Ok(()),
                        ),
                        Err(relay_err) => {
                            log_relay_failed(&trace, &relay_err);
                            let error_kind = relay_err.error.kind();
                            (
                                SessionSummary::failure(
                                    trace.session_id,
                                    trace.inbound_field.as_str(),
                                    trace.outbound_field.as_str(),
                                    trace.peer_field.as_str(),
                                    trace.destination_field.as_str(),
                                    relay_err.stats.bytes_up,
                                    relay_err.stats.bytes_down,
                                    ctx.meta.start.elapsed(),
                                    error_kind,
                                ),
                                Err(relay_err.error),
                            )
                        }
                    }
                }
                Err(err) => {
                    let error_kind = err.kind();
                    (
                        SessionSummary::failure(
                            trace.session_id,
                            trace.inbound_field.as_str(),
                            trace.outbound_field.as_str(),
                            trace.peer_field.as_str(),
                            trace.destination_field.as_str(),
                            0,
                            0,
                            ctx.meta.start.elapsed(),
                            error_kind,
                        ),
                        Err(err),
                    )
                }
            };

            log_session_finish(&trace, &summary, result.as_ref().err());
            result
        })
    }
}

impl DispatchTraceContext {
    fn new(ctx: &SessionContext, outbound_tag: &str, route_reason: RouteReason) -> Self {
        let inbound_field = sanitize_field(ctx.meta.inbound_tag.as_str()).into_owned();
        let outbound_field = sanitize_field(outbound_tag).into_owned();
        let peer_field = sanitize_field(&ctx.meta.peer.to_string()).into_owned();
        let destination_field = sanitize_field(&ctx.meta.destination.to_string()).into_owned();

        Self {
            session_id: ctx.meta.id,
            inbound_field,
            outbound_field,
            peer_field,
            destination_field,
            route_reason,
        }
    }
}

fn log_route_select(trace: &DispatchTraceContext, network: &str) {
    info!(
        event = "route_select",
        session_id = trace.session_id,
        inbound = %trace.inbound_field,
        peer = %trace.peer_field,
        destination = %trace.destination_field,
        outbound = %trace.outbound_field,
        route_reason = %trace.route_reason.as_str(),
        network,
        "route selected"
    );
}

fn log_relay_start(trace: &DispatchTraceContext) {
    info!(
        event = "relay_start",
        session_id = trace.session_id,
        inbound = %trace.inbound_field,
        outbound = %trace.outbound_field,
        destination = %trace.destination_field,
        "relay started"
    );
}

fn log_relay_failed(trace: &DispatchTraceContext, relay_err: &crate::relay::RelayErrorWithStats) {
    warn!(
        event = "relay_failed",
        session_id = trace.session_id,
        inbound = %trace.inbound_field,
        outbound = %trace.outbound_field,
        destination = %trace.destination_field,
        direction = relay_err.direction,
        has_half_close = relay_err.has_half_close,
        bytes_up = relay_err.stats.bytes_up,
        bytes_down = relay_err.stats.bytes_down,
        error_kind = %relay_err.error.kind(),
        error = %relay_err.error,
        "relay failed"
    );
}

fn log_session_finish(
    trace: &DispatchTraceContext,
    summary: &SessionSummary,
    err: Option<&ProxyError>,
) {
    match err {
        Some(err) => {
            warn!(
                event = "session_finish",
                session_id = summary.session_id,
                inbound = %summary.inbound,
                peer = %summary.peer,
                destination = %summary.destination,
                outbound = %summary.outbound,
                route_reason = %trace.route_reason.as_str(),
                success = false,
                duration_ms = summary.duration.as_millis(),
                bytes_up = summary.bytes_up,
                bytes_down = summary.bytes_down,
                error_kind = %err.kind(),
                error = %err,
                "session finished with error"
            );
        }
        None => {
            info!(
                event = "session_finish",
                session_id = summary.session_id,
                inbound = %summary.inbound,
                peer = %summary.peer,
                destination = %summary.destination,
                outbound = %summary.outbound,
                route_reason = %trace.route_reason.as_str(),
                success = true,
                duration_ms = summary.duration.as_millis(),
                bytes_up = summary.bytes_up,
                bytes_down = summary.bytes_down,
                "session finished"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        collections::VecDeque,
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::Instant,
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::SimpleDispatcher;
    use crate::{
        test_support::{assert_has_event, captured_events, install_test_subscriber},
        traits::{Dispatcher, Outbound},
        BoxFuture, BoxedAsyncStream, Destination, ErrorKind, Network, RouteReason, Router,
        SessionContext, SessionMeta, SessionRoute, SessionState,
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

    enum ReadStep {
        Data(&'static [u8]),
        Error(io::Error),
        Eof,
    }

    struct ScriptedStream {
        read_steps: VecDeque<ReadStep>,
        written: Vec<u8>,
    }

    impl ScriptedStream {
        fn new(read_steps: impl IntoIterator<Item = ReadStep>) -> Self {
            Self {
                read_steps: read_steps.into_iter().collect(),
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for ScriptedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.read_steps.pop_front().unwrap_or(ReadStep::Eof) {
                ReadStep::Data(data) => {
                    buf.put_slice(data);
                    Poll::Ready(Ok(()))
                }
                ReadStep::Error(err) => {
                    Poll::Ready(Err(io::Error::new(err.kind(), err.to_string())))
                }
                ReadStep::Eof => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for ScriptedStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.extend_from_slice(buf);
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

    struct ScriptedOutbound {
        tag: String,
        stream: Mutex<Option<BoxedAsyncStream>>,
    }

    impl ScriptedOutbound {
        fn new(tag: impl Into<String>, stream: BoxedAsyncStream) -> Self {
            Self {
                tag: tag.into(),
                stream: Mutex::new(Some(stream)),
            }
        }
    }

    impl Outbound for ScriptedOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }

        fn connect(&self, _ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
            let stream = self
                .stream
                .lock()
                .expect("scripted stream lock poisoned")
                .take()
                .expect("scripted stream should only be taken once");

            Box::pin(async move { Ok(stream) })
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

    #[tokio::test]
    async fn dispatcher_preserves_partial_relay_stats_on_failure() {
        let (_guard, events) = install_test_subscriber();
        let outbound: Arc<dyn Outbound> = Arc::new(ScriptedOutbound::new(
            "proxy",
            Box::new(ScriptedStream::new([
                ReadStep::Data(b"pong"),
                ReadStep::Eof,
            ])),
        ));
        let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        outbounds.insert("proxy".into(), outbound);
        let dispatcher = SimpleDispatcher::new(Router::new("proxy", "direct"), outbounds);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 9,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: std::net::SocketAddr::from(([127, 0, 0, 1], 30000)),
                destination: Destination::from_domain("example.com", 443),
                start: Instant::now(),
            },
            Vec::new(),
        );

        let err = dispatcher
            .dispatch(
                Box::new(ScriptedStream::new([
                    ReadStep::Data(b"ping"),
                    ReadStep::Error(io::Error::other("boom")),
                ])),
                ctx,
            )
            .await
            .expect_err("dispatch should surface relay failure");

        assert_eq!(err.kind(), ErrorKind::Relay);

        let events = captured_events(&events);
        assert_has_event(
            &events,
            "relay_start",
            &[
                ("session_id", "9"),
                ("inbound", "socks-in"),
                ("outbound", "proxy"),
                ("destination", "example.com:443"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "relay_failed",
            &[
                ("session_id", "9"),
                ("outbound", "proxy"),
                ("direction", "upstream_read"),
                ("has_half_close", "true"),
                ("bytes_up", "4"),
                ("bytes_down", "4"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "session_finish",
            &[("success", "false"), ("bytes_up", "4"), ("bytes_down", "4")],
        );
    }
}
