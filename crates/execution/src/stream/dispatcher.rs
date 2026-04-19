use std::sync::Arc;

use tracing::{info, warn};
use veex_observability::{SessionSummary, emit_session_finish};

use veex_core::{
    dns::DnsExecutorHandle,
    io::{BoxedAsyncStream, StreamCarrier},
    logging::sanitize_field,
    session::SessionContext,
};
use veex_router::{RouteFinalAction, RouteReason, RouteResult};

use crate::{
    OutboundCatalog,
    traits::{DnsHijack, ExecutionFuture},
};

use super::{
    dns::hijack_stream_dns,
    relay::{RelayErrorWithStats, RelayStats, RelayTraceContext, relay_bidirectional_with_trace},
};

pub struct StreamDispatcher {
    outbounds: Arc<OutboundCatalog>,
    dns_executor: Option<Arc<dyn DnsExecutorHandle>>,
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

impl StreamDispatcher {
    pub fn new(outbounds: Arc<OutboundCatalog>) -> Self {
        Self::with_dns_executor(outbounds, None)
    }

    pub fn with_dns_executor(
        outbounds: Arc<OutboundCatalog>,
        dns_executor: Option<Arc<dyn DnsExecutorHandle>>,
    ) -> Self {
        Self {
            outbounds,
            dns_executor,
        }
    }

    pub(crate) async fn dispatch_routed(
        &self,
        routed: RouteResult<StreamCarrier>,
    ) -> veex_core::Result<()> {
        let RouteResult {
            mut ctx,
            decision,
            input: StreamCarrier {
                stream: inbound_stream,
            },
        } = routed;
        let outbound_tag = match &decision.final_action {
            RouteFinalAction::Route(target) => {
                ctx.set_route(target.outbound_tag.clone());
                target.outbound_tag.clone()
            }
            RouteFinalAction::HijackDns => {
                return self.hijack((inbound_stream, ctx), decision.reason).await;
            }
        };

        let trace = DispatchTraceContext::new(&ctx, outbound_tag.as_str(), decision.reason);

        // Stream dispatcher owns session-scoped lifecycle events. Lower-level transport,
        // outbound, and relay details stay in their respective modules.
        log_route_select(&trace, ctx.meta.network.as_str());
        let outbound = self.outbounds.require(&outbound_tag)?;

        let (summary, result) = match outbound.open_stream(&ctx).await {
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
                        {
                            log_relay_finish(&trace, &stats);
                            SessionSummary::success(
                                trace.session_id,
                                trace.inbound_field.as_str(),
                                trace.outbound_field.as_str(),
                                trace.peer_field.as_str(),
                                trace.destination_field.as_str(),
                                stats.bytes_up,
                                stats.bytes_down,
                                ctx.meta.start.elapsed(),
                            )
                        },
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

        emit_session_finish(&summary, trace.route_reason.as_str(), result.as_ref().err());
        result
    }
}

impl DnsHijack for StreamDispatcher {
    type Input = (BoxedAsyncStream, SessionContext);

    fn dns_executor(&self) -> Option<&Arc<dyn DnsExecutorHandle>> {
        self.dns_executor.as_ref()
    }

    fn hijack_with_executor(
        &self,
        executor: Arc<dyn DnsExecutorHandle>,
        (inbound_stream, ctx): Self::Input,
        route_reason: RouteReason,
    ) -> ExecutionFuture<'_, ()> {
        Box::pin(
            async move { hijack_stream_dns(&executor, inbound_stream, ctx, route_reason).await },
        )
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
        default_final = matches!(trace.route_reason, RouteReason::Final),
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

fn log_relay_failed(trace: &DispatchTraceContext, relay_err: &RelayErrorWithStats) {
    warn!(
        event = "relay_failed",
        session_id = trace.session_id,
        inbound = %trace.inbound_field,
        outbound = %trace.outbound_field,
        destination = %trace.destination_field,
        direction = relay_err.direction,
        failure_stage = relay_err.failure_stage,
        has_half_close = relay_err.has_half_close,
        bytes_up = relay_err.stats.bytes_up,
        bytes_down = relay_err.stats.bytes_down,
        error_kind = %relay_err.error.kind(),
        error = %relay_err.error,
        "relay failed"
    );
}

fn log_relay_finish(trace: &DispatchTraceContext, stats: &RelayStats) {
    info!(
        event = "relay_finish",
        session_id = trace.session_id,
        inbound = %trace.inbound_field,
        outbound = %trace.outbound_field,
        destination = %trace.destination_field,
        bytes_up = stats.bytes_up,
        bytes_down = stats.bytes_down,
        "relay finished"
    );
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::Instant,
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::StreamDispatcher;
    use veex_core::{
        ErrorKind,
        dns::{DnsExecutorHandle, DnsRequest, DnsResponse},
        io::{BoxedAsyncStream, StreamCarrier},
        logging::Logger,
        portal::{BoxFuture, Outbound, OutboundMeta, StreamOutbound},
        session::{SessionContext, SessionMeta, SessionRoute, SessionState},
        types::{Destination, Network},
    };
    use veex_router::{RouteDecision, RouteFinalAction, RouteReason, RouteResult};
    use veex_test_tracing::{assert_has_event, captured_events, install_test_subscriber};

    use crate::{ExecutionFuture, ExecutionOutbound, OutboundCatalog};

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
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl ScriptedStream {
        fn new(read_steps: impl IntoIterator<Item = ReadStep>) -> Self {
            Self::with_written_capture(read_steps).0
        }

        fn with_written_capture(
            read_steps: impl IntoIterator<Item = ReadStep>,
        ) -> (Self, Arc<Mutex<Vec<u8>>>) {
            let written = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    read_steps: read_steps.into_iter().collect(),
                    written: Arc::clone(&written),
                },
                written,
            )
        }
    }

    struct TestDnsExecutor {
        requests: Arc<Mutex<Vec<DnsRequest>>>,
        responses: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl DnsExecutorHandle for TestDnsExecutor {
        fn execute_query(&self, request: DnsRequest) -> BoxFuture<'_, DnsResponse> {
            let requests = Arc::clone(&self.requests);
            let responses = Arc::clone(&self.responses);
            Box::pin(async move {
                requests
                    .lock()
                    .expect("requests lock poisoned")
                    .push(request);
                let response = responses.lock().expect("responses lock poisoned").remove(0);
                Ok(DnsResponse::new(response))
            })
        }
    }

    fn dns_tcp_frame(payload: &[u8]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(payload.len() + 2);
        framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        framed.extend_from_slice(payload);
        framed
    }

    fn dns_tcp_read_steps(payload: &[u8]) -> [ReadStep; 4] {
        let frame = dns_tcp_frame(payload);
        [
            ReadStep::Data(Box::leak(vec![frame[0]].into_boxed_slice())),
            ReadStep::Data(Box::leak(vec![frame[1]].into_boxed_slice())),
            ReadStep::Data(Box::leak(frame[2..].to_vec().into_boxed_slice())),
            ReadStep::Eof,
        ]
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
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written
                .lock()
                .expect("written lock poisoned")
                .extend_from_slice(buf);
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
        meta: OutboundMeta,
        logger: Logger,
        captured: Arc<Mutex<Option<CapturedContext>>>,
    }

    impl CaptureOutbound {
        fn new(tag: impl Into<String>) -> (Self, Arc<Mutex<Option<CapturedContext>>>) {
            let captured = Arc::new(Mutex::new(None));
            (
                Self {
                    meta: OutboundMeta::new(tag.into(), "capture"),
                    logger: Logger::new("capture-out", "capture"),
                    captured: Arc::clone(&captured),
                },
                captured,
            )
        }
    }

    impl Outbound for CaptureOutbound {
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

    impl StreamOutbound for CaptureOutbound {
        fn connect_stream(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
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

    impl ExecutionOutbound for CaptureOutbound {
        fn tag(&self) -> &str {
            &self.meta.tag
        }

        fn open_stream(&self, ctx: &SessionContext) -> ExecutionFuture<'_, BoxedAsyncStream> {
            StreamOutbound::connect_stream(self, ctx)
        }
    }

    struct ScriptedOutbound {
        meta: OutboundMeta,
        logger: Logger,
        stream: Mutex<Option<BoxedAsyncStream>>,
    }

    impl ScriptedOutbound {
        fn new(tag: impl Into<String>, stream: BoxedAsyncStream) -> Self {
            let tag = tag.into();
            Self {
                meta: OutboundMeta::new(tag.clone(), "scripted"),
                logger: Logger::new(tag, "scripted"),
                stream: Mutex::new(Some(stream)),
            }
        }
    }

    impl Outbound for ScriptedOutbound {
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

    impl StreamOutbound for ScriptedOutbound {
        fn connect_stream(&self, _ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
            let stream = self
                .stream
                .lock()
                .expect("scripted stream lock poisoned")
                .take()
                .expect("scripted stream should only be taken once");

            Box::pin(async move { Ok(stream) })
        }
    }

    impl ExecutionOutbound for ScriptedOutbound {
        fn tag(&self) -> &str {
            &self.meta.tag
        }

        fn open_stream(&self, ctx: &SessionContext) -> ExecutionFuture<'_, BoxedAsyncStream> {
            StreamOutbound::connect_stream(self, ctx)
        }
    }

    fn finalized_catalog(outbound: Arc<dyn ExecutionOutbound>) -> Arc<OutboundCatalog> {
        let mut outbounds = HashMap::new();
        outbounds.insert(outbound.tag().to_string(), Arc::clone(&outbound));
        Arc::new(OutboundCatalog::new(outbounds, outbound))
    }

    fn empty_catalog() -> Arc<OutboundCatalog> {
        finalized_catalog(Arc::new(CaptureOutbound {
            meta: OutboundMeta::new("direct", "capture"),
            logger: Logger::new("direct", "capture"),
            captured: Arc::new(Mutex::new(None)),
        }) as Arc<dyn ExecutionOutbound>)
    }

    #[tokio::test]
    async fn dispatcher_writes_route_and_passes_state_to_outbound() {
        let (_guard, events) = install_test_subscriber();
        let (outbound, captured) = CaptureOutbound::new("proxy");
        let dispatcher = StreamDispatcher::new(finalized_catalog(Arc::new(outbound)));
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
            .dispatch_routed(RouteResult {
                ctx,
                decision: RouteDecision::route("proxy", RouteReason::Final),
                input: StreamCarrier::new(Box::new(ClosedStream)),
            })
            .await
            .expect("dispatch_routed should succeed");

        let captured = captured
            .lock()
            .expect("capture lock poisoned")
            .clone()
            .expect("outbound should receive session context");
        assert_eq!(captured.route.selected_outbound.as_deref(), Some("proxy"));
        assert_eq!(captured.state.buffered_payload, b"hello");

        let events = captured_events(&events);
        assert_has_event(
            &events,
            "relay_finish",
            &[
                ("session_id", "7"),
                ("outbound", "proxy"),
                ("bytes_up", "0"),
                ("bytes_down", "0"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "session_finish",
            &[("success", "true"), ("bytes_up", "0"), ("bytes_down", "0")],
        );
        assert!(
            !events
                .iter()
                .any(|event| event.fields.get("event").map(String::as_str) == Some("relay_failed")),
            "successful relay should not emit relay_failed: {events:?}"
        );
    }

    #[tokio::test]
    async fn dispatcher_preserves_partial_relay_stats_on_failure() {
        let (_guard, events) = install_test_subscriber();
        let dispatcher = StreamDispatcher::new(finalized_catalog(Arc::new(ScriptedOutbound::new(
            "proxy",
            Box::new(ScriptedStream::new([
                ReadStep::Data(b"pong"),
                ReadStep::Eof,
            ])),
        ))));
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
            .dispatch_routed(RouteResult {
                ctx,
                decision: RouteDecision::route("proxy", RouteReason::Final),
                input: StreamCarrier::new(Box::new(ScriptedStream::new([
                    ReadStep::Data(b"ping"),
                    ReadStep::Error(io::Error::other("boom")),
                ]))),
            })
            .await
            .expect_err("dispatch_routed should surface relay failure");

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
                ("direction", "upstream"),
                ("failure_stage", "read"),
                ("has_half_close", "true"),
                ("bytes_up", "4"),
                ("bytes_down", "4"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "relay_stats_finalized",
            &[
                ("session_id", "9"),
                ("success", "false"),
                ("has_half_close", "true"),
                ("bytes_up", "4"),
                ("bytes_down", "4"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "session_finish",
            &[("success", "false"), ("bytes_up", "4"), ("bytes_down", "4")],
        );
    }

    #[tokio::test]
    async fn dispatcher_hands_tcp_dns_to_executor_without_relay() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(vec![b"\x12\x34dns-response".to_vec()]));
        let dispatcher = StreamDispatcher::with_dns_executor(
            empty_catalog(),
            Some(Arc::new(TestDnsExecutor {
                requests: Arc::clone(&requests),
                responses,
            })),
        );
        let query = b"\x00\x01dns-query".to_vec();
        let (stream, written) = ScriptedStream::with_written_capture(dns_tcp_read_steps(&query));
        let ctx = SessionContext::new(
            SessionMeta {
                id: 42,
                network: Network::Tcp,
                inbound_tag: "dns-in".into(),
                peer: std::net::SocketAddr::from(([127, 0, 0, 1], 53053)),
                destination: Destination::from_ip(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    53,
                ),
                start: Instant::now(),
            },
            Vec::new(),
        );

        dispatcher
            .dispatch_routed(RouteResult {
                ctx,
                decision: RouteDecision {
                    final_action: RouteFinalAction::HijackDns,
                    reason: RouteReason::Rule,
                },
                input: StreamCarrier::new(Box::new(stream)),
            })
            .await
            .expect("tcp dns hijack should succeed");

        let captured_requests = requests.lock().expect("requests lock poisoned");
        assert_eq!(captured_requests.len(), 1);
        assert_eq!(captured_requests[0].protocol, Network::Tcp);
        assert_eq!(captured_requests[0].raw_message, query);
        drop(captured_requests);

        assert_eq!(
            written.lock().expect("written lock poisoned").as_slice(),
            dns_tcp_frame(b"\x12\x34dns-response").as_slice()
        );

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "stream_hijack_dns",
            &[("inbound", "dns-in"), ("level", "INFO")],
        );
        assert_has_event(
            &events,
            "stream_hijack_dns_complete",
            &[("inbound", "dns-in"), ("level", "INFO")],
        );
        assert!(
            !events
                .iter()
                .any(|event| event.fields.get("event").map(String::as_str) == Some("relay_start")),
            "tcp dns hijack should not enter relay: {events:?}"
        );
    }
}
