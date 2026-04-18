use std::time::Duration;

use tracing::{debug, info, warn};

use veex_core::{
    io::{BoxedAsyncStream, PacketCarrier, StreamCarrier},
    logging::sanitize_field,
    session::SessionContext,
};

use crate::{
    context::{PipelineRequest, RouteRuntimeContext},
    error::RouteError,
    evaluate::evaluate_current_state,
    result::{RouteResult, RouteRuleMissReason, RouteRuleTrace, RouteStep},
    rule::{RouteDecision, RouteFinalAction, RouteUpgradeAction},
    sniff::{sniff_stream_internal, SniffExecution, SniffResult},
    Router,
};

pub(crate) async fn route_stream(
    router: &Router,
    input: StreamCarrier,
    ctx: SessionContext,
) -> Result<RouteResult<StreamCarrier>, RouteError> {
    match run_pipeline(router, PipelineRequest::Stream(input), ctx).await? {
        PipelineOutput::Stream(routed) => Ok(routed),
        PipelineOutput::Packet(_) => unreachable!("stream route returned packet output"),
    }
}

pub(crate) async fn route_packet(
    router: &Router,
    input: PacketCarrier,
    ctx: SessionContext,
) -> Result<RouteResult<PacketCarrier>, RouteError> {
    match run_pipeline(router, PipelineRequest::Packet(input), ctx).await? {
        PipelineOutput::Packet(routed) => Ok(routed),
        PipelineOutput::Stream(_) => unreachable!("packet route returned stream output"),
    }
}

enum PipelineOutput {
    Stream(RouteResult<StreamCarrier>),
    Packet(RouteResult<PacketCarrier>),
}

async fn run_pipeline(
    router: &Router,
    mut request: PipelineRequest,
    ctx: SessionContext,
) -> Result<PipelineOutput, RouteError> {
    let inbound_tag = Some(ctx.meta.inbound_tag.as_str());
    let destination = &ctx.meta.destination;
    let mut route_context = RouteRuntimeContext::from_destination(destination);
    let mut next_index = 0;

    loop {
        let route_input = route_context.input(destination, inbound_tag);
        let domain_before = route_input.domain.map(str::to_string);

        match evaluate_current_state(router, route_input, next_index) {
            RouteStep::Miss {
                trace,
                reason,
                next_index: resume_at,
            } => {
                log_route_rule_eval(&ctx, trace, domain_before.as_deref());
                log_route_rule_miss(&ctx, trace, domain_before.as_deref(), reason);
                next_index = resume_at;
            }
            RouteStep::Upgrade {
                trace,
                action,
                next_index: resume_at,
            } => {
                log_route_rule_eval(&ctx, trace, domain_before.as_deref());
                log_route_rule_match(&ctx, trace, domain_before.as_deref());
                request = apply_upgrade(
                    &ctx,
                    request,
                    &mut route_context,
                    trace,
                    domain_before.as_deref(),
                    action,
                )
                .await?;
                next_index = resume_at;
            }
            RouteStep::Final { trace, decision } => {
                log_route_rule_eval(&ctx, trace, domain_before.as_deref());
                log_route_rule_match(&ctx, trace, domain_before.as_deref());
                log_route_final_selected(
                    &ctx,
                    trace,
                    domain_before.as_deref(),
                    &decision.final_action,
                );
                return Ok(finish_pipeline(request, ctx, decision));
            }
            RouteStep::DefaultFinal { decision } => {
                log_route_default_final_selected(
                    &ctx,
                    route_context.domain(),
                    &decision.final_action,
                );
                return Ok(finish_pipeline(request, ctx, decision));
            }
        }
    }
}

async fn apply_upgrade(
    ctx: &SessionContext,
    request: PipelineRequest,
    route_context: &mut RouteRuntimeContext,
    trace: RouteRuleTrace<'_>,
    domain_before: Option<&str>,
    action: &RouteUpgradeAction,
) -> Result<PipelineRequest, RouteError> {
    match (request, action) {
        (PipelineRequest::Stream(stream), RouteUpgradeAction::Sniff(action)) => {
            let domain_before_owned = route_context.domain().map(str::to_string);
            let mut stream = stream;
            log_sniff_start(ctx, action.timeout);
            let sniff = sniff_stream_internal(stream.stream, action.timeout).await;
            log_sniff_result(ctx, action.timeout, &sniff);
            route_context.apply_sniffed_domain(sniff.outcome.domain.clone());
            log_route_upgrade_applied(
                ctx,
                trace,
                domain_before_owned.as_deref(),
                route_context.domain(),
            );
            stream = StreamCarrier::new(Box::new(sniff.outcome.stream));
            Ok(PipelineRequest::Stream(stream))
        }
        (request @ PipelineRequest::Packet(_), RouteUpgradeAction::Sniff(_)) => {
            log_route_upgrade_skipped(ctx, trace, domain_before, "sniff_unsupported_for_packet");
            Ok(request)
        }
    }
}

fn finish_pipeline(
    request: PipelineRequest,
    ctx: SessionContext,
    decision: RouteDecision,
) -> PipelineOutput {
    match request {
        PipelineRequest::Stream(input) => PipelineOutput::Stream(RouteResult {
            ctx,
            decision,
            input,
        }),
        PipelineRequest::Packet(input) => PipelineOutput::Packet(RouteResult {
            ctx,
            decision,
            input,
        }),
    }
}

fn sanitize_optional_domain(domain: Option<&str>) -> String {
    domain
        .map(|value| sanitize_field(value).into_owned())
        .unwrap_or_else(|| "<none>".to_string())
}

fn log_route_rule_eval(
    ctx: &SessionContext,
    trace: RouteRuleTrace<'_>,
    domain_before: Option<&str>,
) {
    let matcher_summary = sanitize_field(trace.matcher_summary).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    debug!(
        event = "route_rule_eval",
        session_id = ctx.meta.id,
        rule_index = trace.rule_index as u64,
        action_kind = trace.action_kind,
        matcher_summary = %matcher_summary,
        domain_before = %domain_before,
        "route rule evaluated"
    );
}

fn log_route_rule_match(
    ctx: &SessionContext,
    trace: RouteRuleTrace<'_>,
    domain_before: Option<&str>,
) {
    let matcher_summary = sanitize_field(trace.matcher_summary).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    debug!(
        event = "route_rule_match",
        session_id = ctx.meta.id,
        rule_index = trace.rule_index as u64,
        action_kind = trace.action_kind,
        matcher_summary = %matcher_summary,
        domain_before = %domain_before,
        "route rule matched"
    );
}

fn log_route_rule_miss(
    ctx: &SessionContext,
    trace: RouteRuleTrace<'_>,
    domain_before: Option<&str>,
    reason: RouteRuleMissReason,
) {
    let matcher_summary = sanitize_field(trace.matcher_summary).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    debug!(
        event = "route_rule_miss",
        session_id = ctx.meta.id,
        rule_index = trace.rule_index as u64,
        action_kind = trace.action_kind,
        matcher_summary = %matcher_summary,
        miss_reason = reason.as_str(),
        domain_before = %domain_before,
        "route rule missed"
    );
}

fn log_route_upgrade_applied(
    ctx: &SessionContext,
    trace: RouteRuleTrace<'_>,
    domain_before: Option<&str>,
    domain_after: Option<&str>,
) {
    let matcher_summary = sanitize_field(trace.matcher_summary).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    let domain_after = sanitize_optional_domain(domain_after);
    debug!(
        event = "route_upgrade_applied",
        session_id = ctx.meta.id,
        rule_index = trace.rule_index as u64,
        action_kind = trace.action_kind,
        matcher_summary = %matcher_summary,
        domain_before = %domain_before,
        domain_after = %domain_after,
        "route upgrade applied"
    );
}

fn log_route_upgrade_skipped(
    ctx: &SessionContext,
    trace: RouteRuleTrace<'_>,
    domain_before: Option<&str>,
    reason: &str,
) {
    let matcher_summary = sanitize_field(trace.matcher_summary).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    debug!(
        event = "route_upgrade_skipped",
        session_id = ctx.meta.id,
        rule_index = trace.rule_index as u64,
        action_kind = trace.action_kind,
        matcher_summary = %matcher_summary,
        domain_before = %domain_before,
        reason = reason,
        "route upgrade skipped"
    );
}

fn log_route_final_selected(
    ctx: &SessionContext,
    trace: RouteRuleTrace<'_>,
    domain_before: Option<&str>,
    action: &RouteFinalAction,
) {
    let matcher_summary = sanitize_field(trace.matcher_summary).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    match action {
        RouteFinalAction::Route(target) => {
            let outbound = sanitize_field(&target.outbound_tag).into_owned();
            debug!(
                event = "route_final_selected",
                session_id = ctx.meta.id,
                rule_index = trace.rule_index as u64,
                action_kind = trace.action_kind,
                matcher_summary = %matcher_summary,
                domain_before = %domain_before,
                outbound = %outbound,
                "route final action selected"
            );
        }
        RouteFinalAction::HijackDns => {
            debug!(
                event = "route_final_selected",
                session_id = ctx.meta.id,
                rule_index = trace.rule_index as u64,
                action_kind = trace.action_kind,
                matcher_summary = %matcher_summary,
                domain_before = %domain_before,
                "route final action selected"
            );
        }
    }
}

fn log_route_default_final_selected(
    ctx: &SessionContext,
    domain_before: Option<&str>,
    action: &RouteFinalAction,
) {
    let domain_before = sanitize_optional_domain(domain_before);
    match action {
        RouteFinalAction::Route(target) => {
            let outbound = sanitize_field(&target.outbound_tag).into_owned();
            debug!(
                event = "route_default_final_selected",
                session_id = ctx.meta.id,
                action_kind = action.kind(),
                domain_before = %domain_before,
                outbound = %outbound,
                "route default final action selected"
            );
        }
        RouteFinalAction::HijackDns => {
            debug!(
                event = "route_default_final_selected",
                session_id = ctx.meta.id,
                action_kind = action.kind(),
                domain_before = %domain_before,
                "route default final action selected"
            );
        }
    }
}

fn log_sniff_start(ctx: &SessionContext, timeout: Duration) {
    let inbound_field = sanitize_field(ctx.meta.inbound_tag.as_str()).into_owned();
    info!(
        event = "sniff_start",
        session_id = ctx.meta.id,
        inbound_tag = %inbound_field,
        sniff_timeout_ms = timeout.as_millis() as u64,
        result = "start",
        "sniff started"
    );
}

fn log_sniff_result(
    ctx: &SessionContext,
    timeout: Duration,
    sniff: &SniffExecution<BoxedAsyncStream>,
) {
    let inbound_field = sanitize_field(ctx.meta.inbound_tag.as_str()).into_owned();
    let sniff_timeout_ms = timeout.as_millis() as u64;

    match &sniff.result {
        SniffResult::Matched { domain, protocol } => {
            let domain_field = sanitize_field(domain).into_owned();
            info!(
                event = "sniff_success",
                session_id = ctx.meta.id,
                inbound_tag = %inbound_field,
                sniff_timeout_ms,
                protocol = protocol.as_str(),
                domain = %domain_field,
                result = "matched",
                "sniff matched domain"
            );
        }
        SniffResult::Timeout => {
            info!(
                event = "sniff_timeout",
                session_id = ctx.meta.id,
                inbound_tag = %inbound_field,
                sniff_timeout_ms,
                result = "timeout",
                "sniff timed out"
            );
        }
        SniffResult::NotMatched => {
            info!(
                event = "sniff_no_match",
                session_id = ctx.meta.id,
                inbound_tag = %inbound_field,
                sniff_timeout_ms,
                result = "not_matched",
                "sniff did not match a supported domain"
            );
        }
        SniffResult::Unsupported => {
            if let Some(error) = &sniff.error {
                warn!(
                    event = "sniff_error",
                    session_id = ctx.meta.id,
                    inbound_tag = %inbound_field,
                    sniff_timeout_ms,
                    result = "error",
                    error = %error,
                    "sniff prefix read failed"
                );
            } else {
                info!(
                    event = "sniff_no_match",
                    session_id = ctx.meta.id,
                    inbound_tag = %inbound_field,
                    sniff_timeout_ms,
                    result = "unsupported",
                    "sniff prefix did not contain a supported protocol"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
        time::{Duration, Instant},
    };

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
    use veex_core::{
        io::StreamCarrier,
        session::{SessionContext, SessionMeta},
        types::{Destination, Network},
    };
    use veex_test_tracing::{assert_has_event, captured_events, install_test_subscriber};

    use crate::{RouteReason, RouteRule, Router};

    enum ReadStep {
        Data(Vec<u8>),
        Error(io::Error),
        Eof,
    }

    struct ScriptedStream {
        read_steps: VecDeque<ReadStep>,
    }

    impl ScriptedStream {
        fn new(read_steps: impl IntoIterator<Item = ReadStep>) -> Self {
            Self {
                read_steps: read_steps.into_iter().collect(),
            }
        }
    }

    impl AsyncRead for ScriptedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.read_steps.pop_front().unwrap_or(ReadStep::Eof) {
                ReadStep::Data(data) => {
                    buf.put_slice(&data);
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
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PendingStream;

    impl AsyncRead for PendingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn sniff_upgrade_injects_domain_and_replays_prefix() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                inbound: vec!["tproxy-in".into()],
                ..RouteRule::sniff(Duration::from_millis(300))
            },
            RouteRule {
                domain_suffix: vec!["google.com".into()],
                ..RouteRule::new("proxy")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 7,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );
        let payload = tls_client_hello_with_sni("www.google.com");

        let routed = router
            .route_stream(
                StreamCarrier::new(Box::new(ScriptedStream::new([
                    ReadStep::Data(payload.clone()),
                    ReadStep::Eof,
                ]))),
                ctx,
            )
            .await
            .expect("stream routing should succeed");

        assert_eq!(routed.decision.outbound_tag(), Some("proxy"));
        assert_eq!(routed.decision.reason, RouteReason::Rule);

        let mut replay = routed.input.stream;
        let mut replayed = Vec::new();
        replay
            .read_to_end(&mut replayed)
            .await
            .expect("prefixed stream should replay sniffed bytes");
        assert_eq!(replayed, payload);
    }

    #[tokio::test]
    async fn sniff_timeout_falls_through_to_later_rules() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                inbound: vec!["tproxy-in".into()],
                ..RouteRule::sniff(Duration::from_millis(10))
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("late")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 9,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(StreamCarrier::new(Box::new(PendingStream)), ctx)
            .await
            .expect("stream routing should succeed");
        assert_eq!(routed.decision.outbound_tag(), Some("late"));
        assert_eq!(routed.decision.reason, RouteReason::Rule);
    }

    #[tokio::test]
    async fn sniff_read_error_is_traced_without_failing_route() {
        let (_guard, events) = install_test_subscriber();
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                inbound: vec!["tproxy-in".into()],
                ..RouteRule::sniff(Duration::from_millis(300))
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("late")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 10,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(
                StreamCarrier::new(Box::new(ScriptedStream::new([ReadStep::Error(
                    io::Error::other("boom"),
                )]))),
                ctx,
            )
            .await
            .expect("stream routing should succeed");
        assert_eq!(routed.decision.outbound_tag(), Some("late"));

        let events = captured_events(&events);
        assert_has_event(
            &events,
            "sniff_error",
            &[
                ("session_id", "10"),
                ("inbound_tag", "tproxy-in"),
                ("result", "error"),
                ("level", "WARN"),
            ],
        );
    }

    #[tokio::test]
    async fn route_explainability_traces_rule_miss_and_final_selection() {
        let (_guard, events) = install_test_subscriber();
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                domain_suffix: vec!["google.com".into()],
                ..RouteRule::new("proxy")
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("late")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 13,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(StreamCarrier::new(Box::new(PendingStream)), ctx)
            .await
            .expect("stream routing should succeed");
        assert_eq!(routed.decision.outbound_tag(), Some("late"));

        let events = captured_events(&events);
        assert_has_event(
            &events,
            "route_rule_eval",
            &[
                ("session_id", "13"),
                ("rule_index", "0"),
                ("action_kind", "route"),
                ("matcher_summary", "domain_suffix"),
                ("domain_before", "<none>"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "route_rule_miss",
            &[
                ("session_id", "13"),
                ("rule_index", "0"),
                ("miss_reason", "domain_absent"),
                ("domain_before", "<none>"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "route_rule_match",
            &[
                ("session_id", "13"),
                ("rule_index", "1"),
                ("action_kind", "route"),
                ("matcher_summary", "port"),
                ("domain_before", "<none>"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "route_final_selected",
            &[
                ("session_id", "13"),
                ("rule_index", "1"),
                ("action_kind", "route"),
                ("outbound", "late"),
                ("level", "DEBUG"),
            ],
        );
    }

    #[tokio::test]
    async fn route_explainability_traces_sniff_upgrade_and_default_final() {
        let (_guard, events) = install_test_subscriber();
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            inbound: vec!["tproxy-in".into()],
            ..RouteRule::sniff(Duration::from_millis(300))
        });
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 14,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(
                StreamCarrier::new(Box::new(ScriptedStream::new([
                    ReadStep::Data(tls_client_hello_with_sni("www.google.com")),
                    ReadStep::Eof,
                ]))),
                ctx,
            )
            .await
            .expect("stream routing should succeed");
        assert_eq!(routed.decision.outbound_tag(), Some("final"));
        assert_eq!(routed.decision.reason, RouteReason::Final);

        let events = captured_events(&events);
        assert_has_event(
            &events,
            "route_rule_match",
            &[
                ("session_id", "14"),
                ("rule_index", "0"),
                ("action_kind", "sniff"),
                ("matcher_summary", "inbound"),
                ("domain_before", "<none>"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "route_upgrade_applied",
            &[
                ("session_id", "14"),
                ("rule_index", "0"),
                ("action_kind", "sniff"),
                ("domain_before", "<none>"),
                ("domain_after", "www.google.com"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "route_default_final_selected",
            &[
                ("session_id", "14"),
                ("action_kind", "route"),
                ("domain_before", "www.google.com"),
                ("outbound", "final"),
                ("level", "DEBUG"),
            ],
        );
    }

    fn tls_client_hello_with_sni(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let server_name_len = host_bytes.len();
        let server_name_list_len = 1 + 2 + server_name_len;
        let extension_len = 2 + server_name_list_len;
        let extensions_len = 4 + extension_len;
        let cipher_suites_len = 2;
        let handshake_body_len =
            2 + 32 + 1 + 0 + 2 + cipher_suites_len + 1 + 1 + 2 + extensions_len;
        let handshake_len = 4 + handshake_body_len;
        let record_len = handshake_len;

        let mut data = Vec::with_capacity(5 + record_len);
        data.extend_from_slice(&[0x16, 0x03, 0x01]);
        data.extend_from_slice(&(record_len as u16).to_be_bytes());
        data.push(0x01);
        data.push(((handshake_body_len >> 16) & 0xff) as u8);
        data.push(((handshake_body_len >> 8) & 0xff) as u8);
        data.push((handshake_body_len & 0xff) as u8);
        data.extend_from_slice(&[0x03, 0x03]);
        data.extend_from_slice(&[0u8; 32]);
        data.push(0);
        data.extend_from_slice(&(cipher_suites_len as u16).to_be_bytes());
        data.extend_from_slice(&[0x13, 0x01]);
        data.push(1);
        data.push(0);
        data.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&(extension_len as u16).to_be_bytes());
        data.extend_from_slice(&(server_name_list_len as u16).to_be_bytes());
        data.push(0);
        data.extend_from_slice(&(server_name_len as u16).to_be_bytes());
        data.extend_from_slice(host_bytes);
        data
    }
}
