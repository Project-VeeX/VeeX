use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use tracing::{info, warn};
use veex_core::{
    ProxyError, Result,
    io::BoxedAsyncStream,
    logging::Logger,
    logging::sanitize_field,
    portal::{BoxFuture, Dialer, Outbound, OutboundMeta, ProxyOutbound},
    session::SessionContext,
    types::Destination,
};
use veex_execution::{ExecutionFuture, ExecutionOutbound};
use veex_protocol::{
    adapter::{StreamAdapter, StreamParams},
    trojan::{TrojanStreamAdapter, validate_trojan_key},
};
use veex_transport::{ConnectTraceContext, TlsClientOptions, connect_tls};

use super::error::validate_trojan_client;

type UpstreamAddr = Destination;

#[derive(Debug)]
struct TrojanOutboundState {
    closed: AtomicBool,
}

pub struct TrojanOutbound {
    meta: OutboundMeta,
    logger: Logger,
    dialer: Dialer,
    upstream_addr: UpstreamAddr,
    key: String,
    tls: TlsClientOptions,
    state: Arc<TrojanOutboundState>,
}

impl fmt::Debug for TrojanOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanOutbound")
            .field("meta", &self.meta)
            .field("logger", &self.logger)
            .field("dialer", &self.dialer)
            .field("upstream_addr", &self.upstream_addr)
            .field("key", &"<redacted>")
            .field("tls", &self.tls)
            .finish()
    }
}

impl TrojanOutbound {
    pub fn new(
        meta: OutboundMeta,
        logger: Logger,
        dialer: Dialer,
        upstream_addr: UpstreamAddr,
        key: impl Into<String>,
        tls: TlsClientOptions,
    ) -> Result<Self> {
        let key = key.into();
        let outbound = Self {
            meta,
            logger,
            dialer,
            upstream_addr,
            key,
            tls,
            state: Arc::new(TrojanOutboundState {
                closed: AtomicBool::new(false),
            }),
        };
        outbound.validate()?;
        Ok(outbound)
    }

    pub fn validate(&self) -> Result<()> {
        if self.meta.r#type.trim().is_empty() {
            return Err(ProxyError::config("trojan outbound type must not be empty"));
        }

        validate_trojan_key(&self.key)?;
        validate_trojan_client(&self.meta.tag, &self.upstream_addr, &self.tls)
    }

    fn is_closed(&self) -> bool {
        self.state.closed.load(Ordering::Relaxed)
    }
}

impl Outbound for TrojanOutbound {
    fn meta(&self) -> &OutboundMeta {
        &self.meta
    }

    fn logger(&self) -> &Logger {
        &self.logger
    }

    fn start(&self) -> BoxFuture<'_, ()> {
        self.state.closed.store(false, Ordering::Relaxed);
        Box::pin(async { Ok(()) })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        self.state.closed.store(true, Ordering::Relaxed);
        Box::pin(async { Ok(()) })
    }
}

impl ProxyOutbound for TrojanOutbound {
    fn connect_proxy_stream(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
        let destination = ctx.meta.destination.clone();
        let buffered_payload = ctx.state.buffered_payload.clone();
        let dialer = self.dialer.clone();
        let upstream_addr = self.upstream_addr.clone();
        let key = self.key.clone();
        let tls = self.tls.clone();
        let closed = self.is_closed();
        let tcp_trace = self.dialer.context(ctx, self.meta.tag.clone());
        let tls_trace = ConnectTraceContext {
            session_id: ctx.meta.id,
            outbound: self.meta.tag.clone(),
            routing_mark: self.dialer.routing_mark(),
        };
        let protocol_trace =
            ProtocolTraceContext::new(ctx.meta.id, self.meta.tag.clone(), destination.clone());

        Box::pin(async move {
            if closed {
                return Err(ProxyError::Shutdown);
            }
            validate_trojan_client(&tcp_trace.outbound_tag, &upstream_addr, &tls)?;

            // Trojan preserves transport-originated connect/tls errors and only
            // converts outbound framing failures at its own boundary.
            let tcp_stream = dialer
                .connect(&upstream_addr.host, upstream_addr.port, tcp_trace)
                .await?;
            let stream = connect_tls(
                tcp_stream,
                &upstream_addr.host,
                upstream_addr.port,
                &tls,
                Some(&tls_trace),
            )
            .await?;

            let adapter = TrojanStreamAdapter::new(key)?;
            log_protocol_handshake_start(&protocol_trace, buffered_payload.len());
            let protocol_start = Instant::now();
            match adapter
                .establish(stream, StreamParams::new(destination, buffered_payload))
                .await
            {
                Ok(stream) => {
                    log_protocol_handshake_success(&protocol_trace, protocol_start.elapsed());
                    Ok(stream)
                }
                Err(err) => {
                    log_protocol_handshake_failed(&protocol_trace, protocol_start.elapsed(), &err);
                    Err(err)
                }
            }
        })
    }
}

impl ExecutionOutbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.meta.tag
    }

    fn open_stream(&self, ctx: &SessionContext) -> ExecutionFuture<'_, BoxedAsyncStream> {
        ProxyOutbound::connect_proxy_stream(self, ctx)
    }
}

#[derive(Clone, Debug)]
struct ProtocolTraceContext {
    session_id: u64,
    outbound_field: String,
    destination_field: String,
}

impl ProtocolTraceContext {
    fn new(session_id: u64, outbound: String, destination: Destination) -> Self {
        Self {
            session_id,
            outbound_field: sanitize_field(&outbound).into_owned(),
            destination_field: sanitize_field(&destination.to_string()).into_owned(),
        }
    }
}

fn log_protocol_handshake_start(trace: &ProtocolTraceContext, buffered_payload_len: usize) {
    info!(
        event = "protocol_handshake_start",
        session_id = trace.session_id,
        outbound = %trace.outbound_field,
        protocol = %"trojan",
        protocol_stage = %"request_write",
        destination = %trace.destination_field,
        buffered_payload_bytes = buffered_payload_len as u64,
        "protocol handshake start"
    );
}

fn log_protocol_handshake_success(trace: &ProtocolTraceContext, elapsed: std::time::Duration) {
    info!(
        event = "protocol_handshake_success",
        session_id = trace.session_id,
        outbound = %trace.outbound_field,
        protocol = %"trojan",
        protocol_stage = %"request_write",
        destination = %trace.destination_field,
        elapsed_ms = elapsed.as_millis() as u64,
        "protocol handshake success"
    );
}

fn log_protocol_handshake_failed(
    trace: &ProtocolTraceContext,
    elapsed: std::time::Duration,
    err: &ProxyError,
) {
    warn!(
        event = "protocol_handshake_failed",
        session_id = trace.session_id,
        outbound = %trace.outbound_field,
        protocol = %"trojan",
        protocol_stage = %"request_write",
        destination = %trace.destination_field,
        elapsed_ms = elapsed.as_millis() as u64,
        error_kind = %err.kind(),
        error = %err,
        "protocol handshake failed"
    );
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::{Duration, Instant},
    };

    use rcgen::generate_simple_self_signed;
    use rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::{io::AsyncReadExt, net::TcpListener, time::sleep};
    use tokio_rustls::TlsAcceptor;
    use veex_core::{
        logging::Logger,
        portal::{Dial, OutboundMeta, ProxyOutbound},
        session::{SessionContext, SessionMeta},
        types::{Destination, Host, Network},
    };
    use veex_test_tracing::{
        CapturedEvent, assert_has_event, captured_events, install_test_subscriber,
    };
    use veex_transport::{HostResolveRequest, TlsClientOptions};

    use super::super::build_trojan_request;
    use super::super::dialer::build_dialer_with_connector;
    use super::TrojanOutbound;

    fn event_count(events: &[CapturedEvent], event_name: &str) -> usize {
        events
            .iter()
            .filter(|event| event.fields.get("event").map(String::as_str) == Some(event_name))
            .count()
    }

    #[tokio::test]
    async fn trojan_outbound_uses_transport_fallback_before_tls() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let server = spawn_tls_server("localhost").await;
        let bad_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), server.addr.port());
        let good_addr = server.addr;
        let dialer = build_dialer_with_connector(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_secs(1)),
                routing_mark: None,
                domain_resolver: None,
            },
            Arc::new(move |_request: HostResolveRequest| {
                Box::pin(async move { Ok(vec![bad_addr, good_addr]) })
            }),
            super::super::dialer::system_tcp_connector(),
        );
        let outbound = TrojanOutbound::new(
            OutboundMeta::new("proxy", "trojan"),
            Logger::new("proxy", "trojan"),
            dialer,
            Destination::new(Host::Domain("fallback.test".into()), server.addr.port()),
            "secret",
            TlsClientOptions {
                enabled: true,
                insecure: true,
                server_name: Some("localhost".into()),
                ..TlsClientOptions::default()
            },
        )
        .expect("trojan outbound should build");

        let destination = Destination::new(Host::Domain("example.com".into()), 443);
        let buffered_payload = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let expected = build_trojan_request("secret", &destination, &buffered_payload)
            .expect("request builder should succeed");
        let ctx = SessionContext::new(
            SessionMeta {
                id: 11,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000),
                destination,
                start: Instant::now(),
            },
            buffered_payload,
        );

        let stream = outbound
            .connect_proxy_stream(&ctx)
            .await
            .expect("trojan outbound should connect on the second address");
        drop(stream);

        let received = server
            .handle
            .await
            .expect("server task should finish successfully");
        assert_eq!(received, expected);

        let events = captured_events(&trace_buffer);
        assert_eq!(event_count(&events, "tcp_connect_attempt"), 2);
        assert_eq!(event_count(&events, "tcp_connect_failed"), 1);
        assert_eq!(event_count(&events, "tcp_connect_success"), 1);
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "11"),
                ("attempt_index", "1"),
                ("outbound", "proxy"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "tcp_connect_success",
            &[
                ("session_id", "11"),
                ("attempt_index", "2"),
                ("outbound", "proxy"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "tls_handshake_start",
            &[
                ("session_id", "11"),
                ("outbound", "proxy"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "tls_handshake_success",
            &[
                ("session_id", "11"),
                ("outbound", "proxy"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "protocol_handshake_start",
            &[
                ("session_id", "11"),
                ("outbound", "proxy"),
                ("protocol", "trojan"),
                ("protocol_stage", "request_write"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "protocol_handshake_success",
            &[
                ("session_id", "11"),
                ("outbound", "proxy"),
                ("protocol", "trojan"),
                ("protocol_stage", "request_write"),
                ("level", "INFO"),
            ],
        );
    }

    #[tokio::test]
    async fn trojan_outbound_returns_all_address_failure_before_tls() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 18443);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 18443);
        let dialer = build_dialer_with_connector(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_millis(200)),
                routing_mark: None,
                domain_resolver: None,
            },
            Arc::new(move |_request: HostResolveRequest| {
                Box::pin(async move { Ok(vec![first, second]) })
            }),
            super::super::dialer::system_tcp_connector(),
        );
        let outbound = TrojanOutbound::new(
            OutboundMeta::new("proxy", "trojan"),
            Logger::new("proxy", "trojan"),
            dialer,
            Destination::new(Host::Domain("fallback.test".into()), 18443),
            "secret",
            TlsClientOptions {
                enabled: true,
                insecure: true,
                server_name: Some("localhost".into()),
                ..TlsClientOptions::default()
            },
        )
        .expect("trojan outbound should build");

        let ctx = SessionContext::new(
            SessionMeta {
                id: 12,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40001),
                destination: Destination::new(Host::Domain("example.com".into()), 443),
                start: Instant::now(),
            },
            Vec::new(),
        );

        let err = match outbound.connect_proxy_stream(&ctx).await {
            Ok(_) => panic!("all addresses should fail"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), veex_core::ErrorKind::Dial);
        assert!(
            err.to_string()
                .contains("all 2 tcp connect attempts failed for fallback.test:18443")
        );
        assert!(err.to_string().contains(&second.to_string()));

        let events = captured_events(&trace_buffer);
        assert_eq!(event_count(&events, "tcp_connect_attempt"), 2);
        assert_eq!(event_count(&events, "tcp_connect_failed"), 2);
        assert_eq!(event_count(&events, "tcp_connect_success"), 0);
        assert_eq!(event_count(&events, "tls_handshake_start"), 0);
        assert_eq!(event_count(&events, "tls_handshake_success"), 0);
        assert_eq!(event_count(&events, "protocol_handshake_start"), 0);
        assert_eq!(event_count(&events, "protocol_handshake_success"), 0);
        assert_eq!(event_count(&events, "protocol_handshake_failed"), 0);
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "12"),
                ("attempt_index", "1"),
                ("outbound", "proxy"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "12"),
                ("attempt_index", "2"),
                ("outbound", "proxy"),
                ("level", "WARN"),
            ],
        );
    }

    #[tokio::test]
    async fn trojan_outbound_surfaces_tls_timeout_before_protocol_stage() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let server_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept should succeed");
            sleep(Duration::from_millis(200)).await;
        });
        let outbound = TrojanOutbound::new(
            OutboundMeta::new("proxy", "trojan"),
            Logger::new("proxy", "trojan"),
            build_dialer_with_connector(
                Dial {
                    detour: None,
                    connect_timeout: Some(Duration::from_secs(1)),
                    routing_mark: None,
                    domain_resolver: None,
                },
                super::super::dialer::system_host_resolver(),
                super::super::dialer::system_tcp_connector(),
            ),
            Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), addr.port()),
            "secret",
            TlsClientOptions {
                enabled: true,
                insecure: true,
                server_name: Some("localhost".into()),
                handshake_timeout: Duration::from_millis(50),
                ..TlsClientOptions::default()
            },
        )
        .expect("trojan outbound should build");
        let ctx = SessionContext::new(
            SessionMeta {
                id: 13,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40002),
                destination: Destination::new(Host::Domain("example.com".into()), 443),
                start: Instant::now(),
            },
            Vec::new(),
        );

        let err = match outbound.connect_proxy_stream(&ctx).await {
            Ok(_) => panic!("tls handshake should time out"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), veex_core::ErrorKind::Timeout);
        server_task.await.expect("server task should join");

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tcp_connect_success",
            &[
                ("session_id", "13"),
                ("outbound", "proxy"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "tls_handshake_failed",
            &[
                ("session_id", "13"),
                ("outbound", "proxy"),
                ("error_kind", "timeout"),
                ("failure_reason", "timeout"),
                ("handshake_timeout_ms", "50"),
                ("level", "WARN"),
            ],
        );
        assert_eq!(event_count(&events, "protocol_handshake_start"), 0);
        assert_eq!(event_count(&events, "protocol_handshake_success"), 0);
        assert_eq!(event_count(&events, "protocol_handshake_failed"), 0);
    }

    #[tokio::test]
    async fn trojan_protocol_failure_is_traced_separately_from_connect_and_tls() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let server = spawn_tls_accept_only_server("localhost").await;
        let outbound = TrojanOutbound::new(
            OutboundMeta::new("proxy", "trojan"),
            Logger::new("proxy", "trojan"),
            build_dialer_with_connector(
                Dial {
                    detour: None,
                    connect_timeout: Some(Duration::from_secs(1)),
                    routing_mark: None,
                    domain_resolver: None,
                },
                super::super::dialer::system_host_resolver(),
                super::super::dialer::system_tcp_connector(),
            ),
            Destination::new(
                Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                server.addr.port(),
            ),
            "secret",
            TlsClientOptions {
                enabled: true,
                insecure: true,
                server_name: Some("localhost".into()),
                ..TlsClientOptions::default()
            },
        )
        .expect("trojan outbound should build");
        let ctx = SessionContext::new(
            SessionMeta {
                id: 14,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40003),
                destination: Destination::new(Host::Domain("a".repeat(256)), 443),
                start: Instant::now(),
            },
            Vec::new(),
        );

        let err = match outbound.connect_proxy_stream(&ctx).await {
            Ok(_) => panic!("protocol request encoding should fail"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), veex_core::ErrorKind::Protocol);
        assert!(
            err.to_string()
                .contains("domain is too long for trojan request")
        );
        server.handle.await.expect("server task should join");

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tcp_connect_success",
            &[
                ("session_id", "14"),
                ("outbound", "proxy"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "tls_handshake_success",
            &[
                ("session_id", "14"),
                ("outbound", "proxy"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "protocol_handshake_start",
            &[
                ("session_id", "14"),
                ("outbound", "proxy"),
                ("protocol", "trojan"),
                ("protocol_stage", "request_write"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "protocol_handshake_failed",
            &[
                ("session_id", "14"),
                ("outbound", "proxy"),
                ("protocol", "trojan"),
                ("protocol_stage", "request_write"),
                ("error_kind", "protocol"),
                ("level", "WARN"),
            ],
        );
    }

    struct TestTlsServer {
        addr: SocketAddr,
        handle: tokio::task::JoinHandle<Vec<u8>>,
    }

    struct AcceptOnlyTlsServer {
        addr: SocketAddr,
        handle: tokio::task::JoinHandle<()>,
    }

    async fn spawn_tls_server(server_name: &str) -> TestTlsServer {
        let (listener, addr, acceptor) = tls_server_parts(server_name).await;

        let handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("listener accept should succeed");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("tls accept should succeed");

            let mut received = vec![0u8; expected_trojan_request_len()];
            stream
                .read_exact(&mut received)
                .await
                .expect("server read should succeed");
            received
        });

        TestTlsServer { addr, handle }
    }

    async fn spawn_tls_accept_only_server(server_name: &str) -> AcceptOnlyTlsServer {
        let (listener, addr, acceptor) = tls_server_parts(server_name).await;
        let handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("listener accept should succeed");
            let _stream = acceptor
                .accept(stream)
                .await
                .expect("tls accept should succeed");
        });

        AcceptOnlyTlsServer { addr, handle }
    }

    async fn tls_server_parts(server_name: &str) -> (TcpListener, SocketAddr, TlsAcceptor) {
        let certified = generate_simple_self_signed(vec![server_name.to_string()])
            .expect("certificate generation should succeed");
        let certificate = certified.cert.der().clone();
        let key = certified.key_pair.serialize_der();

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate.as_ref().to_vec())],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)),
            )
            .expect("server config should build");

        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener bind should succeed");
        let addr = listener.local_addr().expect("listener addr should exist");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        (listener, addr, acceptor)
    }

    fn expected_trojan_request_len() -> usize {
        build_trojan_request(
            "secret",
            &Destination::new(Host::Domain("example.com".into()), 443),
            b"GET / HTTP/1.1\r\n\r\n",
        )
        .expect("request builder should succeed")
        .len()
    }
}
