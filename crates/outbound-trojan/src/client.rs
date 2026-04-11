use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use tokio::io::AsyncWriteExt;
use veex_core::{
    BoxFuture, BoxedAsyncStream, DialContext, Dialer, Host, Logger, Outbound, OutboundMeta,
    ProxyError, ProxyOutbound, Result, SessionContext,
};
use veex_transport::{connect_tls, ConnectTraceContext, TlsClientOptions};

use crate::{
    dialer::parse_host,
    encode::build_trojan_request,
    error::{request_write_error, validate_trojan_client},
};

#[derive(Debug)]
struct TrojanOutboundState {
    closed: AtomicBool,
}

pub struct TrojanOutbound {
    meta: OutboundMeta,
    logger: Logger,
    dialer: Dialer,
    server: Host,
    server_port: u16,
    password: String,
    tls: TlsClientOptions,
    state: Arc<TrojanOutboundState>,
}

impl fmt::Debug for TrojanOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanOutbound")
            .field("meta", &self.meta)
            .field("logger", &self.logger)
            .field("dialer", &self.dialer)
            .field("server", &self.server)
            .field("server_port", &self.server_port)
            .field("tls", &self.tls)
            .finish()
    }
}

impl TrojanOutbound {
    pub fn new(
        meta: OutboundMeta,
        logger: Logger,
        dialer: Dialer,
        server: impl Into<String>,
        server_port: u16,
        password: impl Into<String>,
        tls: TlsClientOptions,
    ) -> Result<Self> {
        let outbound = Self {
            meta,
            logger,
            dialer,
            server: parse_host(&server.into()),
            server_port,
            password: password.into(),
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

        validate_trojan_client(&self.meta.tag, &self.password, self.server_port, &self.tls)
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
        let server = self.server.clone();
        let server_port = self.server_port;
        let password = self.password.clone();
        let tls = self.tls.clone();
        let closed = self.is_closed();
        let tcp_trace = DialContext {
            session_id: ctx.meta.id,
            outbound_tag: self.meta.tag.clone(),
        };
        let tls_trace = ConnectTraceContext {
            session_id: ctx.meta.id,
            outbound: self.meta.tag.clone(),
            routing_mark: self.dialer.dial().routing_mark,
        };

        Box::pin(async move {
            if closed {
                return Err(ProxyError::Shutdown);
            }
            validate_trojan_client(&tcp_trace.outbound_tag, &password, server_port, &tls)?;

            // Trojan preserves transport-originated connect/tls errors and only
            // converts outbound framing failures at its own boundary.
            let tcp_stream = dialer.connect(&server, server_port, tcp_trace).await?;
            let mut stream =
                connect_tls(tcp_stream, &server, server_port, &tls, Some(&tls_trace)).await?;
            let request = build_trojan_request(&password, &destination, &buffered_payload)?;
            stream
                .write_all(&request)
                .await
                .map_err(request_write_error)?;

            Ok(stream)
        })
    }
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
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    };
    use tokio::{io::AsyncReadExt, net::TcpListener};
    use tokio_rustls::TlsAcceptor;
    use veex_core::{
        Destination, Dial, Host, Logger, Network, OutboundMeta, ProxyOutbound, SessionContext,
        SessionMeta,
    };
    use veex_test_tracing::{
        assert_has_event, captured_events, install_test_subscriber, CapturedEvent,
    };
    use veex_transport::{connect_resolved_addresses, TlsClientOptions};

    use super::TrojanOutbound;
    use crate::dialer::build_dialer_with_connector;
    use crate::encode::build_trojan_request;

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
                timeout: Some(Duration::from_secs(1)),
                routing_mark: None,
            },
            Arc::new(move |_host, port, options| {
                Box::pin(async move {
                    connect_resolved_addresses(
                        "fallback.test",
                        port,
                        vec![bad_addr, good_addr],
                        options,
                    )
                    .await
                })
            }),
        );
        let outbound = TrojanOutbound::new(
            OutboundMeta::new("proxy", "trojan"),
            Logger::new("proxy", "trojan"),
            dialer,
            "fallback.test",
            server.addr.port(),
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
    }

    #[tokio::test]
    async fn trojan_outbound_returns_all_address_failure_before_tls() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 18443);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 18443);
        let dialer = build_dialer_with_connector(
            Dial {
                timeout: Some(Duration::from_millis(200)),
                routing_mark: None,
            },
            Arc::new(move |_host, port, options| {
                Box::pin(async move {
                    connect_resolved_addresses("fallback.test", port, vec![first, second], options)
                        .await
                })
            }),
        );
        let outbound = TrojanOutbound::new(
            OutboundMeta::new("proxy", "trojan"),
            Logger::new("proxy", "trojan"),
            dialer,
            "fallback.test",
            18443,
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
        assert!(err
            .to_string()
            .contains("all 2 tcp connect attempts failed for fallback.test:18443"));
        assert!(err.to_string().contains(&second.to_string()));

        let events = captured_events(&trace_buffer);
        assert_eq!(event_count(&events, "tcp_connect_attempt"), 2);
        assert_eq!(event_count(&events, "tcp_connect_failed"), 2);
        assert_eq!(event_count(&events, "tcp_connect_success"), 0);
        assert_eq!(event_count(&events, "tls_handshake_start"), 0);
        assert_eq!(event_count(&events, "tls_handshake_success"), 0);
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

    struct TestTlsServer {
        addr: SocketAddr,
        handle: tokio::task::JoinHandle<Vec<u8>>,
    }

    async fn spawn_tls_server(server_name: &str) -> TestTlsServer {
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
