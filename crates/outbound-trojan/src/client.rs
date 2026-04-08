use std::{fmt, net::IpAddr, str::FromStr, sync::Arc, time::Duration};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use veex_core::{BoxFuture, BoxedAsyncStream, Host, Outbound, ProxyError, Result, SessionContext};
use veex_transport::{
    connect_host, connect_tls, ConnectTraceContext, TcpConnectOptions, TlsClientOptions,
};

use crate::request::build_trojan_request;

type TcpConnector =
    dyn Fn(Host, u16, TcpConnectOptions) -> BoxFuture<'static, TcpStream> + Send + Sync;

#[derive(Clone)]
pub struct TrojanOutbound {
    tag: String,
    server: Host,
    server_port: u16,
    password: String,
    tls: TlsClientOptions,
    connect_timeout: Duration,
    connector: Arc<TcpConnector>,
}

impl fmt::Debug for TrojanOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanOutbound")
            .field("tag", &self.tag)
            .field("server", &self.server)
            .field("server_port", &self.server_port)
            .field("tls", &self.tls)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl TrojanOutbound {
    pub fn new(
        tag: impl Into<String>,
        server: impl Into<String>,
        server_port: u16,
        password: impl Into<String>,
        connect_timeout: Duration,
        tls: TlsClientOptions,
    ) -> Self {
        let server = parse_host(&server.into());
        Self {
            tag: tag.into(),
            server,
            server_port,
            password: password.into(),
            tls,
            connect_timeout,
            connector: Arc::new(|host, port, options| {
                Box::pin(async move { connect_host(&host, port, options).await })
            }),
        }
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn server(&self) -> &Host {
        &self.server
    }

    pub fn server_port(&self) -> u16 {
        self.server_port
    }

    pub fn tls(&self) -> &TlsClientOptions {
        &self.tls
    }

    pub fn validate(&self) -> Result<()> {
        if self.tag.trim().is_empty() {
            return Err(ProxyError::Config(
                "trojan outbound tag must not be empty".into(),
            ));
        }
        if self.password.is_empty() {
            return Err(ProxyError::Config(
                "trojan outbound password must not be empty".into(),
            ));
        }
        if self.server_port == 0 {
            return Err(ProxyError::Config(
                "trojan outbound server_port must be within 1..=65535".into(),
            ));
        }
        self.tls.validate()?;
        Ok(())
    }
}

impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn connect(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
        let this = self.clone();
        let session_id = ctx.meta.id;
        let destination = ctx.meta.destination.clone();
        let buffered_payload = ctx.state.buffered_payload.clone();

        Box::pin(async move {
            this.validate()?;
            let trace = ConnectTraceContext {
                session_id,
                outbound: this.tag.clone(),
                routing_mark: None,
            };
            let connector = Arc::clone(&this.connector);

            let stream = connector(
                this.server.clone(),
                this.server_port,
                TcpConnectOptions {
                    timeout: Some(this.connect_timeout),
                    trace: Some(trace.clone()),
                    connector: None,
                },
            )
            .await?;

            // Trojan preserves transport-originated connect/tls errors and only
            // converts outbound framing failures at its own boundary.
            let mut stream = connect_tls(
                stream,
                &this.server,
                this.server_port,
                &this.tls,
                Some(&trace),
            )
            .await?;
            let request = build_trojan_request(&this.password, &destination, &buffered_payload)?;
            stream
                .write_all(&request)
                .await
                .map_err(|err| ProxyError::protocol_ctx("failed to write trojan request", err))?;

            Ok(stream)
        })
    }
}

fn parse_host(value: &str) -> Host {
    match IpAddr::from_str(value) {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use rcgen::generate_simple_self_signed;
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    };
    use tokio::{io::AsyncReadExt, net::TcpListener};
    use tokio_rustls::TlsAcceptor;
    use tracing::{
        field::{Field, Visit},
        Event, Subscriber,
    };
    use tracing_subscriber::{
        layer::Context as LayerContext, prelude::*, registry::LookupSpan, Layer,
    };
    use veex_core::{Destination, Host, Network, Outbound, SessionContext, SessionMeta};
    use veex_transport::{connect_resolved_addresses, TlsClientOptions};

    use super::TrojanOutbound;
    use crate::request::build_trojan_request;

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct CapturedEvent {
        fields: BTreeMap<String, String>,
    }

    #[derive(Default)]
    struct EventVisitor {
        fields: BTreeMap<String, String>,
    }

    impl Visit for EventVisitor {
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    #[derive(Clone)]
    struct CaptureLayer {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
            let mut visitor = EventVisitor::default();
            event.record(&mut visitor);
            visitor
                .fields
                .insert("level".to_string(), event.metadata().level().to_string());
            self.events
                .lock()
                .expect("captured events lock poisoned")
                .push(CapturedEvent {
                    fields: visitor.fields,
                });
        }
    }

    fn install_test_subscriber() -> (
        tracing::subscriber::DefaultGuard,
        Arc<Mutex<Vec<CapturedEvent>>>,
    ) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer {
            events: Arc::clone(&events),
        });

        (tracing::subscriber::set_default(subscriber), events)
    }

    fn captured_events(buffer: &Arc<Mutex<Vec<CapturedEvent>>>) -> Vec<CapturedEvent> {
        buffer
            .lock()
            .expect("captured events lock poisoned")
            .clone()
    }

    fn assert_has_event(
        events: &[CapturedEvent],
        event_name: &str,
        expected_fields: &[(&str, &str)],
    ) {
        let matched = events.iter().any(|event| {
            event.fields.get("event").map(String::as_str) == Some(event_name)
                && expected_fields.iter().all(|(key, expected)| {
                    event.fields.get(*key).map(String::as_str) == Some(*expected)
                })
        });

        assert!(
            matched,
            "expected event `{event_name}` with fields {:?}, captured events: {:?}",
            expected_fields, events
        );
    }

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
        let outbound = TrojanOutbound {
            tag: "proxy".into(),
            server: Host::Domain("fallback.test".into()),
            server_port: server.addr.port(),
            password: "secret".into(),
            tls: TlsClientOptions {
                enabled: true,
                insecure: true,
                server_name: Some("localhost".into()),
                ..TlsClientOptions::default()
            },
            connect_timeout: Duration::from_secs(1),
            connector: Arc::new(move |_host, port, options| {
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
        };

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
            .connect(&ctx)
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
        let outbound = TrojanOutbound {
            tag: "proxy".into(),
            server: Host::Domain("fallback.test".into()),
            server_port: 18443,
            password: "secret".into(),
            tls: TlsClientOptions {
                enabled: true,
                insecure: true,
                server_name: Some("localhost".into()),
                ..TlsClientOptions::default()
            },
            connect_timeout: Duration::from_millis(200),
            connector: Arc::new(move |_host, port, options| {
                Box::pin(async move {
                    connect_resolved_addresses("fallback.test", port, vec![first, second], options)
                        .await
                })
            }),
        };

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

        let err = match outbound.connect(&ctx).await {
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
