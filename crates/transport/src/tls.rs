use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use tracing::{info, warn};
use veex_core::{sanitize_field, BoxedAsyncStream, Host, ProxyError, Result};

use crate::tcp::ConnectTraceContext;
use crate::verifier::{
    build_client_config, validate_certificate_paths, CertificateVerifierOptions, VerifierError,
};

#[derive(Clone, Debug, Default)]
pub struct TlsClientOptions {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub disable_sni: bool,
    pub insecure: bool,
    pub certificate_path: Option<String>,
    pub ca_path: Option<String>,
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("disable_sni=true requires an explicit server_name or insecure=true")]
    DisableSniRequiresServerName,
    #[error("tls server_name is required when using an IP address with certificate verification")]
    MissingServerNameForIp,
    #[error("tls verifier configuration failed: {0}")]
    Verifier(#[from] VerifierError),
    #[error("invalid tls server_name `{server_name}`: {message}")]
    InvalidServerName {
        server_name: String,
        message: String,
    },
    #[error(
        "tls handshake failed for host={host} server_name={server_name} insecure={insecure} disable_sni={disable_sni}: {source}"
    )]
    Handshake {
        host: String,
        server_name: String,
        insecure: bool,
        disable_sni: bool,
        #[source]
        source: io::Error,
    },
}

impl From<TlsError> for ProxyError {
    fn from(value: TlsError) -> Self {
        match value {
            TlsError::DisableSniRequiresServerName
            | TlsError::MissingServerNameForIp
            | TlsError::InvalidServerName { .. } => ProxyError::config(value.to_string()),
            TlsError::Verifier(_) | TlsError::Handshake { .. } => {
                ProxyError::tls(value.to_string())
            }
        }
    }
}

impl TlsClientOptions {
    pub fn validate(&self) -> Result<()> {
        if self.disable_sni && !self.insecure && self.server_name.is_none() {
            return Err(TlsError::DisableSniRequiresServerName.into());
        }

        validate_certificate_paths(&CertificateVerifierOptions {
            insecure: self.insecure,
            certificate_path: self.certificate_path.clone(),
            ca_path: self.ca_path.clone(),
        })
        .map_err(TlsError::from)?;

        Ok(())
    }
}

pub fn server_name_for_tls(
    host: &Host,
    options: &TlsClientOptions,
) -> std::result::Result<String, TlsError> {
    if let Some(server_name) = &options.server_name {
        return Ok(server_name.clone());
    }

    match host {
        Host::Domain(domain) => Ok(domain.clone()),
        Host::Ip(ip) => {
            if options.insecure {
                Ok(ip.to_string())
            } else {
                Err(TlsError::MissingServerNameForIp)
            }
        }
    }
}

pub async fn connect_tls(
    stream: TcpStream,
    host: &Host,
    options: &TlsClientOptions,
    trace: Option<&ConnectTraceContext>,
) -> Result<BoxedAsyncStream> {
    if !options.enabled {
        return Ok(Box::new(stream));
    }

    options.validate()?;
    let server_name = server_name_for_tls(host, options).map_err(ProxyError::from)?;
    let mut config = build_client_config(&CertificateVerifierOptions {
        insecure: options.insecure,
        certificate_path: options.certificate_path.clone(),
        ca_path: options.ca_path.clone(),
    })
    .map_err(TlsError::from)
    .map_err(ProxyError::from)?;
    config.enable_sni = !options.disable_sni;

    let connector = TlsConnector::from(Arc::new(config));
    let tls_server_name = ServerName::try_from(server_name.clone()).map_err(|err| {
        ProxyError::from(TlsError::InvalidServerName {
            server_name: server_name.clone(),
            message: err.to_string(),
        })
    })?;
    let host_field = host.to_string();
    let host_field = sanitize_field(&host_field).into_owned();
    let server_name_field = sanitize_field(&server_name).into_owned();
    let tls_start = Instant::now();

    log_tls_handshake_start(trace, &host_field, &server_name_field, options);

    let stream = connector
        .connect(tls_server_name, stream)
        .await
        .map_err(|err| {
            log_tls_handshake_failed(
                trace,
                &host_field,
                &server_name_field,
                options,
                tls_start.elapsed(),
                &err,
            );
            ProxyError::from(TlsError::Handshake {
                host: host.to_string(),
                server_name: server_name.clone(),
                insecure: options.insecure,
                disable_sni: options.disable_sni,
                source: err,
            })
        })?;

    log_tls_handshake_success(trace, &host_field, &server_name_field, tls_start.elapsed());

    Ok(Box::new(TlsCloseNotifyTolerantStream::new(stream)))
}

fn log_tls_handshake_start(
    trace: Option<&ConnectTraceContext>,
    host_field: &str,
    server_name_field: &str,
    options: &TlsClientOptions,
) {
    match trace {
        Some(trace) => {
            info!(
                event = "tls_handshake_start",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                host = %host_field,
                server_name = %server_name_field,
                insecure = options.insecure,
                disable_sni = options.disable_sni,
                "tls handshake start"
            );
        }
        None => {
            info!(
                event = "tls_handshake_start",
                host = %host_field,
                server_name = %server_name_field,
                insecure = options.insecure,
                disable_sni = options.disable_sni,
                "tls handshake start"
            );
        }
    }
}

fn log_tls_handshake_success(
    trace: Option<&ConnectTraceContext>,
    host_field: &str,
    server_name_field: &str,
    elapsed: std::time::Duration,
) {
    match trace {
        Some(trace) => {
            info!(
                event = "tls_handshake_success",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                host = %host_field,
                server_name = %server_name_field,
                elapsed_ms = elapsed.as_millis() as u64,
                "tls handshake success"
            );
        }
        None => {
            info!(
                event = "tls_handshake_success",
                host = %host_field,
                server_name = %server_name_field,
                elapsed_ms = elapsed.as_millis() as u64,
                "tls handshake success"
            );
        }
    }
}

fn log_tls_handshake_failed(
    trace: Option<&ConnectTraceContext>,
    host_field: &str,
    server_name_field: &str,
    options: &TlsClientOptions,
    elapsed: std::time::Duration,
    err: &io::Error,
) {
    match trace {
        Some(trace) => {
            warn!(
                event = "tls_handshake_failed",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                host = %host_field,
                server_name = %server_name_field,
                insecure = options.insecure,
                disable_sni = options.disable_sni,
                elapsed_ms = elapsed.as_millis() as u64,
                error = %err,
                "tls handshake failed"
            );
        }
        None => {
            warn!(
                event = "tls_handshake_failed",
                host = %host_field,
                server_name = %server_name_field,
                insecure = options.insecure,
                disable_sni = options.disable_sni,
                elapsed_ms = elapsed.as_millis() as u64,
                error = %err,
                "tls handshake failed"
            );
        }
    }
}

fn is_ignorable_tls_close_notify_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::UnexpectedEof
        && err
            .to_string()
            .contains("peer closed connection without sending TLS close_notify")
}

struct TlsCloseNotifyTolerantStream<T> {
    inner: T,
}

impl<T> TlsCloseNotifyTolerantStream<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> AsyncRead for TlsCloseNotifyTolerantStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Err(err)) if is_ignorable_tls_close_notify_error(&err) => {
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T> AsyncWrite for TlsCloseNotifyTolerantStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs, io,
        net::IpAddr,
        path::PathBuf,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use rcgen::generate_simple_self_signed;
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_rustls::TlsAcceptor;
    use tracing::{
        field::{Field, Visit},
        Event, Subscriber,
    };
    use tracing_subscriber::{
        layer::Context as LayerContext, prelude::*, registry::LookupSpan, Layer,
    };
    use veex_core::Host;

    use super::{
        connect_tls, is_ignorable_tls_close_notify_error, server_name_for_tls, TlsClientOptions,
    };
    use crate::tcp::ConnectTraceContext;

    #[test]
    fn derives_server_name_from_domain() {
        let name = server_name_for_tls(
            &Host::Domain("example.com".into()),
            &TlsClientOptions::default(),
        )
        .expect("domain host should derive server name");

        assert_eq!(name, "example.com");
    }

    #[test]
    fn rejects_ip_without_explicit_server_name_when_verifying() {
        let err = server_name_for_tls(
            &Host::Ip(IpAddr::from([127, 0, 0, 1])),
            &TlsClientOptions::default(),
        )
        .expect_err("ip host without insecure mode should fail");

        assert!(err.to_string().contains("server_name"));
    }

    #[tokio::test]
    async fn connects_with_insecure_tls() {
        let server = spawn_tls_server("localhost").await;
        let stream = tokio::net::TcpStream::connect(server.addr)
            .await
            .expect("tcp connect should succeed");

        let mut stream = connect_tls(
            stream,
            &Host::Domain("localhost".into()),
            &TlsClientOptions {
                enabled: true,
                insecure: true,
                ..TlsClientOptions::default()
            },
            None,
        )
        .await
        .expect("insecure tls should connect");

        stream
            .write_all(b"ping")
            .await
            .expect("client write should succeed");

        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .await
            .expect("client read should succeed");
        assert_eq!(&response, b"pong");

        let mut eof_probe = [0u8; 1];
        let read = stream
            .read(&mut eof_probe)
            .await
            .expect("missing close_notify should be treated as eof");
        assert_eq!(read, 0);
    }

    #[tokio::test]
    async fn connects_with_ca_path() {
        let server = spawn_tls_server("localhost").await;
        let stream = tokio::net::TcpStream::connect(server.addr)
            .await
            .expect("tcp connect should succeed");

        let mut stream = connect_tls(
            stream,
            &Host::Domain("localhost".into()),
            &TlsClientOptions {
                enabled: true,
                ca_path: Some(server.certificate_path.to_string_lossy().into_owned()),
                ..TlsClientOptions::default()
            },
            None,
        )
        .await
        .expect("ca_path should trust the self-signed certificate");

        stream
            .write_all(b"ping")
            .await
            .expect("client write should succeed");

        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .await
            .expect("client read should succeed");
        assert_eq!(&response, b"pong");
    }

    #[tokio::test]
    async fn connects_with_certificate_path_pin() {
        let server = spawn_tls_server("localhost").await;
        let stream = tokio::net::TcpStream::connect(server.addr)
            .await
            .expect("tcp connect should succeed");

        let mut stream = connect_tls(
            stream,
            &Host::Domain("localhost".into()),
            &TlsClientOptions {
                enabled: true,
                certificate_path: Some(server.certificate_path.to_string_lossy().into_owned()),
                ..TlsClientOptions::default()
            },
            None,
        )
        .await
        .expect("certificate_path should pin the server certificate");

        stream
            .write_all(b"ping")
            .await
            .expect("client write should succeed");

        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .await
            .expect("client read should succeed");
        assert_eq!(&response, b"pong");
    }

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

    #[tokio::test]
    async fn tls_handshake_emits_start_and_success_with_trace_context() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let server = spawn_tls_server("localhost").await;
        let stream = TcpStream::connect(server.addr)
            .await
            .expect("tcp connect should succeed");

        let stream = connect_tls(
            stream,
            &Host::Domain("localhost".into()),
            &TlsClientOptions {
                enabled: true,
                insecure: true,
                server_name: Some("localhost".into()),
                ..TlsClientOptions::default()
            },
            Some(&ConnectTraceContext {
                session_id: 41,
                outbound: "proxy".into(),
            }),
        )
        .await
        .expect("tls handshake should succeed");
        drop(stream);

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tls_handshake_start",
            &[
                ("session_id", "41"),
                ("outbound", "proxy"),
                ("host", "localhost"),
                ("server_name", "localhost"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "tls_handshake_success",
            &[
                ("session_id", "41"),
                ("outbound", "proxy"),
                ("host", "localhost"),
                ("server_name", "localhost"),
                ("level", "INFO"),
            ],
        );
    }

    #[tokio::test]
    async fn tls_handshake_failed_event_includes_trace_context() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept should succeed");
            stream
                .write_all(b"not-tls")
                .await
                .expect("server write should succeed");
        });
        let stream = TcpStream::connect(addr)
            .await
            .expect("tcp connect should succeed");

        let err = match connect_tls(
            stream,
            &Host::Domain("localhost".into()),
            &TlsClientOptions {
                enabled: true,
                insecure: true,
                server_name: Some("localhost".into()),
                ..TlsClientOptions::default()
            },
            Some(&ConnectTraceContext {
                session_id: 42,
                outbound: "proxy".into(),
            }),
        )
        .await
        {
            Ok(_) => panic!("tls handshake should fail"),
            Err(err) => err,
        };
        server.await.expect("server task should join");

        assert_eq!(err.kind(), veex_core::ErrorKind::Tls);

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tls_handshake_start",
            &[
                ("session_id", "42"),
                ("outbound", "proxy"),
                ("host", "localhost"),
                ("server_name", "localhost"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "tls_handshake_failed",
            &[
                ("session_id", "42"),
                ("outbound", "proxy"),
                ("host", "localhost"),
                ("server_name", "localhost"),
                ("level", "WARN"),
            ],
        );
    }

    struct TestTlsServer {
        addr: std::net::SocketAddr,
        certificate_path: PathBuf,
    }

    impl Drop for TestTlsServer {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.certificate_path);
        }
    }

    async fn spawn_tls_server(server_name: &str) -> TestTlsServer {
        let certified = generate_simple_self_signed(vec![server_name.to_string()])
            .expect("certificate generation should succeed");
        let certificate = certified.cert.der().clone();
        let key = certified.key_pair.serialize_der();
        let certificate_path = write_temp_certificate(certificate.as_ref());

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

        tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("listener accept should succeed");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("tls accept should succeed");

            let mut request = [0u8; 4];
            stream
                .read_exact(&mut request)
                .await
                .expect("server read should succeed");
            assert_eq!(&request, b"ping");

            stream
                .write_all(b"pong")
                .await
                .expect("server write should succeed");
        });

        TestTlsServer {
            addr,
            certificate_path,
        }
    }

    fn write_temp_certificate(certificate_der: &[u8]) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("veex-transport-test-{nanos}.pem"));
        let pem = pem_encode_certificate(certificate_der);
        fs::write(&path, pem).expect("temporary certificate should be written");
        path
    }

    fn pem_encode_certificate(certificate_der: &[u8]) -> String {
        let mut encoded = String::new();
        encoded.push_str("-----BEGIN CERTIFICATE-----\n");

        for chunk in base64_encode(certificate_der).as_bytes().chunks(64) {
            encoded.push_str(std::str::from_utf8(chunk).expect("base64 must be valid utf-8"));
            encoded.push('\n');
        }

        encoded.push_str("-----END CERTIFICATE-----\n");
        encoded
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
        let mut index = 0;
        while index < bytes.len() {
            let b0 = bytes[index];
            let b1 = bytes.get(index + 1).copied();
            let b2 = bytes.get(index + 2).copied();

            output.push(TABLE[(b0 >> 2) as usize] as char);
            output.push(TABLE[(((b0 & 0x03) << 4) | (b1.unwrap_or(0) >> 4)) as usize] as char);

            match (b1, b2) {
                (Some(b1), Some(b2)) => {
                    output.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
                    output.push(TABLE[(b2 & 0x3f) as usize] as char);
                }
                (Some(b1), None) => {
                    output.push(TABLE[((b1 & 0x0f) << 2) as usize] as char);
                    output.push('=');
                }
                (None, _) => {
                    output.push('=');
                    output.push('=');
                }
            }

            index += 3;
        }

        output
    }

    #[test]
    fn only_ignores_rustls_close_notify_eof() {
        let ignored = io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify",
        );
        let preserved = io::Error::new(io::ErrorKind::UnexpectedEof, "connection reset by peer");

        assert!(is_ignorable_tls_close_notify_error(&ignored));
        assert!(!is_ignorable_tls_close_notify_error(&preserved));
    }
}
