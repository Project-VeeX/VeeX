use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::{
    net::{lookup_host, TcpStream},
    time::timeout,
};
use tracing::{debug, info, warn};
use veex_core::{sanitize_field, Host, ProxyError, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectTraceContext {
    pub session_id: u64,
    pub outbound: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpConnectOptions {
    pub timeout: Option<Duration>,
    pub trace: Option<ConnectTraceContext>,
}

pub async fn connect_host(host: &Host, port: u16, options: TcpConnectOptions) -> Result<TcpStream> {
    let addresses = resolve_host(host, port).await?;
    let host_field = host.to_string();
    let host_field = sanitize_field(&host_field).into_owned();

    connect_addresses(&host_field, port, addresses, &options).await
}

async fn connect_addresses(
    host_field: &str,
    port: u16,
    addresses: Vec<SocketAddr>,
    options: &TcpConnectOptions,
) -> Result<TcpStream> {
    let mut last_error = None;

    for (idx, address) in addresses.into_iter().enumerate() {
        let attempt_index = (idx + 1) as u64;
        log_tcp_connect_attempt(
            options.trace.as_ref(),
            host_field,
            port,
            address,
            attempt_index,
            options.timeout,
        );
        let start = Instant::now();

        match connect_socket(address, options.timeout).await {
            Ok(stream) => {
                log_tcp_connect_success(
                    options.trace.as_ref(),
                    host_field,
                    port,
                    address,
                    attempt_index,
                    start.elapsed(),
                );
                return Ok(stream);
            }
            Err(err) => {
                log_tcp_connect_failed(
                    options.trace.as_ref(),
                    host_field,
                    port,
                    address,
                    attempt_index,
                    start.elapsed(),
                    err.error_kind,
                    &err.error,
                );
                last_error = Some(err.error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        ProxyError::dial(format!("no reachable address for {host_field}:{port}"))
    }))
}

async fn resolve_host(host: &Host, port: u16) -> Result<Vec<SocketAddr>> {
    match host {
        Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
        Host::Domain(domain) => {
            let addresses = lookup_host((domain.as_str(), port)).await.map_err(|err| {
                ProxyError::resolve_ctx(format!("failed to resolve {domain}:{port}"), err)
            })?;
            let addresses: Vec<_> = addresses.collect();
            if addresses.is_empty() {
                return Err(ProxyError::resolve(format!(
                    "resolver returned no addresses for {domain}:{port}"
                )));
            }
            Ok(addresses)
        }
    }
}

async fn connect_socket(
    address: SocketAddr,
    timeout_duration: Option<Duration>,
) -> std::result::Result<TcpStream, TcpConnectError> {
    let connect_future = TcpStream::connect(address);

    match timeout_duration {
        Some(duration) => timeout(duration, connect_future)
            .await
            .map_err(|_| TcpConnectError {
                error: ProxyError::timeout(format!("tcp connect timeout to {address}")),
                error_kind: "timeout",
            })?
            .map_err(|err| TcpConnectError::from_io(address, err)),
        None => connect_future
            .await
            .map_err(|err| TcpConnectError::from_io(address, err)),
    }
}

#[derive(Debug)]
struct TcpConnectError {
    error: ProxyError,
    error_kind: &'static str,
}

impl TcpConnectError {
    fn from_io(address: SocketAddr, err: io::Error) -> Self {
        Self {
            error: ProxyError::dial_ctx(format!("tcp connect failed to {address}"), &err),
            error_kind: classify_tcp_connect_error_kind(err.kind()),
        }
    }
}

fn classify_tcp_connect_error_kind(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::TimedOut => "timeout",
        io::ErrorKind::ConnectionRefused => "refused",
        io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NotConnected => "unreachable",
        _ => "other",
    }
}

fn log_tcp_connect_attempt(
    trace: Option<&ConnectTraceContext>,
    host_field: &str,
    port: u16,
    address: SocketAddr,
    attempt_index: u64,
    timeout_duration: Option<Duration>,
) {
    match (trace, timeout_duration) {
        (Some(trace), Some(duration)) => {
            debug!(
                event = "tcp_connect_attempt",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                network = "tcp",
                host = %host_field,
                port,
                resolved_addr = %address,
                attempt_index,
                timeout_ms = duration.as_millis() as u64,
                "tcp connect attempt"
            );
        }
        (Some(trace), None) => {
            debug!(
                event = "tcp_connect_attempt",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                network = "tcp",
                host = %host_field,
                port,
                resolved_addr = %address,
                attempt_index,
                "tcp connect attempt"
            );
        }
        (None, Some(duration)) => {
            debug!(
                event = "tcp_connect_attempt",
                network = "tcp",
                host = %host_field,
                port,
                resolved_addr = %address,
                attempt_index,
                timeout_ms = duration.as_millis() as u64,
                "tcp connect attempt"
            );
        }
        (None, None) => {
            debug!(
                event = "tcp_connect_attempt",
                network = "tcp",
                host = %host_field,
                port,
                resolved_addr = %address,
                attempt_index,
                "tcp connect attempt"
            );
        }
    }
}

fn log_tcp_connect_success(
    trace: Option<&ConnectTraceContext>,
    host_field: &str,
    port: u16,
    address: SocketAddr,
    attempt_index: u64,
    elapsed: Duration,
) {
    match trace {
        Some(trace) => {
            info!(
                event = "tcp_connect_success",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                network = "tcp",
                host = %host_field,
                port,
                resolved_addr = %address,
                attempt_index,
                elapsed_ms = elapsed.as_millis() as u64,
                "tcp connect success"
            );
        }
        None => {
            info!(
                event = "tcp_connect_success",
                network = "tcp",
                host = %host_field,
                port,
                resolved_addr = %address,
                attempt_index,
                elapsed_ms = elapsed.as_millis() as u64,
                "tcp connect success"
            );
        }
    }
}

fn log_tcp_connect_failed(
    trace: Option<&ConnectTraceContext>,
    host_field: &str,
    port: u16,
    address: SocketAddr,
    attempt_index: u64,
    elapsed: Duration,
    error_kind: &'static str,
    err: &ProxyError,
) {
    match trace {
        Some(trace) => {
            warn!(
                event = "tcp_connect_failed",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                network = "tcp",
                host = %host_field,
                port,
                resolved_addr = %address,
                attempt_index,
                elapsed_ms = elapsed.as_millis() as u64,
                error_kind,
                error = %err,
                "tcp connect failed"
            );
        }
        None => {
            warn!(
                event = "tcp_connect_failed",
                network = "tcp",
                host = %host_field,
                port,
                resolved_addr = %address,
                attempt_index,
                elapsed_ms = elapsed.as_millis() as u64,
                error_kind,
                error = %err,
                "tcp connect failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::net::TcpListener;
    use tracing::{
        field::{Field, Visit},
        Event, Subscriber,
    };
    use tracing_subscriber::{
        layer::Context as LayerContext, prelude::*, registry::LookupSpan, Layer,
    };

    use super::{connect_addresses, connect_host, ConnectTraceContext, TcpConnectOptions};
    use veex_core::Host;

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
    async fn tcp_connect_success_emits_attempt_and_success_with_trace_context() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept should succeed");
        });

        let trace = ConnectTraceContext {
            session_id: 7,
            outbound: "proxy".into(),
        };
        let stream = connect_host(
            &Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            addr.port(),
            TcpConnectOptions {
                timeout: Some(Duration::from_secs(1)),
                trace: Some(trace),
            },
        )
        .await
        .expect("connect_host should connect");
        drop(stream);
        accept_task.await.expect("accept task should join");

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tcp_connect_attempt",
            &[
                ("session_id", "7"),
                ("outbound", "proxy"),
                ("network", "tcp"),
                ("attempt_index", "1"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "tcp_connect_success",
            &[
                ("session_id", "7"),
                ("outbound", "proxy"),
                ("network", "tcp"),
                ("attempt_index", "1"),
                ("level", "INFO"),
            ],
        );
    }

    #[tokio::test]
    async fn tcp_connect_failure_emits_failed_event_with_trace_context() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        drop(listener);

        let err = connect_host(
            &Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            addr.port(),
            TcpConnectOptions {
                timeout: Some(Duration::from_millis(200)),
                trace: Some(ConnectTraceContext {
                    session_id: 8,
                    outbound: "proxy".into(),
                }),
            },
        )
        .await
        .expect_err("connect_host should fail");

        assert!(err.to_string().contains("tcp connect failed"));

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tcp_connect_attempt",
            &[
                ("session_id", "8"),
                ("outbound", "proxy"),
                ("network", "tcp"),
                ("attempt_index", "1"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "8"),
                ("outbound", "proxy"),
                ("network", "tcp"),
                ("attempt_index", "1"),
                ("error_kind", "refused"),
                ("level", "WARN"),
            ],
        );
    }

    #[tokio::test]
    async fn tcp_connect_attempt_index_advances_across_multiple_addresses() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let first_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), addr.port());
        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept should succeed");
        });

        let stream = connect_addresses(
            "example.com",
            addr.port(),
            vec![first_addr, addr],
            &TcpConnectOptions {
                timeout: Some(Duration::from_secs(1)),
                trace: Some(ConnectTraceContext {
                    session_id: 9,
                    outbound: "proxy".into(),
                }),
            },
        )
        .await
        .expect("second address should connect");
        drop(stream);
        accept_task.await.expect("accept task should join");

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "9"),
                ("attempt_index", "1"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "tcp_connect_success",
            &[
                ("session_id", "9"),
                ("attempt_index", "2"),
                ("level", "INFO"),
            ],
        );
    }
}
