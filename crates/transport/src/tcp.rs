use std::{
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    net::{lookup_host, TcpStream},
    time::timeout,
};
use tracing::{debug, info, warn};
use veex_core::{sanitize_field, Host, ProxyError, ResolveContext, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectTraceContext {
    pub session_id: u64,
    pub outbound: String,
    pub routing_mark: Option<u32>,
}

pub type TcpAttemptFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'static>>;
pub type TcpAttemptConnector = dyn Fn(SocketAddr) -> TcpAttemptFuture + Send + Sync;
pub type HostResolveFuture =
    Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>>> + Send + 'static>>;
pub type HostResolver = dyn Fn(HostResolveRequest) -> HostResolveFuture + Send + Sync;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostResolveRequest {
    pub host: Host,
    pub port: u16,
    pub context: ResolveContext,
}

#[derive(Clone, Default)]
pub struct TcpConnectOptions {
    pub timeout: Option<Duration>,
    pub trace: Option<ConnectTraceContext>,
    pub connector: Option<Arc<TcpAttemptConnector>>,
}

impl fmt::Debug for TcpConnectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpConnectOptions")
            .field("timeout", &self.timeout)
            .field("trace", &self.trace)
            .field("connector", &self.connector.as_ref().map(|_| "<custom>"))
            .finish()
    }
}

pub async fn connect_host(host: &Host, port: u16, options: TcpConnectOptions) -> Result<TcpStream> {
    let addresses = resolve_host(host, port).await?;
    connect_resolved_addresses(&host.to_string(), port, addresses, options).await
}

pub async fn connect_host_with_resolver(
    host: &Host,
    port: u16,
    context: ResolveContext,
    resolver: &HostResolver,
    options: TcpConnectOptions,
) -> Result<TcpStream> {
    let addresses = resolver(HostResolveRequest {
        host: host.clone(),
        port,
        context,
    })
    .await?;
    connect_resolved_addresses(&host.to_string(), port, addresses, options).await
}

pub async fn connect_resolved_addresses(
    host_field: &str,
    port: u16,
    addresses: Vec<SocketAddr>,
    options: TcpConnectOptions,
) -> Result<TcpStream> {
    let host_field = sanitize_field(host_field).into_owned();

    // Transport owns TCP connect events and keeps them scoped to host/port/socket details.
    connect_addresses(&host_field, port, addresses, &options).await
}

async fn connect_addresses(
    host_field: &str,
    port: u16,
    addresses: Vec<SocketAddr>,
    options: &TcpConnectOptions,
) -> Result<TcpStream> {
    let attempt_count = addresses.len();
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

        match connect_socket(address, options).await {
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
                    &TcpConnectFailureLog {
                        host_field,
                        port,
                        address,
                        attempt_index,
                        elapsed: start.elapsed(),
                        timeout_duration: options.timeout,
                        failure_reason: err.failure_reason,
                        err: &err.error,
                    },
                );
                last_error = Some(err.error);
            }
        }
    }

    Err(last_error
        .map(|error| finalize_tcp_connect_error(error, host_field, port, attempt_count))
        .unwrap_or_else(|| {
            ProxyError::dial(format!("no reachable address for {host_field}:{port}"))
        }))
}

pub async fn resolve_host(host: &Host, port: u16) -> Result<Vec<SocketAddr>> {
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
    options: &TcpConnectOptions,
) -> std::result::Result<TcpStream, TcpConnectError> {
    let connect_future = async {
        match &options.connector {
            Some(connector) => connector(address).await,
            None => TcpStream::connect(address).await,
        }
    };

    match options.timeout {
        Some(duration) => timeout(duration, connect_future)
            .await
            .map_err(|_| TcpConnectError {
                error: ProxyError::timeout(format!("tcp connect timeout to {address}")),
                failure_reason: "timeout",
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
    failure_reason: &'static str,
}

struct TcpConnectFailureLog<'a> {
    host_field: &'a str,
    port: u16,
    address: SocketAddr,
    attempt_index: u64,
    elapsed: Duration,
    timeout_duration: Option<Duration>,
    failure_reason: &'static str,
    err: &'a ProxyError,
}

impl TcpConnectError {
    fn from_io(address: SocketAddr, err: io::Error) -> Self {
        Self {
            error: ProxyError::dial_ctx(format!("tcp connect failed to {address}"), &err),
            failure_reason: classify_tcp_connect_failure_reason(err.kind()),
        }
    }
}

fn classify_tcp_connect_failure_reason(kind: io::ErrorKind) -> &'static str {
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

fn finalize_tcp_connect_error(
    last_error: ProxyError,
    host_field: &str,
    port: u16,
    attempt_count: usize,
) -> ProxyError {
    if attempt_count <= 1 {
        return last_error;
    }

    let context =
        format!("all {attempt_count} tcp connect attempts failed for {host_field}:{port}");
    match last_error {
        ProxyError::Dial(message) => ProxyError::dial(format!("{context}; last error: {message}")),
        ProxyError::Timeout(message) => {
            ProxyError::timeout(format!("{context}; last error: {message}"))
        }
        other => other,
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
            let routing_mark = trace
                .routing_mark
                .map(|mark| mark.to_string())
                .unwrap_or_default();
            debug!(
                event = "tcp_connect_attempt",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                routing_mark = %routing_mark,
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
            let routing_mark = trace
                .routing_mark
                .map(|mark| mark.to_string())
                .unwrap_or_default();
            debug!(
                event = "tcp_connect_attempt",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                routing_mark = %routing_mark,
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
            let routing_mark = trace
                .routing_mark
                .map(|mark| mark.to_string())
                .unwrap_or_default();
            info!(
                event = "tcp_connect_success",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                routing_mark = %routing_mark,
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

fn log_tcp_connect_failed(trace: Option<&ConnectTraceContext>, failure: &TcpConnectFailureLog<'_>) {
    match (trace, failure.timeout_duration) {
        (Some(trace), Some(duration)) => {
            let routing_mark = trace
                .routing_mark
                .map(|mark| mark.to_string())
                .unwrap_or_default();
            warn!(
                event = "tcp_connect_failed",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                routing_mark = %routing_mark,
                network = "tcp",
                host = %failure.host_field,
                port = failure.port,
                resolved_addr = %failure.address,
                attempt_index = failure.attempt_index,
                elapsed_ms = failure.elapsed.as_millis() as u64,
                timeout_ms = duration.as_millis() as u64,
                error_kind = %failure.err.kind(),
                failure_reason = failure.failure_reason,
                error = %failure.err,
                "tcp connect failed"
            );
        }
        (Some(trace), None) => {
            let routing_mark = trace
                .routing_mark
                .map(|mark| mark.to_string())
                .unwrap_or_default();
            warn!(
                event = "tcp_connect_failed",
                session_id = trace.session_id,
                outbound = %sanitize_field(&trace.outbound),
                routing_mark = %routing_mark,
                network = "tcp",
                host = %failure.host_field,
                port = failure.port,
                resolved_addr = %failure.address,
                attempt_index = failure.attempt_index,
                elapsed_ms = failure.elapsed.as_millis() as u64,
                error_kind = %failure.err.kind(),
                failure_reason = failure.failure_reason,
                error = %failure.err,
                "tcp connect failed"
            );
        }
        (None, Some(duration)) => {
            warn!(
                event = "tcp_connect_failed",
                network = "tcp",
                host = %failure.host_field,
                port = failure.port,
                resolved_addr = %failure.address,
                attempt_index = failure.attempt_index,
                elapsed_ms = failure.elapsed.as_millis() as u64,
                timeout_ms = duration.as_millis() as u64,
                error_kind = %failure.err.kind(),
                failure_reason = failure.failure_reason,
                error = %failure.err,
                "tcp connect failed"
            );
        }
        (None, None) => {
            warn!(
                event = "tcp_connect_failed",
                network = "tcp",
                host = %failure.host_field,
                port = failure.port,
                resolved_addr = %failure.address,
                attempt_index = failure.attempt_index,
                elapsed_ms = failure.elapsed.as_millis() as u64,
                error_kind = %failure.err.kind(),
                failure_reason = failure.failure_reason,
                error = %failure.err,
                "tcp connect failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use tokio::{
        net::{TcpListener, TcpStream},
        time::sleep,
    };

    use super::{
        connect_host, connect_resolved_addresses, ConnectTraceContext, TcpAttemptConnector,
        TcpConnectOptions,
    };
    use veex_core::Host;
    use veex_test_tracing::{
        assert_has_event, captured_events, install_test_subscriber, CapturedEvent,
    };

    fn event_count(events: &[CapturedEvent], event_name: &str) -> usize {
        events
            .iter()
            .filter(|event| event.fields.get("event").map(String::as_str) == Some(event_name))
            .count()
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
            routing_mark: None,
        };
        let stream = connect_host(
            &Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            addr.port(),
            TcpConnectOptions {
                timeout: Some(Duration::from_secs(1)),
                trace: Some(trace),
                connector: None,
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
                    routing_mark: None,
                }),
                connector: None,
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
                ("error_kind", "dial"),
                ("failure_reason", "refused"),
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
        let second_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), addr.port());
        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept should succeed");
        });

        let stream = connect_resolved_addresses(
            "example.com",
            addr.port(),
            vec![first_addr, second_addr, addr],
            TcpConnectOptions {
                timeout: Some(Duration::from_secs(1)),
                trace: Some(ConnectTraceContext {
                    session_id: 9,
                    outbound: "proxy".into(),
                    routing_mark: None,
                }),
                connector: None,
            },
        )
        .await
        .expect("third address should connect");
        drop(stream);
        accept_task.await.expect("accept task should join");

        let events = captured_events(&trace_buffer);
        assert_eq!(event_count(&events, "tcp_connect_attempt"), 3);
        assert_eq!(event_count(&events, "tcp_connect_failed"), 2);
        assert_eq!(event_count(&events, "tcp_connect_success"), 1);
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
            "tcp_connect_failed",
            &[
                ("session_id", "9"),
                ("attempt_index", "2"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "tcp_connect_success",
            &[
                ("session_id", "9"),
                ("attempt_index", "3"),
                ("level", "INFO"),
            ],
        );
    }

    #[tokio::test]
    async fn tcp_connect_all_failures_emit_each_attempt_and_preserve_last_error() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener should bind");
        let port = listener
            .local_addr()
            .expect("listener addr should exist")
            .port();
        drop(listener);

        let first_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port);
        let second_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), port);
        let err = connect_resolved_addresses(
            "fallback.example",
            port,
            vec![first_addr, second_addr],
            TcpConnectOptions {
                timeout: Some(Duration::from_millis(200)),
                trace: Some(ConnectTraceContext {
                    session_id: 10,
                    outbound: "proxy".into(),
                    routing_mark: None,
                }),
                connector: None,
            },
        )
        .await
        .expect_err("all addresses should fail");

        assert_eq!(err.kind(), veex_core::ErrorKind::Dial);
        assert!(err
            .to_string()
            .contains("all 2 tcp connect attempts failed for fallback.example"));
        assert!(err.to_string().contains(&second_addr.to_string()));

        let events = captured_events(&trace_buffer);
        assert_eq!(event_count(&events, "tcp_connect_attempt"), 2);
        assert_eq!(event_count(&events, "tcp_connect_failed"), 2);
        assert_eq!(event_count(&events, "tcp_connect_success"), 0);
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "10"),
                ("attempt_index", "1"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "10"),
                ("attempt_index", "2"),
                ("level", "WARN"),
            ],
        );
    }

    #[tokio::test]
    async fn tcp_connect_timeout_is_classified_and_traced() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let connector: Arc<TcpAttemptConnector> = Arc::new(|_address| {
            Box::pin(async move {
                sleep(Duration::from_millis(200)).await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "delayed connector should have timed out earlier",
                ))
            })
        });

        let err = connect_resolved_addresses(
            "timeout.example",
            443,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)],
            TcpConnectOptions {
                timeout: Some(Duration::from_millis(50)),
                trace: Some(ConnectTraceContext {
                    session_id: 13,
                    outbound: "proxy".into(),
                    routing_mark: None,
                }),
                connector: Some(connector),
            },
        )
        .await
        .expect_err("connect should time out");

        assert_eq!(err.kind(), veex_core::ErrorKind::Timeout);

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "13"),
                ("outbound", "proxy"),
                ("attempt_index", "1"),
                ("error_kind", "timeout"),
                ("failure_reason", "timeout"),
                ("timeout_ms", "50"),
                ("level", "WARN"),
            ],
        );
    }

    #[tokio::test]
    async fn tcp_connect_timeout_does_not_block_later_address_fallback() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener should bind");
        let reachable = listener.local_addr().expect("listener addr should exist");
        let delayed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), reachable.port());
        let connector: Arc<TcpAttemptConnector> = Arc::new(move |address| {
            Box::pin(async move {
                if address == delayed {
                    sleep(Duration::from_millis(200)).await;
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "delayed connector should have timed out earlier",
                    ))
                } else {
                    TcpStream::connect(address).await
                }
            })
        });
        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept should succeed");
        });

        let stream = connect_resolved_addresses(
            "fallback.example",
            reachable.port(),
            vec![delayed, reachable],
            TcpConnectOptions {
                timeout: Some(Duration::from_millis(50)),
                trace: Some(ConnectTraceContext {
                    session_id: 14,
                    outbound: "proxy".into(),
                    routing_mark: None,
                }),
                connector: Some(connector),
            },
        )
        .await
        .expect("second address should still connect");
        drop(stream);
        accept_task.await.expect("accept task should join");

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "14"),
                ("attempt_index", "1"),
                ("error_kind", "timeout"),
                ("failure_reason", "timeout"),
                ("timeout_ms", "50"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "tcp_connect_success",
            &[
                ("session_id", "14"),
                ("attempt_index", "2"),
                ("level", "INFO"),
            ],
        );
    }
}
