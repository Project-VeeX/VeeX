//! Direct outbound implementation kept outside `veex-core` so platform-specific
//! egress behavior can evolve without polluting core runtime abstractions.

use std::{
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::{lookup_host, TcpStream},
    time::timeout,
};
use tracing::{info, warn};
use veex_core::{
    error::{ProxyError, Result},
    sanitize_field,
    traits::{BoxFuture, Outbound},
    types::{BoxedAsyncStream, Host, SessionContext},
};

type MarkedConnector = dyn Fn(SocketAddr, u32) -> BoxFuture<'static, TcpStream> + Send + Sync;

#[derive(Clone)]
pub struct DirectOutbound {
    tag: String,
    connect_timeout: Option<Duration>,
    routing_mark: Option<u32>,
    marked_connector: Arc<MarkedConnector>,
}

impl fmt::Debug for DirectOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectOutbound")
            .field("tag", &self.tag)
            .field("connect_timeout", &self.connect_timeout)
            .field("routing_mark", &self.routing_mark)
            .finish()
    }
}

impl DirectOutbound {
    pub fn new(tag: impl Into<String>, routing_mark: Option<u32>) -> Result<Self> {
        if routing_mark.is_some() && !cfg!(target_os = "linux") {
            return Err(ProxyError::Config(
                "direct outbound routing_mark is only supported on linux".into(),
            ));
        }

        Ok(Self {
            tag: tag.into(),
            connect_timeout: Some(Duration::from_secs(10)),
            routing_mark,
            marked_connector: Arc::new(|address, routing_mark| {
                Box::pin(connect_marked_socket(address, routing_mark))
            }),
        })
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn set_connect_timeout(&mut self, timeout: Option<Duration>) {
        self.connect_timeout = timeout;
    }
}

impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn connect(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
        // Direct outbound owns destination-level dialing details such as SO_MARK,
        // so it keeps its own outbound-scoped connect tracing here.
        let destination = ctx.meta.destination.clone();
        let destination_field = sanitize_field(&destination.to_string()).into_owned();
        let outbound_field = sanitize_field(self.tag()).into_owned();
        let session_id = ctx.meta.id;
        let timeout_duration = self.connect_timeout;
        let routing_mark = self.routing_mark;
        let marked_connector = Arc::clone(&self.marked_connector);

        Box::pin(async move {
            let addresses = resolve_destination(&destination.host, destination.port).await?;
            let stream = connect_addresses(
                session_id,
                &outbound_field,
                &destination_field,
                addresses,
                timeout_duration,
                routing_mark,
                marked_connector,
            )
            .await?;
            Ok(Box::new(stream) as BoxedAsyncStream)
        })
    }
}

async fn connect_addresses(
    session_id: u64,
    outbound_field: &str,
    destination_field: &str,
    addresses: Vec<SocketAddr>,
    timeout_duration: Option<Duration>,
    routing_mark: Option<u32>,
    marked_connector: Arc<MarkedConnector>,
) -> Result<TcpStream> {
    let attempt_count = addresses.len();
    let mut last_error = None;

    for (idx, address) in addresses.into_iter().enumerate() {
        let attempt_index = (idx + 1) as u64;
        let start = Instant::now();
        log_direct_connect_attempt(
            session_id,
            outbound_field,
            destination_field,
            address,
            attempt_index,
            routing_mark,
        );

        match connect_socket(
            address,
            timeout_duration,
            routing_mark,
            Arc::clone(&marked_connector),
        )
        .await
        {
            Ok(stream) => {
                log_direct_connect_success(
                    session_id,
                    outbound_field,
                    destination_field,
                    address,
                    attempt_index,
                    routing_mark,
                    start.elapsed().as_millis() as u64,
                );
                return Ok(stream);
            }
            Err(err) => {
                log_direct_connect_failed(
                    session_id,
                    outbound_field,
                    destination_field,
                    address,
                    attempt_index,
                    routing_mark,
                    start.elapsed().as_millis() as u64,
                    &err,
                );
                last_error = Some(err);
            }
        }
    }

    Err(last_error
        .map(|error| finalize_direct_connect_error(error, destination_field, attempt_count))
        .unwrap_or_else(|| {
            ProxyError::Dial(format!(
                "direct outbound found no reachable address for {destination_field}"
            ))
        }))
}

fn log_direct_connect_attempt(
    session_id: u64,
    outbound_field: &str,
    destination_field: &str,
    address: SocketAddr,
    attempt_index: u64,
    routing_mark: Option<u32>,
) {
    match routing_mark {
        Some(mark) => {
            info!(
                event = "direct_connect_attempt",
                session_id,
                outbound = %outbound_field,
                destination = %destination_field,
                resolved_addr = %address,
                attempt_index,
                routing_mark = mark,
                "direct connect attempt"
            );
        }
        None => {
            info!(
                event = "direct_connect_attempt",
                session_id,
                outbound = %outbound_field,
                destination = %destination_field,
                resolved_addr = %address,
                attempt_index,
                routing_mark = "",
                "direct connect attempt"
            );
        }
    }
}

fn log_direct_connect_success(
    session_id: u64,
    outbound_field: &str,
    destination_field: &str,
    address: SocketAddr,
    attempt_index: u64,
    routing_mark: Option<u32>,
    elapsed_ms: u64,
) {
    match routing_mark {
        Some(mark) => {
            info!(
                event = "direct_connect_success",
                session_id,
                outbound = %outbound_field,
                destination = %destination_field,
                resolved_addr = %address,
                attempt_index,
                routing_mark = mark,
                elapsed_ms,
                "direct connect success"
            );
        }
        None => {
            info!(
                event = "direct_connect_success",
                session_id,
                outbound = %outbound_field,
                destination = %destination_field,
                resolved_addr = %address,
                attempt_index,
                routing_mark = "",
                elapsed_ms,
                "direct connect success"
            );
        }
    }
}

fn log_direct_connect_failed(
    session_id: u64,
    outbound_field: &str,
    destination_field: &str,
    address: SocketAddr,
    attempt_index: u64,
    routing_mark: Option<u32>,
    elapsed_ms: u64,
    err: &ProxyError,
) {
    match routing_mark {
        Some(mark) => {
            warn!(
                event = "direct_connect_failed",
                session_id,
                outbound = %outbound_field,
                destination = %destination_field,
                resolved_addr = %address,
                attempt_index,
                routing_mark = mark,
                elapsed_ms,
                error_kind = %err.kind(),
                error = %err,
                "direct connect failed"
            );
        }
        None => {
            warn!(
                event = "direct_connect_failed",
                session_id,
                outbound = %outbound_field,
                destination = %destination_field,
                resolved_addr = %address,
                attempt_index,
                routing_mark = "",
                elapsed_ms,
                error_kind = %err.kind(),
                error = %err,
                "direct connect failed"
            );
        }
    }
}

fn finalize_direct_connect_error(
    last_error: ProxyError,
    destination_field: &str,
    attempt_count: usize,
) -> ProxyError {
    if attempt_count <= 1 {
        return last_error;
    }

    let context =
        format!("all {attempt_count} direct connect attempts failed for {destination_field}");
    match last_error {
        ProxyError::Dial(message) => ProxyError::Dial(format!("{context}; last error: {message}")),
        ProxyError::Timeout(message) => {
            ProxyError::Timeout(format!("{context}; last error: {message}"))
        }
        other => other,
    }
}

async fn resolve_destination(host: &Host, port: u16) -> Result<Vec<SocketAddr>> {
    match host {
        Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
        Host::Domain(domain) => {
            let addresses = lookup_host((domain.as_str(), port)).await.map_err(|err| {
                ProxyError::Resolve(format!("failed to resolve {domain}:{port}: {err}"))
            })?;
            let addresses: Vec<_> = addresses.collect();
            if addresses.is_empty() {
                return Err(ProxyError::Resolve(format!(
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
    routing_mark: Option<u32>,
    marked_connector: Arc<MarkedConnector>,
) -> Result<TcpStream> {
    let connect_future = async move {
        match routing_mark {
            Some(routing_mark) => marked_connector(address, routing_mark).await,
            None => TcpStream::connect(address).await.map_err(|err| {
                ProxyError::Dial(format!("direct connect failed to {address}: {err}"))
            }),
        }
    };

    match timeout_duration {
        Some(duration) => timeout(duration, connect_future)
            .await
            .map_err(|_| ProxyError::Timeout(format!("direct connect timeout to {address}")))?,
        None => connect_future.await,
    }
}

async fn connect_marked_socket(address: SocketAddr, routing_mark: u32) -> Result<TcpStream> {
    connect_marked_socket_impl(address, routing_mark).await
}

#[cfg(target_os = "linux")]
async fn connect_marked_socket_impl(address: SocketAddr, routing_mark: u32) -> Result<TcpStream> {
    use std::os::fd::AsRawFd;

    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(|err| {
        ProxyError::Dial(format!(
            "failed to create direct socket for {address}: {err}"
        ))
    })?;
    socket.set_nonblocking(true).map_err(|err| {
        ProxyError::Dial(format!(
            "failed to switch direct socket to nonblocking mode for {address}: {err}"
        ))
    })?;
    let mark = routing_mark as libc::c_int;
    // SAFETY: the socket fd is live, the option buffer points to a valid integer,
    // and the length matches the pointed-to value size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(ProxyError::Dial(format!(
            "failed to set SO_MARK={routing_mark} for {address}: {}",
            std::io::Error::last_os_error()
        )));
    }

    match socket.connect(&address.into()) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(err) => {
            return Err(ProxyError::Dial(format!(
                "direct connect failed to {address} with SO_MARK={routing_mark}: {err}"
            )))
        }
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream).map_err(|err| {
        ProxyError::Dial(format!(
            "failed to register marked direct socket for {address} with tokio: {err}"
        ))
    })?;
    stream.writable().await.map_err(|err| {
        ProxyError::Dial(format!(
            "marked direct socket did not become writable for {address}: {err}"
        ))
    })?;
    if let Some(err) = stream.take_error().map_err(|err| {
        ProxyError::Dial(format!(
            "failed to inspect marked direct socket error for {address}: {err}"
        ))
    })? {
        return Err(ProxyError::Dial(format!(
            "direct connect failed to {address} with SO_MARK={routing_mark}: {err}"
        )));
    }

    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
async fn connect_marked_socket_impl(address: SocketAddr, _routing_mark: u32) -> Result<TcpStream> {
    Err(ProxyError::Config(format!(
        "direct outbound routing_mark is not supported on this platform for {address}"
    )))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        collections::HashMap,
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::net::{TcpListener, TcpStream};
    use tracing::{
        field::{Field, Visit},
        Event, Subscriber,
    };
    use tracing_subscriber::{
        layer::Context as LayerContext, prelude::*, registry::LookupSpan, Layer,
    };
    use veex_core::{
        BoxFuture, Destination, Host, Network, Outbound, ProxyError, SessionContext, SessionMeta,
    };

    use super::{connect_addresses, DirectOutbound};

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

    #[test]
    fn direct_outbound_is_constructible_for_dispatcher_registration() {
        let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        let mut direct = DirectOutbound::new("direct", None).expect("direct outbound should build");
        direct.set_connect_timeout(Some(Duration::from_secs(1)));
        outbounds.insert("direct".into(), Arc::new(direct));

        assert_eq!(outbounds.len(), 1);
    }

    #[tokio::test]
    async fn direct_outbound_uses_marked_connector_when_routing_mark_is_set() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener addr should exist");
        let captured_mark = Arc::new(Mutex::new(None));
        let captured_mark_for_connector = Arc::clone(&captured_mark);
        let connector = Arc::new(move |connect_address, routing_mark| {
            let captured_mark = Arc::clone(&captured_mark_for_connector);
            Box::pin(async move {
                *captured_mark.lock().expect("mark mutex should lock") = Some(routing_mark);
                TcpStream::connect(connect_address).await.map_err(|err| {
                    ProxyError::Dial(format!(
                        "test marked connector failed to connect to {connect_address}: {err}"
                    ))
                })
            }) as BoxFuture<'static, TcpStream>
        });
        let direct = DirectOutbound {
            tag: "direct".into(),
            connect_timeout: Some(Duration::from_secs(1)),
            routing_mark: Some(9),
            marked_connector: connector,
        };
        let ctx = SessionContext::new(
            SessionMeta {
                id: 1,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: "127.0.0.1:30000".parse().expect("peer addr should parse"),
                destination: Destination::new(Host::Ip(address.ip()), address.port()),
                start: std::time::Instant::now(),
            },
            Vec::new(),
        );

        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept should succeed");
        });
        let stream = direct
            .connect(&ctx)
            .await
            .expect("marked direct outbound should connect");
        drop(stream);
        accept_task.await.expect("accept task should join");

        assert_eq!(
            *captured_mark.lock().expect("mark mutex should lock"),
            Some(9)
        );

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "direct_connect_attempt",
            &[
                ("session_id", "1"),
                ("outbound", "direct"),
                ("attempt_index", "1"),
                ("routing_mark", "9"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "direct_connect_success",
            &[
                ("session_id", "1"),
                ("outbound", "direct"),
                ("attempt_index", "1"),
                ("routing_mark", "9"),
                ("level", "INFO"),
            ],
        );
    }

    #[tokio::test]
    async fn direct_outbound_emits_failed_event_with_routing_mark() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let connector = Arc::new(move |_connect_address, routing_mark| {
            Box::pin(async move {
                Err(ProxyError::Dial(format!(
                    "test marked connector rejected routing_mark={routing_mark}"
                )))
            }) as BoxFuture<'static, TcpStream>
        });
        let direct = DirectOutbound {
            tag: "direct".into(),
            connect_timeout: Some(Duration::from_secs(1)),
            routing_mark: Some(255),
            marked_connector: connector,
        };
        let ctx = SessionContext::new(
            SessionMeta {
                id: 2,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: "127.0.0.1:30000".parse().expect("peer addr should parse"),
                destination: Destination::new(Host::Ip("127.0.0.1".parse().unwrap()), 8080),
                start: std::time::Instant::now(),
            },
            Vec::new(),
        );

        let err = match direct.connect(&ctx).await {
            Ok(_) => panic!("marked direct outbound should fail"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), veex_core::ErrorKind::Dial);

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "direct_connect_attempt",
            &[
                ("session_id", "2"),
                ("outbound", "direct"),
                ("attempt_index", "1"),
                ("routing_mark", "255"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "direct_connect_failed",
            &[
                ("session_id", "2"),
                ("outbound", "direct"),
                ("attempt_index", "1"),
                ("routing_mark", "255"),
                ("error_kind", "dial"),
                ("level", "WARN"),
            ],
        );
    }

    #[tokio::test]
    async fn direct_outbound_falls_back_to_later_address_with_routing_mark() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener should bind");
        let reachable = listener.local_addr().expect("listener addr should exist");
        let unreachable = SocketAddr::new("127.0.0.2".parse().unwrap(), reachable.port());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let calls_for_connector = Arc::clone(&calls);
        let connector = Arc::new(move |connect_address, routing_mark| {
            let calls = Arc::clone(&calls_for_connector);
            Box::pin(async move {
                calls
                    .lock()
                    .expect("calls mutex should lock")
                    .push((connect_address, routing_mark));
                if connect_address == reachable {
                    TcpStream::connect(connect_address).await.map_err(|err| {
                        ProxyError::Dial(format!(
                            "test marked connector failed to connect to {connect_address}: {err}"
                        ))
                    })
                } else {
                    Err(ProxyError::Dial(format!(
                        "test marked connector rejected {connect_address}"
                    )))
                }
            }) as BoxFuture<'static, TcpStream>
        });

        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept should succeed");
        });

        let stream = connect_addresses(
            3,
            "direct",
            "fallback.test:443",
            vec![unreachable, reachable],
            Some(Duration::from_secs(1)),
            Some(42),
            connector,
        )
        .await
        .expect("second address should connect");
        drop(stream);
        accept_task.await.expect("accept task should join");

        assert_eq!(
            *calls.lock().expect("calls mutex should lock"),
            vec![(unreachable, 42), (reachable, 42)]
        );

        let events = captured_events(&trace_buffer);
        assert_eq!(event_count(&events, "direct_connect_attempt"), 2);
        assert_eq!(event_count(&events, "direct_connect_failed"), 1);
        assert_eq!(event_count(&events, "direct_connect_success"), 1);
        assert_has_event(
            &events,
            "direct_connect_failed",
            &[
                ("session_id", "3"),
                ("attempt_index", "1"),
                ("routing_mark", "42"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "direct_connect_success",
            &[
                ("session_id", "3"),
                ("attempt_index", "2"),
                ("routing_mark", "42"),
                ("level", "INFO"),
            ],
        );
    }

    #[tokio::test]
    async fn direct_outbound_returns_last_failure_after_all_addresses_fail() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let first = SocketAddr::new("127.0.0.2".parse().unwrap(), 18080);
        let second = SocketAddr::new("127.0.0.3".parse().unwrap(), 18080);
        let connector = Arc::new(move |connect_address, routing_mark| {
            Box::pin(async move {
                Err(ProxyError::Dial(format!(
                    "test marked connector rejected {connect_address} with routing_mark={routing_mark}"
                )))
            }) as BoxFuture<'static, TcpStream>
        });

        let err = connect_addresses(
            4,
            "direct",
            "fallback.test:443",
            vec![first, second],
            Some(Duration::from_secs(1)),
            Some(99),
            connector,
        )
        .await
        .expect_err("all addresses should fail");

        assert_eq!(err.kind(), veex_core::ErrorKind::Dial);
        assert!(err
            .to_string()
            .contains("all 2 direct connect attempts failed for fallback.test:443"));
        assert!(err.to_string().contains(&second.to_string()));

        let events = captured_events(&trace_buffer);
        assert_eq!(event_count(&events, "direct_connect_attempt"), 2);
        assert_eq!(event_count(&events, "direct_connect_failed"), 2);
        assert_eq!(event_count(&events, "direct_connect_success"), 0);
        assert_has_event(
            &events,
            "direct_connect_failed",
            &[
                ("session_id", "4"),
                ("attempt_index", "1"),
                ("routing_mark", "99"),
                ("level", "WARN"),
            ],
        );
        assert_has_event(
            &events,
            "direct_connect_failed",
            &[
                ("session_id", "4"),
                ("attempt_index", "2"),
                ("routing_mark", "99"),
                ("level", "WARN"),
            ],
        );
    }
}
