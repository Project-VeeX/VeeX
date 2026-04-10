//! Direct outbound implementation kept outside `veex-core` so platform-specific
//! egress behavior can evolve without polluting core runtime abstractions.

use std::{fmt, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;
use veex_core::{
    error::{ProxyError, Result},
    traits::{BoxFuture, Outbound},
    types::{BoxedAsyncStream, SessionContext},
};
use veex_transport::{
    connect_host_with_resolver, resolve_host, ConnectTraceContext, HostResolver,
    TcpAttemptConnector, TcpConnectOptions,
};

type MarkedConnectorFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'static>>;
type MarkedConnector = dyn Fn(SocketAddr, u32) -> MarkedConnectorFuture + Send + Sync;

#[derive(Clone)]
pub struct DirectOutbound {
    tag: String,
    connect_timeout: Duration,
    routing_mark: Option<u32>,
    resolver: Arc<HostResolver>,
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
    pub fn new(
        tag: impl Into<String>,
        routing_mark: Option<u32>,
        connect_timeout: Duration,
    ) -> Result<Self> {
        Self::new_with_resolver(tag, routing_mark, connect_timeout, system_host_resolver())
    }

    pub fn new_with_resolver(
        tag: impl Into<String>,
        routing_mark: Option<u32>,
        connect_timeout: Duration,
        resolver: Arc<HostResolver>,
    ) -> Result<Self> {
        if routing_mark.is_some() && !cfg!(target_os = "linux") {
            return Err(ProxyError::Config(
                "direct outbound routing_mark is only supported on linux".into(),
            ));
        }

        Ok(Self {
            tag: tag.into(),
            connect_timeout,
            routing_mark,
            resolver,
            marked_connector: Arc::new(|address, routing_mark| {
                Box::pin(connect_marked_socket(address, routing_mark))
            }),
        })
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }
}

impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn connect(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
        let destination = ctx.meta.destination.clone();
        let session_id = ctx.meta.id;
        let outbound = self.tag.clone();
        let connect_timeout = self.connect_timeout;
        let routing_mark = self.routing_mark;
        let resolver = Arc::clone(&self.resolver);
        let marked_connector = Arc::clone(&self.marked_connector);

        Box::pin(async move {
            let connector = routing_mark.map(|routing_mark| {
                let marked_connector = Arc::clone(&marked_connector);
                Arc::new(move |address| marked_connector(address, routing_mark))
                    as Arc<TcpAttemptConnector>
            });

            let stream = connect_host_with_resolver(
                &destination.host,
                destination.port,
                resolver.as_ref(),
                TcpConnectOptions {
                    timeout: Some(connect_timeout),
                    trace: Some(ConnectTraceContext {
                        session_id,
                        outbound,
                        routing_mark,
                    }),
                    connector,
                },
            )
            .await?;

            Ok(Box::new(stream) as BoxedAsyncStream)
        })
    }
}

fn system_host_resolver() -> Arc<HostResolver> {
    Arc::new(|host, port| Box::pin(async move { resolve_host(&host, port).await }))
}

async fn connect_marked_socket(address: SocketAddr, routing_mark: u32) -> io::Result<TcpStream> {
    connect_marked_socket_impl(address, routing_mark).await
}

#[cfg(target_os = "linux")]
async fn connect_marked_socket_impl(
    address: SocketAddr,
    routing_mark: u32,
) -> io::Result<TcpStream> {
    use std::os::fd::AsRawFd;

    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(|err| {
        io_error_with_context(format!("failed to create direct socket for {address}"), err)
    })?;
    socket.set_nonblocking(true).map_err(|err| {
        io_error_with_context(
            format!("failed to switch direct socket to nonblocking mode for {address}"),
            err,
        )
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
        return Err(last_os_error_with_context(format!(
            "failed to set SO_MARK={routing_mark} for {address}"
        )));
    }

    match socket.connect(&address.into()) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(err) => {
            return Err(io_error_with_context(
                format!("direct connect failed to {address} with SO_MARK={routing_mark}"),
                err,
            ));
        }
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream).map_err(|err| {
        io_error_with_context(
            format!("failed to register marked direct socket for {address} with tokio"),
            err,
        )
    })?;
    stream.writable().await.map_err(|err| {
        io_error_with_context(
            format!("marked direct socket did not become writable for {address}"),
            err,
        )
    })?;
    if let Some(err) = stream.take_error().map_err(|err| {
        io_error_with_context(
            format!("failed to inspect marked direct socket error for {address}"),
            err,
        )
    })? {
        return Err(io_error_with_context(
            format!("direct connect failed to {address} with SO_MARK={routing_mark}"),
            err,
        ));
    }

    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
async fn connect_marked_socket_impl(
    address: SocketAddr,
    _routing_mark: u32,
) -> io::Result<TcpStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("direct outbound routing_mark is not supported on this platform for {address}"),
    ))
}

fn io_error_with_context(context: impl Into<String>, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), format!("{}: {source}", context.into()))
}

fn last_os_error_with_context(context: impl Into<String>) -> io::Error {
    let source = io::Error::last_os_error();
    io::Error::new(source.kind(), format!("{}: {source}", context.into()))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use tokio::{
        net::{TcpListener, TcpStream},
        time::sleep,
    };
    use tracing::{
        field::{Field, Visit},
        Event, Subscriber,
    };
    use tracing_subscriber::{
        layer::Context as LayerContext, prelude::*, registry::LookupSpan, Layer,
    };
    use veex_core::{Destination, Host, Network, Outbound, SessionContext, SessionMeta};

    use super::{system_host_resolver, DirectOutbound, MarkedConnectorFuture};

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

    #[test]
    fn direct_outbound_is_constructible_for_dispatcher_registration() {
        let direct =
            DirectOutbound::new("direct", None, Duration::from_secs(1)).expect("build direct");

        assert_eq!(direct.tag(), "direct");
    }

    #[tokio::test]
    async fn direct_outbound_uses_transport_connector_for_routing_mark() {
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
                TcpStream::connect(connect_address).await
            }) as MarkedConnectorFuture
        });
        let direct = DirectOutbound {
            tag: "direct".into(),
            connect_timeout: Duration::from_secs(1),
            routing_mark: Some(9),
            resolver: system_host_resolver(),
            marked_connector: connector,
        };
        let ctx = SessionContext::new(
            SessionMeta {
                id: 1,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: "127.0.0.1:30000".parse().expect("peer addr should parse"),
                destination: Destination::new(Host::Ip(address.ip()), address.port()),
                start: Instant::now(),
            },
            Vec::new(),
        );

        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept should succeed");
        });
        let stream = direct.connect(&ctx).await.expect("direct should connect");
        drop(stream);
        accept_task.await.expect("accept task should join");

        assert_eq!(
            *captured_mark.lock().expect("mark mutex should lock"),
            Some(9)
        );

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tcp_connect_attempt",
            &[
                ("session_id", "1"),
                ("outbound", "direct"),
                ("routing_mark", "9"),
                ("attempt_index", "1"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "tcp_connect_success",
            &[
                ("session_id", "1"),
                ("outbound", "direct"),
                ("routing_mark", "9"),
                ("attempt_index", "1"),
                ("level", "INFO"),
            ],
        );
    }

    #[tokio::test]
    async fn direct_outbound_surfaces_connector_failures_with_transport_error_kind() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let connector = Arc::new(move |_connect_address, routing_mark| {
            Box::pin(async move {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("test marked connector rejected routing_mark={routing_mark}"),
                ))
            }) as MarkedConnectorFuture
        });
        let direct = DirectOutbound {
            tag: "direct".into(),
            connect_timeout: Duration::from_secs(1),
            routing_mark: Some(255),
            resolver: system_host_resolver(),
            marked_connector: connector,
        };
        let ctx = SessionContext::new(
            SessionMeta {
                id: 2,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: "127.0.0.1:30000".parse().expect("peer addr should parse"),
                destination: Destination::new(Host::Ip("127.0.0.1".parse().unwrap()), 8080),
                start: Instant::now(),
            },
            Vec::new(),
        );

        let err = match direct.connect(&ctx).await {
            Ok(_) => panic!("direct should fail"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), veex_core::ErrorKind::Dial);

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "2"),
                ("outbound", "direct"),
                ("routing_mark", "255"),
                ("error_kind", "dial"),
                ("failure_reason", "refused"),
                ("level", "WARN"),
            ],
        );
    }

    #[tokio::test]
    async fn direct_outbound_timeout_is_enforced_by_transport() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let connector = Arc::new(move |_connect_address, _routing_mark| {
            Box::pin(async move {
                sleep(Duration::from_millis(200)).await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "delayed connector should have timed out earlier",
                ))
            }) as MarkedConnectorFuture
        });
        let direct = DirectOutbound {
            tag: "direct".into(),
            connect_timeout: Duration::from_millis(50),
            routing_mark: Some(7),
            resolver: system_host_resolver(),
            marked_connector: connector,
        };
        let ctx = SessionContext::new(
            SessionMeta {
                id: 3,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: "127.0.0.1:30000".parse().expect("peer addr should parse"),
                destination: Destination::new(Host::Ip("127.0.0.1".parse().unwrap()), 8080),
                start: Instant::now(),
            },
            Vec::new(),
        );

        let err = match direct.connect(&ctx).await {
            Ok(_) => panic!("direct should time out"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), veex_core::ErrorKind::Timeout);

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "tcp_connect_failed",
            &[
                ("session_id", "3"),
                ("outbound", "direct"),
                ("routing_mark", "7"),
                ("error_kind", "timeout"),
                ("failure_reason", "timeout"),
                ("timeout_ms", "50"),
                ("level", "WARN"),
            ],
        );
    }
}
