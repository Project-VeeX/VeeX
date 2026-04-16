//! Direct outbound implementation kept outside `veex-core` so platform-specific
//! egress behavior can evolve without polluting core runtime abstractions.

use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use veex_core::{
    BoxFuture, BoxedAsyncStream, Dialer, ExecutionOutbound, Logger, Outbound, OutboundMeta,
    PacketDialer, PacketSessionHandle, ProxyError, Result, SessionContext, StreamOutbound,
};

#[derive(Debug)]
struct DirectOutboundState {
    closed: AtomicBool,
}

pub struct DirectOutbound {
    meta: OutboundMeta,
    logger: Logger,
    dialer: Dialer,
    packet_dialer: PacketDialer,
    state: Arc<DirectOutboundState>,
}

impl fmt::Debug for DirectOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectOutbound")
            .field("meta", &self.meta)
            .field("logger", &self.logger)
            .field("dialer", &self.dialer)
            .field("packet_dialer", &self.packet_dialer)
            .finish()
    }
}

impl DirectOutbound {
    pub fn new(
        meta: OutboundMeta,
        logger: Logger,
        dialer: Dialer,
        packet_dialer: PacketDialer,
    ) -> Result<Self> {
        let outbound = Self {
            meta,
            logger,
            dialer,
            packet_dialer,
            state: Arc::new(DirectOutboundState {
                closed: AtomicBool::new(false),
            }),
        };
        outbound.validate()?;
        Ok(outbound)
    }

    pub fn validate(&self) -> Result<()> {
        if self.meta.tag.trim().is_empty() {
            return Err(ProxyError::config("direct outbound tag must not be empty"));
        }
        if self.meta.r#type.trim().is_empty() {
            return Err(ProxyError::config("direct outbound type must not be empty"));
        }

        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.state.closed.load(Ordering::Relaxed)
    }

    fn connect_upstream_stream(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
        let destination = ctx.meta.destination.clone();
        let dialer = self.dialer.clone();
        let trace = self.dialer.context(ctx, self.meta.tag.clone());
        let closed = self.is_closed();

        Box::pin(async move {
            if closed {
                return Err(ProxyError::Shutdown);
            }
            let stream = dialer
                .connect(&destination.host, destination.port, trace)
                .await?;

            Ok(Box::new(stream) as BoxedAsyncStream)
        })
    }

    fn connect_upstream_packet(&self, ctx: &SessionContext) -> BoxFuture<'_, PacketSessionHandle> {
        let destination = ctx.meta.destination.clone();
        let dialer = self.packet_dialer.clone();
        let trace = self.packet_dialer.context(ctx, self.meta.tag.clone());
        let closed = self.is_closed();

        Box::pin(async move {
            if closed {
                return Err(ProxyError::Shutdown);
            }

            dialer
                .connect(&destination.host, destination.port, trace)
                .await
        })
    }
}

impl Outbound for DirectOutbound {
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

impl StreamOutbound for DirectOutbound {
    fn connect_stream(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
        self.connect_upstream_stream(ctx)
    }
}

impl ExecutionOutbound for DirectOutbound {
    fn open_stream(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
        self.connect_upstream_stream(ctx)
    }

    fn open_packet(&self, ctx: &SessionContext) -> BoxFuture<'_, PacketSessionHandle> {
        self.connect_upstream_packet(ctx)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use tokio::{
        net::{TcpListener, TcpStream},
        time::sleep,
    };
    use veex_core::{
        BoxFuture, Destination, Dial, DialContext, Dialer, ExecutionOutbound, Host, Logger,
        Network, Outbound, OutboundMeta, PacketDialer, PacketSession, PacketSessionHandle,
        SessionContext, SessionMeta, StreamOutbound,
    };
    use veex_test_tracing::{assert_has_event, captured_events, install_test_subscriber};

    use super::super::dialer::{
        build_dialer_with_connector, system_host_resolver, MarkedConnectorFuture,
    };

    use super::DirectOutbound;

    fn shutdown_packet_dialer() -> PacketDialer {
        PacketDialer::new(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_secs(1)),
                routing_mark: None,
                domain_resolver: None,
            },
            Arc::new(|_host, _port, _dial, _ctx| {
                Box::pin(async { Err(veex_core::ProxyError::Shutdown) })
            }),
        )
    }

    #[derive(Default)]
    struct TestPacketSession;

    impl PacketSession for TestPacketSession {
        fn send_packet(&self, _payload: Vec<u8>) -> BoxFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn recv_packet(&self) -> BoxFuture<'_, Vec<u8>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[test]
    fn direct_outbound_is_constructible_for_dispatcher_registration() {
        let dialer = Dialer::new(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_secs(1)),
                routing_mark: None,
                domain_resolver: None,
            },
            Arc::new(|_host, _port, _dial, _ctx| {
                Box::pin(async { Err(veex_core::ProxyError::Shutdown) })
            }),
        );
        let direct = DirectOutbound::new(
            OutboundMeta::new("direct", "direct"),
            Logger::new("direct", "direct"),
            dialer,
            shutdown_packet_dialer(),
        )
        .expect("build direct");

        assert_eq!(direct.meta().tag, "direct");
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
        let dialer = build_dialer_with_connector(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_secs(1)),
                routing_mark: Some(9),
                domain_resolver: None,
            },
            system_host_resolver(),
            connector,
        )
        .expect("dialer should build");
        let direct = DirectOutbound::new(
            OutboundMeta::new("direct", "direct"),
            Logger::new("direct", "direct"),
            dialer,
            shutdown_packet_dialer(),
        )
        .expect("direct should build");
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
        let stream = direct
            .connect_stream(&ctx)
            .await
            .expect("direct should connect");
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
        let dialer = build_dialer_with_connector(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_secs(1)),
                routing_mark: Some(255),
                domain_resolver: None,
            },
            system_host_resolver(),
            connector,
        )
        .expect("dialer should build");
        let direct = DirectOutbound::new(
            OutboundMeta::new("direct", "direct"),
            Logger::new("direct", "direct"),
            dialer,
            shutdown_packet_dialer(),
        )
        .expect("direct should build");
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

        let err = match direct.connect_stream(&ctx).await {
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
        let dialer = build_dialer_with_connector(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_millis(50)),
                routing_mark: Some(7),
                domain_resolver: None,
            },
            system_host_resolver(),
            connector,
        )
        .expect("dialer should build");
        let direct = DirectOutbound::new(
            OutboundMeta::new("direct", "direct"),
            Logger::new("direct", "direct"),
            dialer,
            shutdown_packet_dialer(),
        )
        .expect("direct should build");
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

        let err = match direct.connect_stream(&ctx).await {
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

    #[tokio::test]
    async fn direct_outbound_open_packet_uses_packet_dialer_directly() {
        #[derive(Debug, Clone, Eq, PartialEq)]
        struct PacketDialCall {
            host: Host,
            port: u16,
            outbound_tag: String,
        }

        let dialer = Dialer::new(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_secs(1)),
                routing_mark: None,
                domain_resolver: None,
            },
            Arc::new(|_host, _port, _dial, _ctx| {
                Box::pin(async { Err(veex_core::ProxyError::Shutdown) })
            }),
        );
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded_calls = Arc::clone(&calls);
        let packet_dialer = PacketDialer::new(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_secs(1)),
                routing_mark: None,
                domain_resolver: None,
            },
            Arc::new(move |host, port, _dial, ctx: DialContext| {
                let recorded_calls = Arc::clone(&recorded_calls);
                Box::pin(async move {
                    recorded_calls
                        .lock()
                        .expect("packet call mutex should lock")
                        .push(PacketDialCall {
                            host,
                            port,
                            outbound_tag: ctx.outbound_tag,
                        });
                    Ok(Arc::new(TestPacketSession) as PacketSessionHandle)
                })
            }),
        );
        let direct = DirectOutbound::new(
            OutboundMeta::new("direct", "direct"),
            Logger::new("direct", "direct"),
            dialer,
            packet_dialer,
        )
        .expect("direct should build");
        let ctx = SessionContext::new(
            SessionMeta {
                id: 4,
                network: Network::Udp,
                inbound_tag: "direct-in".into(),
                peer: "127.0.0.1:30001".parse().expect("peer addr should parse"),
                destination: Destination::new(Host::Domain("example.com".into()), 53),
                start: Instant::now(),
            },
            Vec::new(),
        );

        direct
            .open_packet(&ctx)
            .await
            .expect("direct should open packet session");

        assert_eq!(
            calls
                .lock()
                .expect("packet call mutex should lock")
                .as_slice(),
            &[PacketDialCall {
                host: Host::Domain("example.com".into()),
                port: 53,
                outbound_tag: "direct".into(),
            }]
        );
    }

    #[tokio::test]
    async fn closing_direct_outbound_blocks_packet_execution() {
        let dialer = Dialer::new(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_secs(1)),
                routing_mark: None,
                domain_resolver: None,
            },
            Arc::new(|_host, _port, _dial, _ctx| {
                Box::pin(async { Err(veex_core::ProxyError::Shutdown) })
            }),
        );
        let packet_dialer = PacketDialer::new(
            Dial {
                detour: None,
                connect_timeout: Some(Duration::from_secs(1)),
                routing_mark: None,
                domain_resolver: None,
            },
            Arc::new(|_host, _port, _dial, _ctx| {
                Box::pin(async { Ok(Arc::new(TestPacketSession) as PacketSessionHandle) })
            }),
        );
        let direct = DirectOutbound::new(
            OutboundMeta::new("direct", "direct"),
            Logger::new("direct", "direct"),
            dialer,
            packet_dialer,
        )
        .expect("direct should build");
        direct.close().await.expect("direct close should succeed");
        let ctx = SessionContext::new(
            SessionMeta {
                id: 5,
                network: Network::Udp,
                inbound_tag: "direct-in".into(),
                peer: "127.0.0.1:30002".parse().expect("peer addr should parse"),
                destination: Destination::new(Host::Ip("127.0.0.1".parse().unwrap()), 53),
                start: Instant::now(),
            },
            Vec::new(),
        );

        let err = match direct.open_packet(&ctx).await {
            Ok(_) => panic!("packet execution should observe shutdown"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), veex_core::ErrorKind::Shutdown);
    }
}
