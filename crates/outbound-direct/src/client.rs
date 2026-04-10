//! Direct outbound implementation kept outside `veex-core` so platform-specific
//! egress behavior can evolve without polluting core runtime abstractions.

use std::{fmt, sync::Arc, time::Duration};

use veex_core::{
    error::Result,
    traits::{BoxFuture, Outbound},
    types::{BoxedAsyncStream, SessionContext},
};
use veex_transport::{ConnectTraceContext, HostResolver};

use crate::{
    dialer::{connect_destination, connect_marked_socket, system_host_resolver, MarkedConnector},
    error::validate_routing_mark_support,
};

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
        validate_routing_mark_support(routing_mark)?;

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
            let stream = connect_destination(
                &destination,
                resolver.as_ref(),
                connect_timeout,
                ConnectTraceContext {
                    session_id,
                    outbound,
                    routing_mark,
                },
                routing_mark,
                &marked_connector,
            )
            .await?;

            Ok(Box::new(stream) as BoxedAsyncStream)
        })
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
    use veex_core::{Destination, Host, Network, Outbound, SessionContext, SessionMeta};
    use veex_test_tracing::{assert_has_event, captured_events, install_test_subscriber};

    use crate::dialer::{system_host_resolver, MarkedConnectorFuture};

    use super::DirectOutbound;

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
