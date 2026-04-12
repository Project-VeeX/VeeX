use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use tokio::time::timeout;
use tracing::{info, warn};
use veex_core::{
    sanitize_field, BoxFuture, Destination, DnsExecutorHandle, Network, OutboundRegistry,
    PacketFrame, ProxyError, SessionContext, SessionMeta,
};

mod router;
mod wire;

pub use router::{DnsRouteReason, DnsRouter, DnsRule, DnsSelection};
pub use wire::parse_query_domain;

const DEFAULT_DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRuntimeConfig {
    pub final_server_tag: String,
    pub servers: Vec<DnsServer>,
    pub rules: Vec<DnsRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsServer {
    pub tag: String,
    pub transport: DnsServerTransport,
    pub destination: Destination,
    pub detour: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsServerTransport {
    Udp,
    Unsupported(String),
}

pub struct DnsExecutor {
    router: DnsRouter,
    servers: HashMap<String, DnsServer>,
    outbounds: Arc<OutboundRegistry>,
    next_query_id: AtomicU64,
    query_timeout: Duration,
}

impl DnsExecutor {
    pub fn new(
        config: DnsRuntimeConfig,
        outbounds: Arc<OutboundRegistry>,
    ) -> veex_core::Result<Self> {
        let mut servers = HashMap::new();
        for server in config.servers {
            if servers.insert(server.tag.clone(), server).is_some() {
                return Err(ProxyError::config("duplicate dns server tag in runtime"));
            }
        }

        Ok(Self {
            router: DnsRouter::new(config.final_server_tag, config.rules),
            servers,
            outbounds,
            next_query_id: AtomicU64::new(1),
            query_timeout: DEFAULT_DNS_QUERY_TIMEOUT,
        })
    }

    fn next_query_id(&self) -> u64 {
        self.next_query_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn execute_query_impl(&self, packet: PacketFrame) -> veex_core::Result<Vec<u8>> {
        let query_name = parse_query_domain(&packet.payload)?;
        let selection = self.router.select(&query_name);
        let server = self.servers.get(&selection.server_tag).ok_or_else(|| {
            ProxyError::config(format!("missing dns server tag: {}", selection.server_tag))
        })?;

        let inbound = sanitize_field(&packet.metadata.inbound_tag).into_owned();
        let query_name_field = sanitize_field(&query_name).into_owned();
        let server_tag = sanitize_field(&server.tag).into_owned();
        let detour = sanitize_field(&server.detour).into_owned();
        let destination = sanitize_field(&server.destination.to_string()).into_owned();
        let query_id = self.next_query_id();

        info!(
            event = "dns_query_start",
            query_id,
            inbound = %inbound,
            query_name = %query_name_field,
            server = %server_tag,
            detour = %detour,
            destination = %destination,
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            "dns query started"
        );

        match &server.transport {
            DnsServerTransport::Udp => {}
            DnsServerTransport::Unsupported(kind) => {
                return Err(ProxyError::protocol(format!(
                    "dns server '{}' uses unsupported upstream type '{}'",
                    server.tag, kind
                )));
            }
        }

        let outbound = self.outbounds.get(&server.detour).ok_or_else(|| {
            ProxyError::config(format!(
                "missing outbound tag for dns detour: {}",
                server.detour
            ))
        })?;
        let ctx = SessionContext::new(
            SessionMeta {
                id: query_id,
                network: Network::Udp,
                inbound_tag: packet.metadata.inbound_tag.clone(),
                peer: packet.metadata.peer,
                destination: server.destination.clone(),
                start: Instant::now(),
            },
            Vec::new(),
        );
        let session = outbound.connect_packet(&ctx).await?;

        if let Err(err) = session.send_packet(packet.payload).await {
            let _ = log_close_result(query_id, session.close().await);
            warn!(
                event = "dns_query_failed",
                query_id,
                inbound = %inbound,
                query_name = %query_name_field,
                server = %server_tag,
                detour = %detour,
                destination = %destination,
                route_reason = %selection.reason.as_str(),
                error_kind = ?err.kind(),
                error = %err,
                "dns upstream send failed"
            );
            return Err(err);
        }

        let response = match timeout(self.query_timeout, session.recv_packet()).await {
            Ok(result) => result,
            Err(_) => Err(ProxyError::timeout(format!(
                "dns upstream response timeout after {} ms",
                self.query_timeout.as_millis()
            ))),
        };
        let _ = log_close_result(query_id, session.close().await);

        match response {
            Ok(response) => {
                info!(
                    event = "dns_query_success",
                    query_id,
                    inbound = %inbound,
                    query_name = %query_name_field,
                    server = %server_tag,
                    detour = %detour,
                    destination = %destination,
                    route_reason = %selection.reason.as_str(),
                    transport = %server.transport.as_str(),
                    response_bytes = response.len() as u64,
                    "dns query succeeded"
                );
                Ok(response)
            }
            Err(err) => {
                warn!(
                    event = "dns_query_failed",
                    query_id,
                    inbound = %inbound,
                    query_name = %query_name_field,
                    server = %server_tag,
                    detour = %detour,
                    destination = %destination,
                    route_reason = %selection.reason.as_str(),
                    error_kind = ?err.kind(),
                    error = %err,
                    "dns upstream receive failed"
                );
                Err(err)
            }
        }
    }
}

impl DnsExecutorHandle for DnsExecutor {
    fn execute_query(&self, packet: PacketFrame) -> BoxFuture<'_, Vec<u8>> {
        Box::pin(async move { self.execute_query_impl(packet).await })
    }
}

impl DnsServerTransport {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Udp => "udp",
            Self::Unsupported(kind) => kind.as_str(),
        }
    }
}

fn log_close_result(query_id: u64, result: veex_core::Result<()>) {
    if let Err(err) = result {
        warn!(
            event = "dns_query_close_failed",
            query_id,
            error_kind = ?err.kind(),
            error = %err,
            "dns upstream session close failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use tokio::sync::{mpsc, Mutex};
    use veex_core::{
        packet::PacketSessionHandle, BoxedAsyncStream, Destination, DnsExecutorHandle, Host,
        Logger, Network, Outbound, OutboundConnector, OutboundMeta, PacketFrame, ProxyError,
        SessionContext,
    };

    use super::{DnsExecutor, DnsRule, DnsRuntimeConfig, DnsServer, DnsServerTransport};

    struct TestPacketSession {
        recv: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        sent_count: AtomicUsize,
    }

    impl veex_core::PacketSession for TestPacketSession {
        fn send_packet(&self, _payload: Vec<u8>) -> veex_core::BoxFuture<'_, ()> {
            self.sent_count.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }

        fn recv_packet(&self) -> veex_core::BoxFuture<'_, Vec<u8>> {
            Box::pin(async move {
                self.recv
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| ProxyError::protocol("test packet session closed"))
            })
        }
    }

    struct TestOutbound {
        meta: OutboundMeta,
        logger: Logger,
        session: PacketSessionHandle,
    }

    impl Outbound for TestOutbound {
        fn meta(&self) -> &OutboundMeta {
            &self.meta
        }

        fn logger(&self) -> &Logger {
            &self.logger
        }

        fn close(&self) -> veex_core::BoxFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    impl OutboundConnector for TestOutbound {
        fn connect(&self, _ctx: &SessionContext) -> veex_core::BoxFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("stream path unused")) })
        }

        fn connect_packet(
            &self,
            _ctx: &SessionContext,
        ) -> veex_core::BoxFuture<'_, PacketSessionHandle> {
            let session = Arc::clone(&self.session);
            Box::pin(async move { Ok(session) })
        }
    }

    #[tokio::test]
    async fn dns_executor_uses_dns_rule_and_returns_upstream_response() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(vec![0x12, 0x34]).expect("response should enqueue");
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
        });
        let outbound = Arc::new(TestOutbound {
            meta: OutboundMeta::new("direct", "test"),
            logger: Logger::new("direct", "test"),
            session,
        });
        let mut registry = veex_core::OutboundRegistry::default();
        registry
            .register(outbound as Arc<dyn OutboundConnector>)
            .expect("test outbound should register");
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "fallback".into(),
                servers: vec![
                    DnsServer {
                        tag: "direct".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            53,
                        ),
                        detour: "direct".into(),
                    },
                    DnsServer {
                        tag: "fallback".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        detour: "direct".into(),
                    },
                ],
                rules: vec![DnsRule {
                    domain: vec!["trojan.example.com".into()],
                    server_tag: "direct".into(),
                }],
            },
            Arc::new(registry),
        )
        .expect("dns executor should build");

        let response = executor
            .execute_query(PacketFrame::new(
                veex_core::PacketMetadata::new(
                    "dns-in",
                    SocketAddr::from(([127, 0, 0, 1], 53000)),
                    Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
                    Network::Udp,
                ),
                vec![
                    0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
                    b't', b'r', b'o', b'j', b'a', b'n', 0x07, b'e', b'x', b'a', b'm', b'p', b'l',
                    b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
                ],
            ))
            .await
            .expect("dns query should succeed");

        assert_eq!(response, vec![0x12, 0x34]);
    }
}
