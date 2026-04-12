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
    read_dns_tcp_message, sanitize_field, write_dns_tcp_message, BoxFuture, Destination,
    DnsExecutorHandle, DnsRequest, DnsResponse, Network, OutboundRegistry, ProxyError,
    SessionContext, SessionMeta,
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
    Tcp,
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

    async fn execute_query_impl(&self, request: DnsRequest) -> veex_core::Result<DnsResponse> {
        let query_name = parse_query_domain(&request.raw_message)?;
        let selection = self.router.select(&query_name);
        let server = self.servers.get(&selection.server_tag).ok_or_else(|| {
            ProxyError::config(format!("missing dns server tag: {}", selection.server_tag))
        })?;

        let inbound = sanitize_field(&request.inbound_tag).into_owned();
        let query_name_field = sanitize_field(&query_name).into_owned();
        let server_tag = sanitize_field(&server.tag).into_owned();
        let detour = sanitize_field(&server.detour).into_owned();
        let destination = sanitize_field(&server.destination.to_string()).into_owned();
        let ingress_protocol = request.protocol.as_str();
        let query_id = self.next_query_id();

        info!(
            event = "dns_query_start",
            query_id,
            inbound = %inbound,
            ingress_protocol = %ingress_protocol,
            query_name = %query_name_field,
            server = %server_tag,
            detour = %detour,
            destination = %destination,
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            "dns query started"
        );

        let upstream_network = match &server.transport {
            DnsServerTransport::Udp => Network::Udp,
            DnsServerTransport::Tcp => Network::Tcp,
            DnsServerTransport::Unsupported(_) => request.protocol,
        };
        let ctx = SessionContext::new(
            SessionMeta {
                id: query_id,
                network: upstream_network,
                inbound_tag: request.inbound_tag.clone(),
                peer: request.peer,
                destination: server.destination.clone(),
                start: Instant::now(),
            },
            Vec::new(),
        );

        let response = match &server.transport {
            DnsServerTransport::Udp => {
                self.execute_udp_query(&ctx, &server.detour, &request.raw_message, query_id)
                    .await
            }
            DnsServerTransport::Tcp => {
                self.execute_tcp_query(&ctx, &server.detour, &request.raw_message, query_id)
                    .await
            }
            DnsServerTransport::Unsupported(kind) => {
                return Err(ProxyError::protocol(format!(
                    "dns server '{}' uses unsupported upstream type '{}'",
                    server.tag, kind
                )));
            }
        };

        match response {
            Ok(response) => {
                info!(
                    event = "dns_query_success",
                    query_id,
                    inbound = %inbound,
                    ingress_protocol = %ingress_protocol,
                    query_name = %query_name_field,
                    server = %server_tag,
                    detour = %detour,
                    destination = %destination,
                    route_reason = %selection.reason.as_str(),
                    transport = %server.transport.as_str(),
                    response_bytes = response.raw_message.len() as u64,
                    "dns query succeeded"
                );
                Ok(response)
            }
            Err(err) => {
                warn!(
                    event = "dns_query_failed",
                    query_id,
                    inbound = %inbound,
                    ingress_protocol = %ingress_protocol,
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

    async fn execute_udp_query(
        &self,
        ctx: &SessionContext,
        detour: &str,
        query: &[u8],
        query_id: u64,
    ) -> veex_core::Result<DnsResponse> {
        let outbound = self.outbounds.get(detour).ok_or_else(|| {
            ProxyError::config(format!("missing outbound tag for dns detour: {detour}"))
        })?;
        let session = outbound.connect_packet(ctx).await?;

        if let Err(err) = session.send_packet(query.to_vec()).await {
            log_close_result(query_id, session.close().await);
            return Err(err);
        }

        let response = match timeout(self.query_timeout, session.recv_packet()).await {
            Ok(result) => result,
            Err(_) => Err(ProxyError::timeout(format!(
                "dns upstream response timeout after {} ms",
                self.query_timeout.as_millis()
            ))),
        };
        log_close_result(query_id, session.close().await);

        response.map(DnsResponse::new)
    }

    async fn execute_tcp_query(
        &self,
        ctx: &SessionContext,
        detour: &str,
        query: &[u8],
        _query_id: u64,
    ) -> veex_core::Result<DnsResponse> {
        let outbound = self.outbounds.get(detour).ok_or_else(|| {
            ProxyError::config(format!("missing outbound tag for dns detour: {detour}"))
        })?;
        let mut stream = outbound.connect(ctx).await?;
        write_dns_tcp_message(&mut *stream, query).await?;
        let response = timeout(self.query_timeout, read_dns_tcp_message(&mut *stream)).await;
        let response = match response {
            Ok(result) => result?,
            Err(_) => {
                return Err(ProxyError::timeout(format!(
                    "dns upstream response timeout after {} ms",
                    self.query_timeout.as_millis()
                )));
            }
        };
        let response = response.ok_or_else(|| {
            ProxyError::protocol("dns over tcp upstream closed before sending a response")
        })?;
        Ok(DnsResponse::new(response))
    }
}

impl DnsExecutorHandle for DnsExecutor {
    fn execute_query(&self, request: DnsRequest) -> BoxFuture<'_, DnsResponse> {
        Box::pin(async move { self.execute_query_impl(request).await })
    }
}

impl DnsServerTransport {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
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
        packet::PacketSessionHandle, BoxedAsyncStream, Destination, DnsExecutorHandle, DnsRequest,
        Host, Logger, Network, Outbound, OutboundConnector, OutboundMeta, ProxyError,
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
            .execute_query(DnsRequest::new(
                vec![
                    0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
                    b't', b'r', b'o', b'j', b'a', b'n', 0x07, b'e', b'x', b'a', b'm', b'p', b'l',
                    b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
                ],
                Network::Udp,
                "dns-in",
                SocketAddr::from(([127, 0, 0, 1], 53000)),
                Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
            ))
            .await
            .expect("dns query should succeed");

        assert_eq!(response.raw_message, vec![0x12, 0x34]);
    }
}
