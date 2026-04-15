use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use tracing::{info, warn};
use veex_core::{
    sanitize_field, BoxFuture, DnsExecutorHandle, DnsRequest, DnsResponse, DomainResolverHandle,
    Host, OutboundRegistry, ProxyError, ResolveContext,
};

use crate::{
    build_a_query,
    dialer::DnsDialer,
    parse_query_domain, parse_response_ips,
    router::{DnsRouter, DnsServerRoute},
    traits::DnsUpstream,
    types::{DnsRuntimeConfig, DnsSelection, DnsServer, DnsServerTransport},
    upstream::build_upstream,
};

const DEFAULT_DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_RECURSION_DEPTH: u8 = 4;

struct DnsServerRuntime {
    server: DnsServer,
    dialer: Option<DnsDialer>,
    upstream: Arc<dyn DnsUpstream>,
}

impl DnsServerRuntime {
    fn new(
        server: DnsServer,
        outbounds: &Arc<OutboundRegistry>,
        query_timeout: Duration,
    ) -> veex_core::Result<Self> {
        let dialer = match &server.transport {
            DnsServerTransport::Local | DnsServerTransport::Unsupported(_) => None,
            _ => Some(DnsDialer::new(
                server.tag.clone(),
                server.dial.clone(),
                outbounds,
            )?),
        };
        let upstream = build_upstream(&server, dialer.clone(), query_timeout)?;
        Ok(Self {
            server,
            dialer,
            upstream,
        })
    }
}

pub struct DnsExecutor {
    router: DnsRouter,
    servers: HashMap<String, DnsServerRuntime>,
    next_query_id: AtomicU64,
}

impl DnsExecutor {
    pub fn new(
        config: DnsRuntimeConfig,
        outbounds: Arc<OutboundRegistry>,
    ) -> veex_core::Result<Self> {
        let query_timeout = DEFAULT_DNS_QUERY_TIMEOUT;
        let mut servers = HashMap::new();
        for server in config.servers {
            let tag = server.tag.clone();
            let runtime = DnsServerRuntime::new(server, &outbounds, query_timeout)?;
            if servers.insert(tag, runtime).is_some() {
                return Err(ProxyError::config("duplicate dns server tag in runtime"));
            }
        }

        Ok(Self {
            router: DnsRouter::new(config.final_server_tag, config.rules),
            servers,
            next_query_id: AtomicU64::new(1),
        })
    }

    fn next_query_id(&self) -> u64 {
        self.next_query_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn execute_query_impl(&self, request: DnsRequest) -> veex_core::Result<DnsResponse> {
        let query_name = parse_query_domain(&request.raw_message)?;
        let selection = self
            .router
            .select_client_upstream(&query_name, &self.server_routes())?;
        let server = self.lookup_server(&selection.server_tag)?;
        let query_id = self.next_query_id();

        self.log_query_start(&request, &query_name, &server.server, &selection, query_id);

        let response = selection
            .upstream
            .exchange(self.build_client_upstream_request(&request, server, query_id))
            .await;

        match response {
            Ok(response) => {
                self.on_client_response(&query_name, &response);
                self.log_query_success(
                    &request,
                    &query_name,
                    &server.server,
                    &selection,
                    query_id,
                    &response,
                );
                Ok(response)
            }
            Err(err) => {
                self.log_query_failure(
                    &request,
                    &query_name,
                    &server.server,
                    &selection,
                    query_id,
                    &err,
                );
                Err(err)
            }
        }
    }

    async fn resolve_host_impl(
        &self,
        host: Host,
        port: u16,
        context: ResolveContext,
    ) -> veex_core::Result<Vec<SocketAddr>> {
        match host {
            Host::Ip(ip) => Ok(vec![SocketAddr::new(ip, port)]),
            Host::Domain(domain) => self.resolve_domain_impl(domain, port, context).await,
        }
    }

    async fn resolve_domain_impl(
        &self,
        domain: String,
        port: u16,
        context: ResolveContext,
    ) -> veex_core::Result<Vec<SocketAddr>> {
        if context.recursion_depth >= MAX_DNS_RECURSION_DEPTH {
            return Err(ProxyError::resolve(format!(
                "domain resolver recursion depth exceeded for {domain}:{} at depth {}",
                port, context.recursion_depth
            )));
        }

        let selection = self
            .router
            .select_resolution_upstream(&context, &self.server_routes())?
            .ok_or_else(|| {
                ProxyError::resolve(format!(
                    "no safe dns server is available for dial-side resolution of {domain}"
                ))
            })?;
        let server = self.lookup_server(&selection.server_tag)?;
        let query_id = self.next_query_id();

        self.log_domain_resolve_start(
            &domain,
            port,
            &server.server,
            &selection,
            query_id,
            &context,
        );

        let query = build_a_query(&domain, query_id as u16)?;
        let response = selection
            .upstream
            .exchange(
                self.build_resolution_upstream_request(&domain, server, &query, query_id, &context),
            )
            .await;

        match response {
            Ok(response) => {
                let addresses = parse_response_ips(&response.raw_message)?
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect::<Vec<_>>();
                self.log_domain_resolve_success(
                    &domain,
                    port,
                    &server.server,
                    &selection,
                    query_id,
                    &context,
                    &addresses,
                );
                Ok(addresses)
            }
            Err(err) => {
                self.log_domain_resolve_failure(
                    &domain,
                    port,
                    &server.server,
                    &selection,
                    query_id,
                    &context,
                    &err,
                );
                Err(err)
            }
        }
    }

    fn server_routes(&self) -> Vec<DnsServerRoute<'_>> {
        self.servers
            .values()
            .map(|server| DnsServerRoute {
                tag: server.server.tag.as_str(),
                detour: server.server.dial.detour.as_deref(),
                upstream: Arc::clone(&server.upstream),
            })
            .collect()
    }

    fn lookup_server(&self, server_tag: &str) -> veex_core::Result<&DnsServerRuntime> {
        self.servers
            .get(server_tag)
            .ok_or_else(|| ProxyError::config(format!("missing dns server tag: {server_tag}")))
    }

    fn build_client_upstream_request(
        &self,
        request: &DnsRequest,
        server: &DnsServerRuntime,
        query_id: u64,
    ) -> DnsRequest {
        match &server.dialer {
            Some(dialer) => dialer.bind_client_request(request, query_id),
            None => request.clone().with_session_id(query_id),
        }
    }

    fn build_resolution_upstream_request(
        &self,
        domain: &str,
        server: &DnsServerRuntime,
        query: &[u8],
        query_id: u64,
        resolve_context: &ResolveContext,
    ) -> DnsRequest {
        match &server.dialer {
            Some(dialer) => dialer.bind_resolution_request(
                domain,
                &server.server,
                query,
                query_id,
                resolve_context,
            ),
            None => DnsRequest::new(
                query.to_vec(),
                crate::types::upstream_network(&server.server.transport),
                "dns-resolver",
                SocketAddr::from(([127, 0, 0, 1], 0)),
                server.server.destination.clone(),
            )
            .with_session_id(query_id)
            .with_resolve_context(resolve_context.clone())
            .with_buffered_payload(domain.as_bytes().to_vec()),
        }
    }

    fn log_query_start(
        &self,
        request: &DnsRequest,
        query_name: &str,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
    ) {
        info!(
            event = "dns_query_start",
            query_id,
            inbound = %sanitize_field(&request.inbound_tag),
            ingress_protocol = %request.protocol.as_str(),
            query_name = %sanitize_field(query_name),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            destination = %sanitize_field(&server.destination.to_string()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            "dns query started"
        );
    }

    fn on_client_response(&self, _query_name: &str, _response: &DnsResponse) {
        // Reserved for a future reverse_mapping side effect. This remains a no-op
        // until the DNS subsystem grows an explicit reverse map store.
    }

    fn log_query_success(
        &self,
        request: &DnsRequest,
        query_name: &str,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        response: &DnsResponse,
    ) {
        info!(
            event = "dns_query_success",
            query_id,
            inbound = %sanitize_field(&request.inbound_tag),
            ingress_protocol = %request.protocol.as_str(),
            query_name = %sanitize_field(query_name),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            destination = %sanitize_field(&server.destination.to_string()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            response_bytes = response.raw_message.len() as u64,
            "dns query succeeded"
        );
    }

    fn log_query_failure(
        &self,
        request: &DnsRequest,
        query_name: &str,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        err: &ProxyError,
    ) {
        warn!(
            event = "dns_query_failed",
            query_id,
            inbound = %sanitize_field(&request.inbound_tag),
            ingress_protocol = %request.protocol.as_str(),
            query_name = %sanitize_field(query_name),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            destination = %sanitize_field(&server.destination.to_string()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            error_kind = ?err.kind(),
            error = %err,
            "dns upstream receive failed"
        );
    }

    fn log_domain_resolve_start(
        &self,
        domain: &str,
        port: u16,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        context: &ResolveContext,
    ) {
        info!(
            event = "domain_resolve_start",
            query_id,
            domain = %sanitize_field(domain),
            port,
            purpose = %context.purpose.as_str(),
            recursion_depth = context.recursion_depth as u64,
            caller_outbound = %sanitize_field(context.caller_outbound_tag.as_deref().unwrap_or("")),
            caller_dns_server = %sanitize_field(context.caller_dns_server_tag.as_deref().unwrap_or("")),
            explicit_server = %sanitize_field(context.explicit_server_tag.as_deref().unwrap_or("")),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            "dial-side domain resolution started"
        );
    }

    fn log_domain_resolve_success(
        &self,
        domain: &str,
        port: u16,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        context: &ResolveContext,
        addresses: &[SocketAddr],
    ) {
        let addresses_field = addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        info!(
            event = "domain_resolve_success",
            query_id,
            domain = %sanitize_field(domain),
            port,
            purpose = %context.purpose.as_str(),
            recursion_depth = context.recursion_depth as u64,
            caller_outbound = %sanitize_field(context.caller_outbound_tag.as_deref().unwrap_or("")),
            caller_dns_server = %sanitize_field(context.caller_dns_server_tag.as_deref().unwrap_or("")),
            explicit_server = %sanitize_field(context.explicit_server_tag.as_deref().unwrap_or("")),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            resolved_addrs = %sanitize_field(&addresses_field),
            "dial-side domain resolution succeeded"
        );
    }

    fn log_domain_resolve_failure(
        &self,
        domain: &str,
        port: u16,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        context: &ResolveContext,
        err: &ProxyError,
    ) {
        warn!(
            event = "domain_resolve_failed",
            query_id,
            domain = %sanitize_field(domain),
            port,
            purpose = %context.purpose.as_str(),
            recursion_depth = context.recursion_depth as u64,
            caller_outbound = %sanitize_field(context.caller_outbound_tag.as_deref().unwrap_or("")),
            caller_dns_server = %sanitize_field(context.caller_dns_server_tag.as_deref().unwrap_or("")),
            explicit_server = %sanitize_field(context.explicit_server_tag.as_deref().unwrap_or("")),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            error_kind = ?err.kind(),
            error = %err,
            "dial-side domain resolution failed"
        );
    }
}

impl DnsExecutorHandle for DnsExecutor {
    fn execute_query(&self, request: DnsRequest) -> BoxFuture<'_, DnsResponse> {
        Box::pin(async move { self.execute_query_impl(request).await })
    }
}

impl DomainResolverHandle for DnsExecutor {
    fn resolve_host(
        &self,
        host: Host,
        port: u16,
        context: ResolveContext,
    ) -> BoxFuture<'_, Vec<SocketAddr>> {
        Box::pin(async move { self.resolve_host_impl(host, port, context).await })
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

    use tokio::net::UdpSocket;
    use tokio::sync::{mpsc, Mutex};
    use veex_core::{
        BoxedAsyncStream, Destination, DnsExecutorHandle, DnsRequest, DomainResolverHandle,
        ExecutionOutbound, Host, Logger, Network, Outbound, OutboundMeta, PacketSessionHandle,
        ProxyError, ResolveContext, SessionContext,
    };

    use crate::{
        build_a_query,
        types::{DnsRule, DnsRuntimeConfig, DnsServer, DnsServerTransport},
        upstream::{execute_local_udp_query, udp_bind_addr},
    };

    use super::{DnsExecutor, DEFAULT_DNS_QUERY_TIMEOUT, MAX_DNS_RECURSION_DEPTH};

    struct TestPacketSession {
        recv: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        sent_count: AtomicUsize,
        sent_payloads: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl veex_core::PacketSession for TestPacketSession {
        fn send_packet(&self, payload: Vec<u8>) -> veex_core::BoxFuture<'_, ()> {
            self.sent_count.fetch_add(1, Ordering::Relaxed);
            let sent_payloads = Arc::clone(&self.sent_payloads);
            Box::pin(async move {
                sent_payloads.lock().await.push(payload);
                Ok(())
            })
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
        connected_destinations: Arc<Mutex<Vec<Destination>>>,
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

    impl ExecutionOutbound for TestOutbound {
        fn open_stream(&self, _ctx: &SessionContext) -> veex_core::BoxFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("stream path unused")) })
        }

        fn open_packet(
            &self,
            ctx: &SessionContext,
        ) -> veex_core::BoxFuture<'_, PacketSessionHandle> {
            let session = Arc::clone(&self.session);
            let connected_destinations = Arc::clone(&self.connected_destinations);
            let destination = ctx.meta.destination.clone();
            Box::pin(async move {
                connected_destinations.lock().await.push(destination);
                Ok(session)
            })
        }
    }

    fn empty_test_session() -> PacketSessionHandle {
        let (_tx, rx) = mpsc::unbounded_channel();
        Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn register_test_outbound(
        registry: &mut veex_core::OutboundRegistry,
        tag: &str,
        session: PacketSessionHandle,
        connected_destinations: Arc<Mutex<Vec<Destination>>>,
    ) {
        registry
            .register(Arc::new(TestOutbound {
                meta: OutboundMeta::new(tag, "test"),
                logger: Logger::new(tag, "test"),
                session,
                connected_destinations,
            }) as Arc<dyn ExecutionOutbound>)
            .expect("test outbound should register");
    }

    #[tokio::test]
    async fn dns_executor_uses_dns_rule_and_returns_upstream_response() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(vec![0x12, 0x34]).expect("response should enqueue");
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        });
        let mut registry = veex_core::OutboundRegistry::default();
        register_test_outbound(
            &mut registry,
            "direct",
            session,
            Arc::new(Mutex::new(Vec::new())),
        );
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
                        dial: veex_core::Dial {
                            detour: Some("direct".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                    DnsServer {
                        tag: "fallback".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        dial: veex_core::Dial {
                            detour: Some("direct".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
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

    #[tokio::test]
    async fn domain_resolver_uses_explicit_server_and_parses_addresses() {
        let response = build_dns_answer_response("resolver.example.com", [203, 0, 113, 9]);
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(response).expect("response should enqueue");
        let connected_destinations = Arc::new(Mutex::new(Vec::new()));
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        });
        let mut registry = veex_core::OutboundRegistry::default();
        register_test_outbound(
            &mut registry,
            "direct",
            session,
            Arc::clone(&connected_destinations),
        );
        register_test_outbound(
            &mut registry,
            "proxy",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "remote".into(),
                servers: vec![
                    DnsServer {
                        tag: "direct".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            53,
                        ),
                        dial: veex_core::Dial {
                            detour: Some("direct".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                    DnsServer {
                        tag: "remote".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        dial: veex_core::Dial {
                            detour: Some("proxy".into()),
                            connect_timeout: None,
                            routing_mark: None,
                            domain_resolver: None,
                        },
                    },
                ],
                rules: vec![DnsRule {
                    domain: vec!["resolver.example.com".into()],
                    server_tag: "remote".into(),
                }],
            },
            Arc::new(registry),
        )
        .expect("dns executor should build");

        let addresses = executor
            .resolve_host(
                Host::Domain("resolver.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", Some("direct".into())),
            )
            .await
            .expect("domain resolver should succeed");

        assert_eq!(addresses, vec![SocketAddr::from(([203, 0, 113, 9], 443))]);
        assert_eq!(
            connected_destinations.lock().await.as_slice(),
            &[Destination::new(
                Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                53
            )]
        );
    }

    #[tokio::test]
    async fn domain_resolver_rejects_recursive_default_path_without_safe_server() {
        let mut registry = veex_core::OutboundRegistry::default();
        register_test_outbound(
            &mut registry,
            "proxy",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "remote".into(),
                servers: vec![DnsServer {
                    tag: "remote".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: veex_core::Dial {
                        detour: Some("proxy".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                rules: Vec::new(),
            },
            Arc::new(registry),
        )
        .expect("dns executor should build");

        let err = executor
            .resolve_host(
                Host::Domain("loop.example.com".into()),
                443,
                ResolveContext::outbound_dial("proxy", None),
            )
            .await
            .expect_err("recursive default resolver path should be rejected");

        assert!(err.to_string().contains("no safe dns server"));
    }

    #[tokio::test]
    async fn domain_resolver_rejects_excessive_recursion_depth() {
        let mut registry = veex_core::OutboundRegistry::default();
        register_test_outbound(
            &mut registry,
            "direct",
            empty_test_session(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "direct".into(),
                servers: vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: veex_core::Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                    },
                }],
                rules: Vec::new(),
            },
            Arc::new(registry),
        )
        .expect("dns executor should build");

        let err = executor
            .resolve_host(
                Host::Domain("depth.example.com".into()),
                443,
                ResolveContext::outbound_dial("direct", None).with_depth(MAX_DNS_RECURSION_DEPTH),
            )
            .await
            .expect_err("resolver should enforce recursion depth");

        assert!(err.to_string().contains("recursion depth exceeded"));
    }

    #[tokio::test]
    async fn local_udp_query_exchanges_standard_dns_payload() {
        let query = vec![0x12, 0x34, 0x56];
        let response = vec![0xab, 0xcd, 0xef];
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("udp server should bind");
        let addr = socket.local_addr().expect("udp server addr should resolve");
        let expected_query = query.clone();
        let expected_response = response.clone();
        let server = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let (size, peer) = socket
                .recv_from(&mut buffer)
                .await
                .expect("udp server should receive");
            assert_eq!(&buffer[..size], expected_query.as_slice());
            socket
                .send_to(&expected_response, peer)
                .await
                .expect("udp server should respond");
        });

        let result = execute_local_udp_query(addr, &query, DEFAULT_DNS_QUERY_TIMEOUT)
            .await
            .expect("local udp query should succeed");

        server.await.expect("udp server task should join");
        assert_eq!(result, response);
    }

    #[test]
    fn udp_bind_addr_matches_destination_family() {
        assert_eq!(
            udp_bind_addr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        );
        assert_eq!(
            udp_bind_addr(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
        );
    }

    fn build_dns_answer_response(domain: &str, ip: [u8; 4]) -> Vec<u8> {
        let query = build_a_query(domain, 0x1234).expect("query should build");
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&ip);
        response
    }
}
