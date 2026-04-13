use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use tokio::time::timeout;
use tracing::{info, warn};
use veex_core::{
    read_dns_tcp_message, sanitize_field, write_dns_tcp_message, BoxFuture, BoxedAsyncStream,
    Destination, DnsExecutorHandle, DnsRequest, DnsResponse, DomainResolverHandle, Host, Network,
    OutboundRegistry, ProxyError, ResolveContext, SessionContext, SessionMeta,
};
use veex_transport::{connect_tls_stream, ConnectTraceContext, TlsClientOptions};

mod http;
mod router;
mod wire;

pub use http::DEFAULT_DOH_PATH;
pub use router::{DnsRouteReason, DnsRouter, DnsRule, DnsSelection, DnsServerRouteMeta};
pub use wire::{build_a_query, parse_query_domain, parse_response_ips};

const DEFAULT_DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_RECURSION_DEPTH: u8 = 4;

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
    pub domain_resolver: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsHttpsOptions {
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub tls: TlsClientOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsServerTransport {
    Udp,
    Tcp,
    Tls(TlsClientOptions),
    Https(DnsHttpsOptions),
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
        let selection = self.router.select_client_query(&query_name);
        let server = self.lookup_server(&selection.server_tag)?;
        let query_id = self.next_query_id();

        self.log_query_start(&request, &query_name, server, &selection, query_id);

        let mut ctx = self.build_upstream_context_from_request(
            &request,
            server,
            query_id,
            &ResolveContext::client_query(),
        );
        let response = self
            .execute_server_query(&mut ctx, server, &request.raw_message, query_id)
            .await;

        match response {
            Ok(response) => {
                self.on_client_response(&query_name, &response);
                self.log_query_success(
                    &request,
                    &query_name,
                    server,
                    &selection,
                    query_id,
                    &response,
                );
                Ok(response)
            }
            Err(err) => {
                self.log_query_failure(&request, &query_name, server, &selection, query_id, &err);
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
            .select_resolution_server(&context, &self.server_route_meta())
            .ok_or_else(|| {
                ProxyError::resolve(format!(
                    "no safe dns server is available for dial-side resolution of {domain}"
                ))
            })?;
        let server = self.lookup_server(&selection.server_tag)?;
        let query_id = self.next_query_id();

        self.log_domain_resolve_start(&domain, port, server, &selection, query_id, &context);

        let query = build_a_query(&domain, query_id as u16)?;
        let upstream_context = context.for_dns_upstream_dial(
            server.detour.clone(),
            server.tag.clone(),
            server.domain_resolver.clone(),
        );
        let mut ctx =
            self.build_resolution_upstream_context(&domain, server, query_id, &upstream_context);

        let response = self
            .execute_server_query(&mut ctx, server, &query, query_id)
            .await;

        match response {
            Ok(response) => {
                let addresses = parse_response_ips(&response.raw_message)?
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect::<Vec<_>>();
                self.log_domain_resolve_success(
                    &domain, port, server, &selection, query_id, &context, &addresses,
                );
                Ok(addresses)
            }
            Err(err) => {
                self.log_domain_resolve_failure(
                    &domain, port, server, &selection, query_id, &context, &err,
                );
                Err(err)
            }
        }
    }

    fn server_route_meta(&self) -> Vec<DnsServerRouteMeta<'_>> {
        self.servers
            .values()
            .map(|server| DnsServerRouteMeta {
                tag: server.tag.as_str(),
                detour: server.detour.as_str(),
            })
            .collect()
    }

    fn lookup_server(&self, server_tag: &str) -> veex_core::Result<&DnsServer> {
        self.servers
            .get(server_tag)
            .ok_or_else(|| ProxyError::config(format!("missing dns server tag: {server_tag}")))
    }

    fn build_upstream_context_from_request(
        &self,
        request: &DnsRequest,
        server: &DnsServer,
        query_id: u64,
        resolve_context: &ResolveContext,
    ) -> SessionContext {
        let mut ctx = SessionContext::new(
            SessionMeta {
                id: query_id,
                network: upstream_network(&server.transport),
                inbound_tag: request.inbound_tag.clone(),
                peer: request.peer,
                destination: server.destination.clone(),
                start: Instant::now(),
            },
            Vec::new(),
        );
        ctx.set_resolve_context(Some(resolve_context.for_dns_upstream_dial(
            server.detour.clone(),
            server.tag.clone(),
            server.domain_resolver.clone(),
        )));
        ctx
    }

    fn build_resolution_upstream_context(
        &self,
        domain: &str,
        server: &DnsServer,
        query_id: u64,
        resolve_context: &ResolveContext,
    ) -> SessionContext {
        let mut ctx = SessionContext::new(
            SessionMeta {
                id: query_id,
                network: upstream_network(&server.transport),
                inbound_tag: "dns-resolver".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 0)),
                destination: server.destination.clone(),
                start: Instant::now(),
            },
            Vec::new(),
        );
        ctx.set_resolve_context(Some(resolve_context.clone()));
        ctx.state.buffered_payload = domain.as_bytes().to_vec();
        ctx
    }

    async fn execute_server_query(
        &self,
        ctx: &mut SessionContext,
        server: &DnsServer,
        query: &[u8],
        query_id: u64,
    ) -> veex_core::Result<DnsResponse> {
        match &server.transport {
            DnsServerTransport::Udp => {
                self.execute_udp_query(ctx, &server.detour, query, query_id)
                    .await
            }
            DnsServerTransport::Tcp => self.execute_tcp_query(ctx, &server.detour, query).await,
            DnsServerTransport::Tls(tls) => {
                self.execute_tls_query(ctx, server, tls, query, query_id)
                    .await
            }
            DnsServerTransport::Https(options) => {
                self.execute_https_query(ctx, server, options, query, query_id)
                    .await
            }
            DnsServerTransport::Unsupported(kind) => Err(ProxyError::protocol(format!(
                "dns server '{}' uses unsupported upstream type '{}'",
                server.tag, kind
            ))),
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
    ) -> veex_core::Result<DnsResponse> {
        let mut stream = self.connect_detour_stream(ctx, detour).await?;
        self.exchange_dns_over_stream(&mut *stream, query).await
    }

    async fn execute_tls_query(
        &self,
        ctx: &SessionContext,
        server: &DnsServer,
        tls: &TlsClientOptions,
        query: &[u8],
        query_id: u64,
    ) -> veex_core::Result<DnsResponse> {
        let stream = self.connect_detour_stream(ctx, &server.detour).await?;
        let mut stream = self
            .connect_tls_for_dns(stream, &server.destination, &server.detour, tls, query_id)
            .await?;
        self.exchange_dns_over_stream(&mut *stream, query).await
    }

    async fn execute_https_query(
        &self,
        ctx: &SessionContext,
        server: &DnsServer,
        options: &DnsHttpsOptions,
        query: &[u8],
        query_id: u64,
    ) -> veex_core::Result<DnsResponse> {
        let stream = self.connect_detour_stream(ctx, &server.detour).await?;
        let mut stream = self
            .connect_tls_for_dns(
                stream,
                &server.destination,
                &server.detour,
                &options.tls,
                query_id,
            )
            .await?;

        let host_header = options
            .tls
            .server_name
            .clone()
            .unwrap_or_else(|| server.destination.host.to_string());
        let path_field = sanitize_field(&options.path).into_owned();
        info!(
            event = "dns_https_exchange_start",
            query_id,
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(&server.detour),
            path = %path_field,
            "dns https exchange started"
        );
        http::write_doh_http1_request(
            &mut *stream,
            &host_header,
            &options.path,
            &options.headers,
            query,
        )
        .await?;
        let response = match timeout(
            self.query_timeout,
            http::read_doh_http1_response(&mut *stream),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(ProxyError::timeout(format!(
                    "dns upstream response timeout after {} ms",
                    self.query_timeout.as_millis()
                )));
            }
        };
        info!(
            event = "dns_https_exchange_success",
            query_id,
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(&server.detour),
            path = %path_field,
            response_bytes = response.len() as u64,
            "dns https exchange succeeded"
        );
        Ok(DnsResponse::new(response))
    }

    async fn connect_detour_stream(
        &self,
        ctx: &SessionContext,
        detour: &str,
    ) -> veex_core::Result<BoxedAsyncStream> {
        let outbound = self.outbounds.get(detour).ok_or_else(|| {
            ProxyError::config(format!("missing outbound tag for dns detour: {detour}"))
        })?;
        outbound.connect(ctx).await
    }

    async fn connect_tls_for_dns(
        &self,
        stream: BoxedAsyncStream,
        destination: &Destination,
        detour: &str,
        tls: &TlsClientOptions,
        query_id: u64,
    ) -> veex_core::Result<BoxedAsyncStream> {
        let trace = ConnectTraceContext {
            session_id: query_id,
            outbound: detour.to_string(),
            routing_mark: None,
        };
        connect_tls_stream(
            stream,
            &destination.host,
            destination.port,
            tls,
            Some(&trace),
        )
        .await
    }

    async fn exchange_dns_over_stream(
        &self,
        stream: &mut dyn veex_core::AsyncStream,
        query: &[u8],
    ) -> veex_core::Result<DnsResponse> {
        write_dns_tcp_message(stream, query).await?;
        let response = timeout(self.query_timeout, read_dns_tcp_message(stream)).await;
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
            detour = %sanitize_field(&server.detour),
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
            detour = %sanitize_field(&server.detour),
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
            detour = %sanitize_field(&server.detour),
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
            detour = %sanitize_field(&server.detour),
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
            detour = %sanitize_field(&server.detour),
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
            detour = %sanitize_field(&server.detour),
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

impl DnsServerTransport {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls(_) => "tls",
            Self::Https(_) => "https",
            Self::Unsupported(kind) => kind.as_str(),
        }
    }
}

fn upstream_network(transport: &DnsServerTransport) -> Network {
    match transport {
        DnsServerTransport::Udp => Network::Udp,
        DnsServerTransport::Tcp
        | DnsServerTransport::Tls(_)
        | DnsServerTransport::Https(_)
        | DnsServerTransport::Unsupported(_) => Network::Tcp,
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
        BoxedAsyncStream, Destination, DnsExecutorHandle, DnsRequest, DomainResolverHandle, Host,
        Logger, Network, Outbound, OutboundConnector, OutboundMeta, PacketSessionHandle,
        ProxyError, ResolveContext, SessionContext,
    };

    use super::{
        build_a_query, DnsExecutor, DnsRule, DnsRuntimeConfig, DnsServer, DnsServerTransport,
        MAX_DNS_RECURSION_DEPTH,
    };

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

    impl OutboundConnector for TestOutbound {
        fn connect(&self, _ctx: &SessionContext) -> veex_core::BoxFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("stream path unused")) })
        }

        fn connect_packet(
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

    #[tokio::test]
    async fn dns_executor_uses_dns_rule_and_returns_upstream_response() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(vec![0x12, 0x34]).expect("response should enqueue");
        let session: PacketSessionHandle = Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        });
        let outbound = Arc::new(TestOutbound {
            meta: OutboundMeta::new("direct", "test"),
            logger: Logger::new("direct", "test"),
            session,
            connected_destinations: Arc::new(Mutex::new(Vec::new())),
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
                        domain_resolver: None,
                    },
                    DnsServer {
                        tag: "fallback".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        detour: "direct".into(),
                        domain_resolver: None,
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
        let outbound = Arc::new(TestOutbound {
            meta: OutboundMeta::new("direct", "test"),
            logger: Logger::new("direct", "test"),
            session,
            connected_destinations: Arc::clone(&connected_destinations),
        });
        let mut registry = veex_core::OutboundRegistry::default();
        registry
            .register(outbound as Arc<dyn OutboundConnector>)
            .expect("test outbound should register");
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
                        detour: "direct".into(),
                        domain_resolver: None,
                    },
                    DnsServer {
                        tag: "remote".into(),
                        transport: DnsServerTransport::Udp,
                        destination: Destination::new(
                            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            54,
                        ),
                        detour: "proxy".into(),
                        domain_resolver: None,
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
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "remote".into(),
                servers: vec![DnsServer {
                    tag: "remote".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    detour: "proxy".into(),
                    domain_resolver: None,
                }],
                rules: Vec::new(),
            },
            Arc::new(veex_core::OutboundRegistry::default()),
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
        let executor = DnsExecutor::new(
            DnsRuntimeConfig {
                final_server_tag: "direct".into(),
                servers: vec![DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    detour: "direct".into(),
                    domain_resolver: None,
                }],
                rules: Vec::new(),
            },
            Arc::new(veex_core::OutboundRegistry::default()),
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
