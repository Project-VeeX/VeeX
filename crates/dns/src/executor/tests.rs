use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::{Mutex, mpsc};
use veex_core::{
    ProxyError,
    dns::{DnsExecutorHandle, DnsRequest, DomainResolverHandle, ResolveContext},
    io::{BoxedAsyncStream, PacketSession, PacketSessionHandle},
    logging::Logger,
    portal::{BoxFuture, Dial, Outbound, OutboundMeta},
    session::SessionContext,
    types::{Destination, Host, Network},
};
use veex_execution::{ExecutionFuture, ExecutionOutbound, OutboundCatalog};
use veex_test_tracing::{assert_has_event, captured_events, install_test_subscriber};

use crate::{
    DEFAULT_DNS_CACHE_CAPACITY, build_a_query, parse_response_ips,
    types::{DnsRule, DnsRuntimeConfig, DnsServer, DnsServerTransport},
};

use super::{DnsExecutor, MAX_DNS_RECURSION_DEPTH};

struct TestPacketSession {
    recv: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    sent_count: AtomicUsize,
    sent_payloads: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PacketSession for TestPacketSession {
    fn send_packet(&self, payload: Vec<u8>) -> BoxFuture<'_, ()> {
        self.sent_count.fetch_add(1, Ordering::Relaxed);
        let sent_payloads = Arc::clone(&self.sent_payloads);
        Box::pin(async move {
            sent_payloads.lock().await.push(payload);
            Ok(())
        })
    }

    fn recv_packet(&self) -> BoxFuture<'_, Vec<u8>> {
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

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

impl ExecutionOutbound for TestOutbound {
    fn tag(&self) -> &str {
        &self.meta.tag
    }

    fn open_stream(&self, _ctx: &SessionContext) -> ExecutionFuture<'_, BoxedAsyncStream> {
        Box::pin(async { Err(ProxyError::protocol("stream path unused")) })
    }

    fn open_packet(&self, ctx: &SessionContext) -> ExecutionFuture<'_, PacketSessionHandle> {
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

fn queued_test_session(responses: Vec<Vec<u8>>) -> Arc<TestPacketSession> {
    let (tx, rx) = mpsc::unbounded_channel();
    for response in responses {
        tx.send(response).expect("response should enqueue");
    }
    drop(tx);
    Arc::new(TestPacketSession {
        recv: Mutex::new(rx),
        sent_count: AtomicUsize::new(0),
        sent_payloads: Arc::new(Mutex::new(Vec::new())),
    })
}

fn parked_test_session() -> (Arc<TestPacketSession>, mpsc::UnboundedSender<Vec<u8>>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (
        Arc::new(TestPacketSession {
            recv: Mutex::new(rx),
            sent_count: AtomicUsize::new(0),
            sent_payloads: Arc::new(Mutex::new(Vec::new())),
        }),
        tx,
    )
}

fn register_test_outbound(
    registry: &mut Vec<Arc<dyn ExecutionOutbound>>,
    tag: &str,
    session: PacketSessionHandle,
    connected_destinations: Arc<Mutex<Vec<Destination>>>,
) -> Arc<dyn ExecutionOutbound> {
    let outbound = Arc::new(TestOutbound {
        meta: OutboundMeta::new(tag, "test"),
        logger: Logger::new(tag, "test"),
        session,
        connected_destinations,
    }) as Arc<dyn ExecutionOutbound>;
    registry.push(Arc::clone(&outbound));
    outbound
}

fn finalize_catalog(
    builder: Vec<Arc<dyn ExecutionOutbound>>,
    default_outbound: Arc<dyn ExecutionOutbound>,
) -> Arc<OutboundCatalog> {
    let outbounds = builder
        .into_iter()
        .map(|outbound| (outbound.tag().to_string(), outbound))
        .collect();
    Arc::new(OutboundCatalog::new(outbounds, default_outbound))
}

fn register_default_test_outbound(
    registry: &mut Vec<Arc<dyn ExecutionOutbound>>,
    tag: &str,
    session: PacketSessionHandle,
    connected_destinations: Arc<Mutex<Vec<Destination>>>,
) -> Arc<dyn ExecutionOutbound> {
    register_test_outbound(registry, tag, session, connected_destinations)
}

fn dns_runtime_config(
    final_server_tag: &str,
    servers: Vec<DnsServer>,
    rules: Vec<DnsRule>,
) -> DnsRuntimeConfig {
    DnsRuntimeConfig {
        final_server_tag: final_server_tag.into(),
        disable_cache: false,
        cache_capacity: DEFAULT_DNS_CACHE_CAPACITY,
        servers,
        rules,
    }
}

fn dns_query_request(domain: &str, id: u16) -> DnsRequest {
    DnsRequest::new(
        build_a_query(domain, id).expect("query should build"),
        Network::Udp,
        "dns-in",
        SocketAddr::from(([127, 0, 0, 1], 53000)),
        Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353),
    )
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
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        session,
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        DnsRuntimeConfig {
            final_server_tag: "fallback".into(),
            disable_cache: false,
            cache_capacity: 4096,
            servers: vec![
                DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
                DnsServer {
                    tag: "fallback".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 54),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
            ],
            rules: vec![DnsRule {
                domain: vec!["trojan.example.com".into()],
                server_tag: "direct".into(),
                disable_cache: false,
            }],
        },
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let response = executor
        .execute_query(DnsRequest::new(
            vec![
                0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b't',
                b'r', b'o', b'j', b'a', b'n', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03,
                b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
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
async fn dns_executor_cache_hit_avoids_second_upstream_exchange() {
    let session = queued_test_session(vec![build_dns_answer_response_with_id(
        "cache.example.com",
        [203, 0, 113, 20],
        60,
        0x1001,
    )]);
    let session_handle: PacketSessionHandle = session.clone();
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        session_handle,
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        dns_runtime_config(
            "direct",
            vec![DnsServer {
                tag: "direct".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("direct".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            Vec::new(),
        ),
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let _first = executor
        .execute_query(dns_query_request("cache.example.com", 0x1001))
        .await
        .expect("first query should succeed");
    let second = executor
        .execute_query(dns_query_request("cache.example.com", 0x1002))
        .await
        .expect("second query should hit cache");

    assert_eq!(session.sent_count.load(Ordering::Relaxed), 1);
    assert_eq!(&second.raw_message[..2], &[0x10, 0x02]);
    assert_eq!(
        parse_response_ips(&second.raw_message).expect("cached response should remain usable"),
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20))]
    );
}

#[tokio::test]
async fn dns_executor_expired_cache_triggers_new_upstream_exchange() {
    let session = queued_test_session(vec![
        build_dns_answer_response_with_ttl("expire.example.com", [203, 0, 113, 21], 1),
        build_dns_answer_response_with_ttl("expire.example.com", [203, 0, 113, 22], 60),
    ]);
    let session_handle: PacketSessionHandle = session.clone();
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        session_handle,
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        dns_runtime_config(
            "direct",
            vec![DnsServer {
                tag: "direct".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("direct".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            Vec::new(),
        ),
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    executor
        .execute_query(dns_query_request("expire.example.com", 0x2001))
        .await
        .expect("first query should succeed");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let refreshed = executor
        .execute_query(dns_query_request("expire.example.com", 0x2002))
        .await
        .expect("expired cache should trigger refresh");

    assert_eq!(session.sent_count.load(Ordering::Relaxed), 2);
    assert_eq!(
        parse_response_ips(&refreshed.raw_message).expect("refreshed response should parse"),
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 22))]
    );
}

#[tokio::test]
async fn dns_rule_disable_cache_bypasses_cache() {
    let session = queued_test_session(vec![
        build_dns_answer_response("bypass.example.com", [203, 0, 113, 30]),
        build_dns_answer_response("bypass.example.com", [203, 0, 113, 30]),
    ]);
    let session_handle: PacketSessionHandle = session.clone();
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        session_handle,
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        dns_runtime_config(
            "direct",
            vec![DnsServer {
                tag: "direct".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("direct".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            vec![DnsRule {
                domain: vec!["bypass.example.com".into()],
                server_tag: "direct".into(),
                disable_cache: true,
            }],
        ),
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    executor
        .execute_query(dns_query_request("bypass.example.com", 0x3001))
        .await
        .expect("first query should succeed");
    executor
        .execute_query(dns_query_request("bypass.example.com", 0x3002))
        .await
        .expect("second query should also hit upstream");

    assert_eq!(session.sent_count.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn dns_executor_emits_cache_lifecycle_events() {
    let (_guard, trace_buffer) = install_test_subscriber();
    let session = queued_test_session(vec![build_dns_answer_response(
        "trace-cache.example.com",
        [203, 0, 113, 60],
    )]);
    let session_handle: PacketSessionHandle = session.clone();
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        session_handle,
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        dns_runtime_config(
            "direct",
            vec![DnsServer {
                tag: "direct".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("direct".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            Vec::new(),
        ),
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    executor
        .execute_query(dns_query_request("trace-cache.example.com", 0x4001))
        .await
        .expect("first query should succeed");
    executor
        .execute_query(dns_query_request("trace-cache.example.com", 0x4002))
        .await
        .expect("second query should hit cache");

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "dns_cache_miss",
        &[
            ("query_kind", "client_query"),
            ("query_name", "trace-cache.example.com"),
        ],
    );
    assert_has_event(
        &events,
        "dns_cache_store",
        &[("query_kind", "client_query"), ("winner_server", "direct")],
    );
    assert_has_event(
        &events,
        "dns_cache_hit",
        &[("query_kind", "client_query"), ("winner_server", "direct")],
    );
    assert_has_event(
        &events,
        "dns_query_finish",
        &[
            ("query_name", "trace-cache.example.com"),
            ("cache_hit", "true"),
        ],
    );
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
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
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
            disable_cache: false,
            cache_capacity: 4096,
            servers: vec![
                DnsServer {
                    tag: "direct".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
                DnsServer {
                    tag: "remote".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 54),
                    dial: Dial {
                        detour: Some("proxy".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
            ],
            rules: vec![DnsRule {
                domain: vec!["resolver.example.com".into()],
                server_tag: "remote".into(),
                disable_cache: false,
            }],
        },
        finalize_catalog(registry, default_outbound),
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
async fn domain_resolver_cache_hit_avoids_second_exchange() {
    let session = queued_test_session(vec![build_dns_answer_response(
        "resolve-cache.example.com",
        [203, 0, 113, 40],
    )]);
    let session_handle: PacketSessionHandle = session.clone();
    let connected_destinations = Arc::new(Mutex::new(Vec::new()));
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        session_handle,
        Arc::clone(&connected_destinations),
    );
    let executor = DnsExecutor::new(
        dns_runtime_config(
            "direct",
            vec![DnsServer {
                tag: "direct".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("direct".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            Vec::new(),
        ),
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let first = executor
        .resolve_host(
            Host::Domain("resolve-cache.example.com".into()),
            443,
            ResolveContext::outbound_dial("proxy", None),
        )
        .await
        .expect("first resolve should succeed");
    let second = executor
        .resolve_host(
            Host::Domain("resolve-cache.example.com".into()),
            443,
            ResolveContext::outbound_dial("proxy", None),
        )
        .await
        .expect("second resolve should hit cache");

    assert_eq!(session.sent_count.load(Ordering::Relaxed), 1);
    assert_eq!(first, second);
    assert_eq!(connected_destinations.lock().await.len(), 1);
}

#[tokio::test]
async fn domain_resolver_disable_cache_bypasses_cache() {
    let session = queued_test_session(vec![
        build_dns_answer_response("resolve-bypass.example.com", [203, 0, 113, 41]),
        build_dns_answer_response("resolve-bypass.example.com", [203, 0, 113, 41]),
    ]);
    let session_handle: PacketSessionHandle = session.clone();
    let connected_destinations = Arc::new(Mutex::new(Vec::new()));
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        session_handle,
        Arc::clone(&connected_destinations),
    );
    let executor = DnsExecutor::new(
        dns_runtime_config(
            "direct",
            vec![DnsServer {
                tag: "direct".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("direct".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            Vec::new(),
        ),
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let context = ResolveContext::outbound_dial("proxy", None).with_disable_cache(true);
    executor
        .resolve_host(
            Host::Domain("resolve-bypass.example.com".into()),
            443,
            context.clone(),
        )
        .await
        .expect("first resolve should succeed");
    executor
        .resolve_host(
            Host::Domain("resolve-bypass.example.com".into()),
            443,
            context,
        )
        .await
        .expect("second resolve should bypass cache");

    assert_eq!(session.sent_count.load(Ordering::Relaxed), 2);
    assert_eq!(connected_destinations.lock().await.len(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_resolution_uses_first_success_and_cancels_loser() {
    let (remote_session, _remote_tx) = parked_test_session();
    let remote_handle: PacketSessionHandle = remote_session.clone();
    let bootstrap_session = queued_test_session(vec![build_dns_answer_response(
        "concurrent.example.com",
        [203, 0, 113, 50],
    )]);
    let bootstrap_handle: PacketSessionHandle = bootstrap_session.clone();
    let mut registry = Vec::new();
    let direct_connected_destinations = Arc::new(Mutex::new(Vec::new()));
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        bootstrap_handle.clone(),
        Arc::clone(&direct_connected_destinations),
    );
    let dns_egress_connected_destinations = Arc::new(Mutex::new(Vec::new()));
    register_test_outbound(
        &mut registry,
        "dns-egress",
        remote_handle,
        Arc::clone(&dns_egress_connected_destinations),
    );
    register_test_outbound(
        &mut registry,
        "proxy",
        empty_test_session(),
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        dns_runtime_config(
            "remote",
            vec![
                DnsServer {
                    tag: "remote".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("dns-egress".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
                DnsServer {
                    tag: "bootstrap".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 54),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
            ],
            Vec::new(),
        ),
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let addresses = executor
        .resolve_host(
            Host::Domain("concurrent.example.com".into()),
            443,
            ResolveContext::outbound_dial("proxy", None),
        )
        .await
        .expect("concurrent resolution should succeed");

    assert_eq!(addresses, vec![SocketAddr::from(([203, 0, 113, 50], 443))]);
    assert_eq!(bootstrap_session.sent_count.load(Ordering::Relaxed), 1);
    assert_eq!(remote_session.sent_count.load(Ordering::Relaxed), 1);
    assert_eq!(
        direct_connected_destinations.lock().await.as_slice(),
        &[Destination::new(
            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            54
        )]
    );
    let remote_destinations = dns_egress_connected_destinations.lock().await;
    assert!(
        remote_destinations.len() <= 1,
        "losing upstream should not open more than one packet destination"
    );
}

#[tokio::test]
async fn concurrent_resolution_returns_clear_all_failed_error() {
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        empty_test_session(),
        Arc::new(Mutex::new(Vec::new())),
    );
    register_test_outbound(
        &mut registry,
        "dns-egress",
        empty_test_session(),
        Arc::new(Mutex::new(Vec::new())),
    );
    register_test_outbound(
        &mut registry,
        "proxy",
        empty_test_session(),
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        dns_runtime_config(
            "remote",
            vec![
                DnsServer {
                    tag: "remote".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("dns-egress".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
                DnsServer {
                    tag: "bootstrap".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 54),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
            ],
            Vec::new(),
        ),
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let err = executor
        .resolve_host(
            Host::Domain("all-failed.example.com".into()),
            443,
            ResolveContext::outbound_dial("proxy", None),
        )
        .await
        .expect_err("all candidates should fail");

    assert!(err.to_string().contains(
        "all dns upstream queries failed for dial_side_resolve 'all-failed.example.com'"
    ));
    assert!(err.to_string().contains("[remote,bootstrap]"));
}

#[tokio::test]
async fn domain_resolver_rejects_recursive_default_path_without_safe_server() {
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "proxy",
        empty_test_session(),
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        DnsRuntimeConfig {
            final_server_tag: "remote".into(),
            disable_cache: false,
            cache_capacity: 4096,
            servers: vec![DnsServer {
                tag: "remote".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("proxy".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            rules: Vec::new(),
        },
        finalize_catalog(registry, default_outbound),
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
async fn domain_resolver_uses_safe_final_server_when_allowed() {
    let response = build_dns_answer_response("safe-final.example.com", [203, 0, 113, 10]);
    let (tx, rx) = mpsc::unbounded_channel();
    tx.send(response).expect("response should enqueue");
    let connected_destinations = Arc::new(Mutex::new(Vec::new()));
    let session: PacketSessionHandle = Arc::new(TestPacketSession {
        recv: Mutex::new(rx),
        sent_count: AtomicUsize::new(0),
        sent_payloads: Arc::new(Mutex::new(Vec::new())),
    });
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        empty_test_session(),
        Arc::new(Mutex::new(Vec::new())),
    );
    register_test_outbound(
        &mut registry,
        "dns-egress",
        session,
        Arc::clone(&connected_destinations),
    );
    let executor = DnsExecutor::new(
        DnsRuntimeConfig {
            final_server_tag: "remote".into(),
            disable_cache: false,
            cache_capacity: 4096,
            servers: vec![
                DnsServer {
                    tag: "remote".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 54),
                    dial: Dial {
                        detour: Some("dns-egress".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
                DnsServer {
                    tag: "bootstrap".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
            ],
            rules: Vec::new(),
        },
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let addresses = executor
        .resolve_host(
            Host::Domain("safe-final.example.com".into()),
            443,
            ResolveContext::outbound_dial("proxy", None),
        )
        .await
        .expect("domain resolver should use safe final server");

    assert_eq!(addresses, vec![SocketAddr::from(([203, 0, 113, 10], 443))]);
    assert_eq!(
        connected_destinations.lock().await.as_slice(),
        &[Destination::new(
            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            54
        )]
    );
}

#[tokio::test]
async fn domain_resolver_skips_caller_dns_server_and_uses_safe_fallback() {
    let response = build_dns_answer_response("fallback.example.com", [203, 0, 113, 11]);
    let (tx, rx) = mpsc::unbounded_channel();
    tx.send(response).expect("response should enqueue");
    let connected_destinations = Arc::new(Mutex::new(Vec::new()));
    let session: PacketSessionHandle = Arc::new(TestPacketSession {
        recv: Mutex::new(rx),
        sent_count: AtomicUsize::new(0),
        sent_payloads: Arc::new(Mutex::new(Vec::new())),
    });
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
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
            disable_cache: false,
            cache_capacity: 4096,
            servers: vec![
                DnsServer {
                    tag: "remote".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 54),
                    dial: Dial {
                        detour: Some("proxy".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
                DnsServer {
                    tag: "bootstrap".into(),
                    transport: DnsServerTransport::Udp,
                    destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                    dial: Dial {
                        detour: Some("direct".into()),
                        connect_timeout: None,
                        routing_mark: None,
                        domain_resolver: None,
                        ..Dial::default()
                    },
                },
            ],
            rules: Vec::new(),
        },
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let addresses = executor
        .resolve_host(
            Host::Domain("fallback.example.com".into()),
            443,
            ResolveContext {
                purpose: veex_core::dns::ResolvePurpose::DnsUpstreamDial,
                caller_outbound_tag: Some("proxy".into()),
                caller_dns_server_tag: Some("remote".into()),
                explicit_server_tag: None,
                disable_cache: false,
                recursion_depth: 1,
            },
        )
        .await
        .expect("domain resolver should skip caller dns server");

    assert_eq!(addresses, vec![SocketAddr::from(([203, 0, 113, 11], 443))]);
    assert_eq!(
        connected_destinations.lock().await.as_slice(),
        &[Destination::new(
            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53
        )]
    );
}

#[tokio::test]
async fn domain_resolver_rejects_missing_explicit_server() {
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        empty_test_session(),
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        DnsRuntimeConfig {
            final_server_tag: "direct".into(),
            disable_cache: false,
            cache_capacity: 4096,
            servers: vec![DnsServer {
                tag: "direct".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("direct".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            rules: Vec::new(),
        },
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let err = executor
        .resolve_host(
            Host::Domain("missing.example.com".into()),
            443,
            ResolveContext::outbound_dial("proxy", Some("missing".into())),
        )
        .await
        .expect_err("missing explicit resolver should fail");

    assert!(
        err.to_string()
            .contains("explicit domain_resolver points to missing dns server tag: missing")
    );
}

#[tokio::test]
async fn domain_resolver_rejects_empty_answer_response() {
    let response = build_dns_empty_response("empty.example.com");
    let (tx, rx) = mpsc::unbounded_channel();
    tx.send(response).expect("response should enqueue");
    let connected_destinations = Arc::new(Mutex::new(Vec::new()));
    let session: PacketSessionHandle = Arc::new(TestPacketSession {
        recv: Mutex::new(rx),
        sent_count: AtomicUsize::new(0),
        sent_payloads: Arc::new(Mutex::new(Vec::new())),
    });
    let mut registry = Vec::new();
    let default_outbound =
        register_default_test_outbound(&mut registry, "direct", session, connected_destinations);
    let executor = DnsExecutor::new(
        DnsRuntimeConfig {
            final_server_tag: "direct".into(),
            disable_cache: false,
            cache_capacity: 4096,
            servers: vec![DnsServer {
                tag: "direct".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("direct".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            rules: Vec::new(),
        },
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let err = executor
        .resolve_host(
            Host::Domain("empty.example.com".into()),
            443,
            ResolveContext::outbound_dial("proxy", None),
        )
        .await
        .expect_err("empty response should fail resolution");

    assert!(
        err.to_string()
            .contains("dns response did not contain usable A/AAAA answers")
    );
}

#[tokio::test]
async fn domain_resolver_propagates_upstream_exchange_failure() {
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        empty_test_session(),
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        DnsRuntimeConfig {
            final_server_tag: "direct".into(),
            disable_cache: false,
            cache_capacity: 4096,
            servers: vec![DnsServer {
                tag: "direct".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("direct".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            rules: Vec::new(),
        },
        finalize_catalog(registry, default_outbound),
    )
    .expect("dns executor should build");

    let err = executor
        .resolve_host(
            Host::Domain("failure.example.com".into()),
            443,
            ResolveContext::outbound_dial("proxy", None),
        )
        .await
        .expect_err("upstream exchange failure should surface");

    assert!(err.to_string().contains("test packet session closed"));
}

#[tokio::test]
async fn domain_resolver_rejects_excessive_recursion_depth() {
    let mut registry = Vec::new();
    let default_outbound = register_default_test_outbound(
        &mut registry,
        "direct",
        empty_test_session(),
        Arc::new(Mutex::new(Vec::new())),
    );
    let executor = DnsExecutor::new(
        DnsRuntimeConfig {
            final_server_tag: "direct".into(),
            disable_cache: false,
            cache_capacity: 4096,
            servers: vec![DnsServer {
                tag: "direct".into(),
                transport: DnsServerTransport::Udp,
                destination: Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53),
                dial: Dial {
                    detour: Some("direct".into()),
                    connect_timeout: None,
                    routing_mark: None,
                    domain_resolver: None,
                    ..Dial::default()
                },
            }],
            rules: Vec::new(),
        },
        finalize_catalog(registry, default_outbound),
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

#[test]
fn local_dns_executor_builds_with_default_outbound() {
    let default_outbound = Arc::new(TestOutbound {
        meta: OutboundMeta::new("direct", "test"),
        logger: Logger::new("direct", "test"),
        session: empty_test_session(),
        connected_destinations: Arc::new(Mutex::new(Vec::new())),
    }) as Arc<dyn ExecutionOutbound>;
    let executor = DnsExecutor::new(
        DnsRuntimeConfig {
            final_server_tag: "local".into(),
            disable_cache: false,
            cache_capacity: 4096,
            servers: vec![DnsServer {
                tag: "local".into(),
                transport: DnsServerTransport::Local,
                destination: Destination::new(Host::Domain("local".into()), 53),
                dial: Dial::default(),
            }],
            rules: Vec::new(),
        },
        Arc::new(OutboundCatalog::new(HashMap::new(), default_outbound)),
    );

    assert!(executor.is_ok());
}

fn build_dns_answer_response(domain: &str, ip: [u8; 4]) -> Vec<u8> {
    build_dns_answer_response_with_id(domain, ip, 60, 0x1234)
}

fn build_dns_answer_response_with_ttl(domain: &str, ip: [u8; 4], ttl_secs: u32) -> Vec<u8> {
    build_dns_answer_response_with_id(domain, ip, ttl_secs, 0x1234)
}

fn build_dns_answer_response_with_id(
    domain: &str,
    ip: [u8; 4],
    ttl_secs: u32,
    query_id: u16,
) -> Vec<u8> {
    let query = build_a_query(domain, query_id).expect("query should build");
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
    response.extend_from_slice(&ttl_secs.to_be_bytes());
    response.extend_from_slice(&4u16.to_be_bytes());
    response.extend_from_slice(&ip);
    response
}

fn build_dns_empty_response(domain: &str) -> Vec<u8> {
    let query = build_a_query(domain, 0x1234).expect("query should build");
    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&query[12..]);
    response
}
