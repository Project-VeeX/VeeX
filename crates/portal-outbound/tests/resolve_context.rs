use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use veex_core::{
    ProxyError,
    dns::ResolveContext,
    logging::Logger,
    portal::{Dial, DialContext, OutboundMeta, ProxyOutbound, StreamOutbound},
    session::{SessionContext, SessionMeta},
    types::{Destination, Host, Network},
};
use veex_portal_outbound::{
    DirectOutbound, TrojanOutbound,
    direct::{
        build_dialer as build_direct_dialer,
        build_dialer_with_connector as build_direct_dialer_with_connector,
        build_packet_dialer_with_connector,
    },
    trojan::{
        build_dialer as build_trojan_dialer,
        build_dialer_with_connector as build_trojan_dialer_with_connector,
    },
};
use veex_test_tracing::{assert_has_event, captured_events, install_test_subscriber};
use veex_transport::{HostResolveRequest, HostResolver, OutboundTls};

type TcpConnectFuture =
    Pin<Box<dyn Future<Output = io::Result<tokio::net::TcpStream>> + Send + 'static>>;
type UdpConnectFuture =
    Pin<Box<dyn Future<Output = io::Result<tokio::net::UdpSocket>> + Send + 'static>>;
type MarkedTcpConnector = Arc<dyn Fn(SocketAddr, u32) -> TcpConnectFuture + Send + Sync>;
type MarkedUdpConnector = Arc<dyn Fn(SocketAddr, u32) -> UdpConnectFuture + Send + Sync>;
type TcpConnector = Arc<dyn Fn(SocketAddr) -> TcpConnectFuture + Send + Sync>;

fn capture_contexts(store: Arc<Mutex<Vec<ResolveContext>>>) -> Arc<HostResolver> {
    Arc::new(move |request: HostResolveRequest| {
        let store = Arc::clone(&store);
        Box::pin(async move {
            store
                .lock()
                .expect("context store should lock")
                .push(request.context);
            Err(ProxyError::resolve("stop after capturing resolve context"))
        })
    })
}

#[tokio::test]
async fn direct_and_trojan_build_the_same_fresh_resolve_context() {
    let direct_contexts = Arc::new(Mutex::new(Vec::new()));
    let trojan_contexts = Arc::new(Mutex::new(Vec::new()));
    let direct = build_direct_dialer(
        Dial {
            domain_resolver: Some("bootstrap".into()),
            ..Dial::default()
        },
        capture_contexts(Arc::clone(&direct_contexts)),
    )
    .expect("direct dialer should build");
    let trojan = build_trojan_dialer(
        Dial {
            domain_resolver: Some("bootstrap".into()),
            ..Dial::default()
        },
        capture_contexts(Arc::clone(&trojan_contexts)),
    );
    let dial_context = DialContext {
        session_id: 7,
        outbound_tag: "shared-outbound".into(),
        resolve_context: None,
    };

    let direct_err = direct
        .connect(
            &Host::Domain("example.com".into()),
            443,
            dial_context.clone(),
        )
        .await
        .expect_err("test resolver should stop direct dialer");
    let trojan_err = trojan
        .connect(&Host::Domain("example.com".into()), 443, dial_context)
        .await
        .expect_err("test resolver should stop trojan dialer");

    assert!(direct_err.to_string().contains("capturing resolve context"));
    assert!(trojan_err.to_string().contains("capturing resolve context"));
    assert_eq!(
        direct_contexts
            .lock()
            .expect("direct contexts should lock")
            .as_slice(),
        &[ResolveContext::outbound_dial(
            "shared-outbound",
            Some("bootstrap".into())
        )]
    );
    assert_eq!(
        trojan_contexts
            .lock()
            .expect("trojan contexts should lock")
            .as_slice(),
        &[ResolveContext::outbound_dial(
            "shared-outbound",
            Some("bootstrap".into())
        )]
    );
}

fn test_stream_session(destination: Destination) -> SessionContext {
    SessionContext::new(
        SessionMeta {
            id: 21,
            network: Network::Tcp,
            inbound_tag: "socks-in".into(),
            peer: SocketAddr::from(([127, 0, 0, 1], 40010)),
            destination,
            start: Instant::now(),
        },
        Vec::new(),
    )
}

fn panic_marked_connector() -> MarkedTcpConnector {
    Arc::new(|_address, _routing_mark| Box::pin(async move { panic!("connector should not run") }))
}

fn panic_udp_connector() -> MarkedUdpConnector {
    Arc::new(|_address, _routing_mark| {
        Box::pin(async move { panic!("udp connector should not run") })
    })
}

fn direct_outbound_for_test(
    dial: Dial,
    resolver: Arc<HostResolver>,
    connector: MarkedTcpConnector,
) -> DirectOutbound {
    DirectOutbound::new(
        OutboundMeta::new("direct", "direct"),
        Logger::new("direct", "direct"),
        build_direct_dialer_with_connector(dial.clone(), Arc::clone(&resolver), connector)
            .expect("direct dialer should build"),
        build_packet_dialer_with_connector(dial, resolver, panic_udp_connector())
            .expect("packet dialer should build"),
    )
    .expect("direct outbound should build")
}

fn trojan_outbound_for_test(
    dial: Dial,
    resolver: Arc<HostResolver>,
    connector: TcpConnector,
) -> TrojanOutbound {
    TrojanOutbound::new(
        OutboundMeta::new("proxy", "trojan"),
        Logger::new("proxy", "trojan"),
        build_trojan_dialer_with_connector(dial, resolver, connector),
        Destination::new(Host::Domain("proxy.example".into()), 443),
        "secret",
        OutboundTls {
            enabled: true,
            insecure: true,
            server_name: Some("localhost".into()),
            ..OutboundTls::default()
        },
    )
    .expect("trojan outbound should build")
}

fn event_count(events: &[veex_test_tracing::CapturedEvent], event_name: &str) -> usize {
    events
        .iter()
        .filter(|event| event.fields.get("event").map(String::as_str) == Some(event_name))
        .count()
}

#[tokio::test]
async fn direct_and_trojan_surface_resolve_failures_before_connect() {
    let (_guard, trace_buffer) = install_test_subscriber();
    let resolver: Arc<HostResolver> = Arc::new(|_request: HostResolveRequest| {
        Box::pin(async { Err(ProxyError::resolve("test resolver failed")) })
    });
    let direct = direct_outbound_for_test(
        Dial {
            connect_timeout: Some(Duration::from_secs(1)),
            routing_mark: Some(9),
            domain_resolver: Some("bootstrap".into()),
            ..Dial::default()
        },
        Arc::clone(&resolver),
        panic_marked_connector(),
    );
    let trojan = trojan_outbound_for_test(
        Dial {
            connect_timeout: Some(Duration::from_secs(1)),
            domain_resolver: Some("bootstrap".into()),
            ..Dial::default()
        },
        resolver,
        Arc::new(|_address| Box::pin(async move { panic!("connector should not run") })),
    );

    let direct_err = match direct
        .connect_stream(&test_stream_session(Destination::new(
            Host::Domain("example.com".into()),
            443,
        )))
        .await
    {
        Ok(_) => panic!("direct resolve should fail"),
        Err(err) => err,
    };
    let trojan_err = match trojan
        .connect_proxy_stream(&test_stream_session(Destination::new(
            Host::Domain("example.com".into()),
            443,
        )))
        .await
    {
        Ok(_) => panic!("trojan resolve should fail"),
        Err(err) => err,
    };

    assert_eq!(direct_err.kind(), veex_core::ErrorKind::Resolve);
    assert_eq!(trojan_err.kind(), veex_core::ErrorKind::Resolve);
    assert!(direct_err.to_string().contains("test resolver failed"));
    assert!(trojan_err.to_string().contains("test resolver failed"));

    let events = captured_events(&trace_buffer);
    assert_eq!(event_count(&events, "tcp_connect_attempt"), 0);
    assert_eq!(event_count(&events, "tcp_connect_success"), 0);
    assert_eq!(event_count(&events, "tcp_connect_failed"), 0);
    assert_eq!(event_count(&events, "tls_handshake_start"), 0);
    assert_eq!(event_count(&events, "tls_handshake_success"), 0);
    assert_eq!(event_count(&events, "tls_handshake_failed"), 0);
    assert_eq!(event_count(&events, "protocol_handshake_start"), 0);
    assert_eq!(event_count(&events, "protocol_handshake_success"), 0);
    assert_eq!(event_count(&events, "protocol_handshake_failed"), 0);
}

#[tokio::test]
async fn direct_and_trojan_share_connect_timeout_semantics() {
    let (_guard, trace_buffer) = install_test_subscriber();
    let resolver: Arc<HostResolver> = Arc::new(|request: HostResolveRequest| {
        Box::pin(async move {
            Ok(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                request.port,
            )])
        })
    });
    let direct = direct_outbound_for_test(
        Dial {
            connect_timeout: Some(Duration::from_millis(50)),
            routing_mark: Some(7),
            ..Dial::default()
        },
        Arc::clone(&resolver),
        Arc::new(|_address, _routing_mark| {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "delayed connector should have timed out earlier",
                ))
            })
        }),
    );
    let trojan = trojan_outbound_for_test(
        Dial {
            connect_timeout: Some(Duration::from_millis(50)),
            ..Dial::default()
        },
        resolver,
        Arc::new(|_address| {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "delayed connector should have timed out earlier",
                ))
            })
        }),
    );

    let direct_err = match direct
        .connect_stream(&test_stream_session(Destination::new(
            Host::Domain("example.com".into()),
            443,
        )))
        .await
    {
        Ok(_) => panic!("direct connect should time out"),
        Err(err) => err,
    };
    let trojan_err = match trojan
        .connect_proxy_stream(&test_stream_session(Destination::new(
            Host::Domain("example.com".into()),
            443,
        )))
        .await
    {
        Ok(_) => panic!("trojan connect should time out"),
        Err(err) => err,
    };

    assert_eq!(direct_err.kind(), veex_core::ErrorKind::Timeout);
    assert_eq!(trojan_err.kind(), veex_core::ErrorKind::Timeout);
    assert!(direct_err.to_string().contains("tcp connect timeout"));
    assert!(trojan_err.to_string().contains("tcp connect timeout"));

    let events = captured_events(&trace_buffer);
    assert_eq!(event_count(&events, "tcp_connect_failed"), 2);
    assert_has_event(
        &events,
        "tcp_connect_failed",
        &[
            ("outbound", "direct"),
            ("error_kind", "timeout"),
            ("failure_reason", "timeout"),
            ("timeout_ms", "50"),
            ("level", "WARN"),
        ],
    );
    assert_has_event(
        &events,
        "tcp_connect_failed",
        &[
            ("outbound", "proxy"),
            ("error_kind", "timeout"),
            ("failure_reason", "timeout"),
            ("timeout_ms", "50"),
            ("level", "WARN"),
        ],
    );
    assert_eq!(event_count(&events, "tls_handshake_start"), 0);
    assert_eq!(event_count(&events, "protocol_handshake_start"), 0);
}

#[tokio::test]
async fn direct_and_trojan_preserve_inherited_resolve_context() {
    let inherited = ResolveContext::outbound_dial("parent", Some("bootstrap".into())).with_depth(2);
    let direct_contexts = Arc::new(Mutex::new(Vec::new()));
    let trojan_contexts = Arc::new(Mutex::new(Vec::new()));
    let direct = build_direct_dialer(
        Dial {
            domain_resolver: Some("ignored".into()),
            ..Dial::default()
        },
        capture_contexts(Arc::clone(&direct_contexts)),
    )
    .expect("direct dialer should build");
    let trojan = build_trojan_dialer(
        Dial {
            domain_resolver: Some("ignored".into()),
            ..Dial::default()
        },
        capture_contexts(Arc::clone(&trojan_contexts)),
    );
    let dial_context = DialContext {
        session_id: 8,
        outbound_tag: "shared-outbound".into(),
        resolve_context: Some(inherited.clone()),
    };

    direct
        .connect(
            &Host::Domain("example.com".into()),
            443,
            dial_context.clone(),
        )
        .await
        .expect_err("test resolver should stop direct dialer");
    trojan
        .connect(&Host::Domain("example.com".into()), 443, dial_context)
        .await
        .expect_err("test resolver should stop trojan dialer");

    assert_eq!(
        direct_contexts
            .lock()
            .expect("direct contexts should lock")
            .as_slice(),
        std::slice::from_ref(&inherited)
    );
    assert_eq!(
        trojan_contexts
            .lock()
            .expect("trojan contexts should lock")
            .as_slice(),
        &[inherited]
    );
}
