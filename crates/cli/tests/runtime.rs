use std::{
    collections::BTreeMap,
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use rcgen::generate_simple_self_signed;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
};
use tokio_rustls::TlsAcceptor;
use veex_cli::runtime::{RuntimeError, run_with_shutdown};
use veex_config::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_TLS_HANDSHAKE_TIMEOUT, DirectInboundConfig,
    DirectOutboundConfig, DnsConfig, DnsRuleConfig, DnsServerConfig, DnsServerTypeConfig,
    DomainResolverConfig, InboundConfig, LogConfig, OutboundConfig, ProxyConfig, RouteActionConfig,
    RouteConfig, RouteFinalActionConfig, RouteRuleConfig, RouteTargetConfig, SocksInboundConfig,
    TrojanOutboundConfig, TrojanTlsConfig,
};
use veex_core::{
    ErrorKind,
    dns::{read_dns_tcp_message, write_dns_tcp_message},
    types::{Destination, Host},
};
use veex_dns::parse_query_domain;
use veex_portal_outbound::trojan::build_trojan_request;
use veex_test_tracing::{
    assert_event_has_fields, assert_has_event, captured_events, install_test_subscriber,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnsIngressTransport {
    Udp,
    Tcp,
}

impl DnsIngressTransport {
    fn as_network(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnsUpstreamTransport {
    Udp,
    Tcp,
    Tls,
    Https,
}

impl DnsUpstreamTransport {
    fn as_kind(self) -> DnsServerTypeConfig {
        match self {
            Self::Udp => DnsServerTypeConfig::Udp,
            Self::Tcp => DnsServerTypeConfig::Tcp,
            Self::Tls => DnsServerTypeConfig::Tls,
            Self::Https => DnsServerTypeConfig::Https,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Https => "https",
        }
    }
}

#[tokio::test]
async fn runtime_supports_socks_to_direct_round_trip() {
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("echo listener should bind");
    let echo_addr = echo_listener
        .local_addr()
        .expect("echo listener should expose local addr");
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener
            .accept()
            .await
            .expect("echo accept should succeed");
        let mut buf = [0u8; 4];
        stream
            .read_exact(&mut buf)
            .await
            .expect("echo server should read payload");
        stream
            .write_all(&buf)
            .await
            .expect("echo server should write payload");
    });

    let socks_addr = reserve_local_port().await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "info".into(),
            disabled: false,
            timestamp: false,
        },
        dns: None,
        inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
            tag: "socks-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: socks_addr.port(),
        })],
        outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
            tag: "direct".into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            routing_mark: None,
            domain_resolver: None,
        })],
        route: RouteConfig {
            final_outbound: "direct".into(),
            rules: vec![],
        },
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    wait_for_listener(socks_addr).await;
    run_socks_client_round_trip(socks_addr, echo_addr)
        .await
        .expect("socks direct round-trip should succeed");

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");
    echo_task.await.expect("echo task should join");
}

#[tokio::test]
async fn runtime_supports_direct_udp_to_direct_udp_round_trip() {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("udp echo socket should bind");
    let echo_addr = echo_socket
        .local_addr()
        .expect("udp echo socket should expose local addr");
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        for _ in 0..2 {
            let (size, peer) = echo_socket
                .recv_from(&mut buf)
                .await
                .expect("udp echo should receive payload");
            echo_socket
                .send_to(&buf[..size], peer)
                .await
                .expect("udp echo should send payload");
        }
    });

    let inbound_addr = reserve_udp_port().await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "debug".into(),
            disabled: false,
            timestamp: false,
        },
        dns: None,
        inbounds: vec![InboundConfig::Direct(DirectInboundConfig {
            tag: "direct-udp-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: inbound_addr.port(),
            network: Some("udp".into()),
            override_address: Some("127.0.0.1".into()),
            override_port: Some(echo_addr.port()),
        })],
        outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
            tag: "direct".into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            routing_mark: None,
            domain_resolver: None,
        })],
        route: RouteConfig {
            final_outbound: "direct".into(),
            rules: vec![],
        },
    };
    let (_guard, trace_buffer) = install_test_subscriber();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    run_direct_udp_client_round_trip(inbound_addr)
        .await
        .expect("udp direct round-trip should succeed");

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");
    echo_task.await.expect("echo task should join");

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "packet_association_create",
        &[
            ("inbound", "direct-udp-in"),
            ("outbound", "direct"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "packet_association_hit",
        &[
            ("inbound", "direct-udp-in"),
            ("outbound", "direct"),
            ("level", "DEBUG"),
        ],
    );
    assert_has_event(
        &events,
        "udp_connect_success",
        &[
            ("outbound", "direct"),
            ("network", "udp"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "packet_session_shutdown",
        &[
            ("inbound", "direct-udp-in"),
            ("shutdown_reason", "dispatcher_shutdown"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "packet_session_closed",
        &[
            ("inbound", "direct-udp-in"),
            ("close_reason", "shutdown"),
            ("level", "INFO"),
        ],
    );
}

#[tokio::test]
async fn runtime_supports_udp_dns_hijack_to_udp_upstream_round_trip() {
    assert_dns_hijack_round_trip(DnsIngressTransport::Udp, DnsUpstreamTransport::Udp).await;
}

#[tokio::test]
async fn runtime_supports_udp_dns_hijack_to_tcp_upstream_round_trip() {
    assert_dns_hijack_round_trip(DnsIngressTransport::Udp, DnsUpstreamTransport::Tcp).await;
}

#[tokio::test]
async fn runtime_supports_tcp_dns_hijack_to_udp_upstream_round_trip() {
    assert_dns_hijack_round_trip(DnsIngressTransport::Tcp, DnsUpstreamTransport::Udp).await;
}

#[tokio::test]
async fn runtime_supports_tcp_dns_hijack_to_tcp_upstream_round_trip() {
    assert_dns_hijack_round_trip(DnsIngressTransport::Tcp, DnsUpstreamTransport::Tcp).await;
}

#[tokio::test]
async fn runtime_supports_udp_dns_hijack_to_tls_upstream_round_trip() {
    assert_dns_hijack_round_trip(DnsIngressTransport::Udp, DnsUpstreamTransport::Tls).await;
}

#[tokio::test]
async fn runtime_supports_udp_dns_hijack_to_https_upstream_round_trip() {
    assert_dns_hijack_round_trip(DnsIngressTransport::Udp, DnsUpstreamTransport::Https).await;
}

#[tokio::test]
async fn runtime_supports_tcp_dns_hijack_to_tls_upstream_round_trip() {
    assert_dns_hijack_round_trip(DnsIngressTransport::Tcp, DnsUpstreamTransport::Tls).await;
}

#[tokio::test]
async fn runtime_supports_tcp_dns_hijack_to_https_upstream_round_trip() {
    assert_dns_hijack_round_trip(DnsIngressTransport::Tcp, DnsUpstreamTransport::Https).await;
}

#[tokio::test]
async fn runtime_uses_explicit_domain_resolver_for_trojan_server_dial() {
    let destination = Destination::new(Host::Ip(Ipv4Addr::new(93, 184, 216, 34).into()), 443);
    let trojan_server = spawn_trojan_server("localhost", destination.clone()).await;
    let (bootstrap_addr, bootstrap_task) =
        spawn_dns_answer_server(Ipv4Addr::LOCALHOST, trojan_server.addr.ip()).await;
    let (misroute_addr, misroute_task) =
        spawn_dns_answer_server(Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2).into()).await;
    let socks_addr = reserve_local_port().await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "debug".into(),
            disabled: false,
            timestamp: false,
        },
        dns: Some(DnsConfig {
            final_server: "remote-dns".into(),
            servers: vec![
                DnsServerConfig {
                    tag: "direct-dns".into(),
                    kind: DnsServerTypeConfig::Udp,
                    server: "127.0.0.1".into(),
                    server_port: bootstrap_addr.port(),
                    path: None,
                    headers: BTreeMap::new(),
                    detour: "direct".into(),
                    domain_resolver: None,
                    tls: dns_server_tls_config(DnsUpstreamTransport::Udp),
                },
                DnsServerConfig {
                    tag: "remote-dns".into(),
                    kind: DnsServerTypeConfig::Udp,
                    server: "127.0.0.1".into(),
                    server_port: misroute_addr.port(),
                    path: None,
                    headers: BTreeMap::new(),
                    detour: "direct".into(),
                    domain_resolver: None,
                    tls: dns_server_tls_config(DnsUpstreamTransport::Udp),
                },
            ],
            rules: vec![DnsRuleConfig {
                domain: vec!["trojan-bootstrap.test".into()],
                server: "remote-dns".into(),
            }],
        }),
        inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
            tag: "socks-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: socks_addr.port(),
        })],
        outbounds: vec![
            OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
                domain_resolver: None,
            }),
            OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: "proxy".into(),
                server: "trojan-bootstrap.test".into(),
                server_port: trojan_server.addr.port(),
                password: "secret".into(),
                domain_resolver: Some(DomainResolverConfig {
                    server: "direct-dns".into(),
                }),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                tls: TrojanTlsConfig {
                    enabled: true,
                    server_name: Some("localhost".into()),
                    disable_sni: false,
                    insecure: true,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }),
        ],
        route: RouteConfig {
            final_outbound: "proxy".into(),
            rules: vec![],
        },
    };
    let (_guard, trace_buffer) = install_test_subscriber();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    wait_for_listener(socks_addr).await;
    run_socks_client_round_trip(
        socks_addr,
        SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443)),
    )
    .await
    .expect("trojan round-trip with explicit domain_resolver should succeed");

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");

    let observation = bootstrap_task
        .await
        .expect("bootstrap dns task should join");
    assert_eq!(
        parse_dns_query_name(&observation.query),
        "trojan-bootstrap.test"
    );
    misroute_task.abort();
    let received = trojan_server
        .handle
        .await
        .expect("trojan server task should join");
    assert_eq!(received.payload, b"ping");

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "domain_resolve_start",
        &[
            ("domain", "trojan-bootstrap.test"),
            ("explicit_server", "direct-dns"),
            ("route_reason", "explicit_resolver"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "domain_resolve_success",
        &[
            ("domain", "trojan-bootstrap.test"),
            ("server", "direct-dns"),
            ("level", "INFO"),
        ],
    );
    let _ = fs::remove_file(trojan_server.certificate_path);
}

#[tokio::test]
async fn runtime_supports_tls_dns_upstream_self_resolution_via_domain_resolver() {
    assert_dns_upstream_self_resolution_round_trip(DnsUpstreamTransport::Tls).await;
}

#[tokio::test]
async fn runtime_supports_https_dns_upstream_self_resolution_via_domain_resolver() {
    assert_dns_upstream_self_resolution_round_trip(DnsUpstreamTransport::Https).await;
}

#[tokio::test]
async fn runtime_supports_socks_to_trojan_round_trip() {
    let destination = Destination::new(Host::Ip(Ipv4Addr::new(93, 184, 216, 34).into()), 443);
    let trojan_server = spawn_trojan_server("localhost", destination.clone()).await;
    let socks_addr = reserve_local_port().await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "info".into(),
            disabled: false,
            timestamp: false,
        },
        dns: None,
        inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
            tag: "socks-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: socks_addr.port(),
        })],
        outbounds: vec![
            OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
                domain_resolver: None,
            }),
            OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: "proxy".into(),
                server: "127.0.0.1".into(),
                server_port: trojan_server.addr.port(),
                password: "secret".into(),
                domain_resolver: None,
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                tls: TrojanTlsConfig {
                    enabled: true,
                    server_name: Some("localhost".into()),
                    disable_sni: false,
                    insecure: true,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }),
        ],
        route: RouteConfig {
            final_outbound: "proxy".into(),
            rules: vec![],
        },
    };
    let (_guard, trace_buffer) = install_test_subscriber();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    wait_for_listener(socks_addr).await;
    run_socks_client_round_trip(
        socks_addr,
        SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443)),
    )
    .await
    .expect("socks trojan round-trip should succeed");

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");

    let received = trojan_server
        .handle
        .await
        .expect("trojan server task should join");
    assert_eq!(
        received.request,
        build_trojan_request("secret", &destination, &[]).unwrap()
    );
    assert_eq!(received.payload, b"ping");
    let _ = fs::remove_file(trojan_server.certificate_path);

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "tcp_connect_attempt",
        &[("outbound", "proxy"), ("network", "tcp")],
    );
    assert_event_has_fields(
        &events,
        "tcp_connect_attempt",
        &["session_id", "resolved_addr", "attempt_index"],
    );
    assert_has_event(
        &events,
        "tcp_connect_success",
        &[("outbound", "proxy"), ("network", "tcp"), ("level", "INFO")],
    );
    assert_event_has_fields(
        &events,
        "tcp_connect_success",
        &["session_id", "resolved_addr", "attempt_index"],
    );
    assert_has_event(
        &events,
        "tls_handshake_start",
        &[
            ("outbound", "proxy"),
            ("host", "127.0.0.1"),
            ("level", "INFO"),
        ],
    );
    assert_event_has_fields(
        &events,
        "tls_handshake_start",
        &["session_id", "server_name", "port", "resolved_addr"],
    );
    assert_has_event(
        &events,
        "tls_handshake_success",
        &[
            ("outbound", "proxy"),
            ("host", "127.0.0.1"),
            ("level", "INFO"),
        ],
    );
    assert_event_has_fields(
        &events,
        "tls_handshake_success",
        &["session_id", "server_name", "port", "resolved_addr"],
    );
    assert_has_event(
        &events,
        "relay_start",
        &[
            ("inbound", "socks-in"),
            ("outbound", "proxy"),
            ("level", "INFO"),
        ],
    );
    assert_event_has_fields(&events, "relay_start", &["session_id", "destination"]);
    assert_has_event(
        &events,
        "session_finish",
        &[
            ("inbound", "socks-in"),
            ("outbound", "proxy"),
            ("success", "true"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "relay_finish",
        &[
            ("inbound", "socks-in"),
            ("outbound", "proxy"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "relay_stats_finalized",
        &[("success", "true"), ("level", "INFO")],
    );
}

#[tokio::test]
async fn runtime_supports_socks_domain_route_rule_to_trojan() {
    let destination = Destination::from_domain("rule-test.invalid", 443);
    let trojan_server = spawn_trojan_server("localhost", destination.clone()).await;
    let socks_addr = reserve_local_port().await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "info".into(),
            disabled: false,
            timestamp: false,
        },
        dns: None,
        inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
            tag: "socks-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: socks_addr.port(),
        })],
        outbounds: vec![
            OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
                domain_resolver: None,
            }),
            OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: "proxy".into(),
                server: "127.0.0.1".into(),
                server_port: trojan_server.addr.port(),
                password: "secret".into(),
                domain_resolver: None,
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                tls: TrojanTlsConfig {
                    enabled: true,
                    server_name: Some("localhost".into()),
                    disable_sni: false,
                    insecure: true,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }),
        ],
        route: RouteConfig {
            final_outbound: "direct".into(),
            rules: vec![RouteRuleConfig {
                domain: vec!["rule-test.invalid".into()],
                domain_suffix: vec![],
                ip_cidr: vec![],
                ip_is_private: false,
                ip_is_loopback: false,
                ip_is_link_local: false,
                port: vec![],
                inbound: vec![],
                action: RouteActionConfig::Final(RouteFinalActionConfig::Route(
                    RouteTargetConfig {
                        outbound: "proxy".into(),
                    },
                )),
            }],
        },
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    wait_for_listener(socks_addr).await;
    run_socks_domain_client_round_trip(socks_addr, "rule-test.invalid", 443)
        .await
        .expect("domain rule should route through trojan");

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");

    let received = trojan_server
        .handle
        .await
        .expect("trojan server task should join");
    assert_eq!(
        received.request,
        build_trojan_request("secret", &destination, &[]).unwrap()
    );
    assert_eq!(received.payload, b"ping");
    let _ = fs::remove_file(trojan_server.certificate_path);
}

#[tokio::test]
async fn runtime_reports_trojan_failure_on_wrong_password() {
    let destination = Destination::new(Host::Ip(Ipv4Addr::new(93, 184, 216, 34).into()), 443);
    let trojan_server =
        spawn_rejecting_trojan_server("localhost", destination.clone(), "secret").await;
    let socks_addr = reserve_local_port().await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "info".into(),
            disabled: false,
            timestamp: false,
        },
        dns: None,
        inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
            tag: "socks-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: socks_addr.port(),
        })],
        outbounds: vec![
            OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
                domain_resolver: None,
            }),
            OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: "proxy".into(),
                server: "127.0.0.1".into(),
                server_port: trojan_server.addr.port(),
                password: "wrong-secret".into(),
                domain_resolver: None,
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                tls: TrojanTlsConfig {
                    enabled: true,
                    server_name: Some("localhost".into()),
                    disable_sni: false,
                    insecure: true,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }),
        ],
        route: RouteConfig {
            final_outbound: "proxy".into(),
            rules: vec![],
        },
    };
    let (_guard, trace_buffer) = install_test_subscriber();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    wait_for_listener(socks_addr).await;
    let failure = run_socks_client_expect_relay_failure(
        socks_addr,
        SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443)),
    )
    .await;
    assert!(
        failure.contains("failed to read relay response")
            || failure.contains("connection closed before relay response"),
        "unexpected failure: {failure}"
    );

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");

    let received = trojan_server
        .handle
        .await
        .expect("trojan server task should join");
    assert_ne!(
        received.request,
        build_trojan_request("secret", &destination, &[]).unwrap()
    );
    assert_eq!(received.payload, b"ping");
    let _ = fs::remove_file(trojan_server.certificate_path);

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "tcp_connect_success",
        &[("outbound", "proxy"), ("network", "tcp"), ("level", "INFO")],
    );
    assert_has_event(
        &events,
        "tls_handshake_start",
        &[
            ("outbound", "proxy"),
            ("host", "127.0.0.1"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "tls_handshake_success",
        &[
            ("outbound", "proxy"),
            ("host", "127.0.0.1"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "relay_start",
        &[
            ("inbound", "socks-in"),
            ("outbound", "proxy"),
            ("level", "INFO"),
        ],
    );
}

#[tokio::test]
async fn runtime_reports_direct_failure_on_unreachable_target() {
    let unreachable_addr = reserve_local_port().await;
    let socks_addr = reserve_local_port().await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "info".into(),
            disabled: false,
            timestamp: false,
        },
        dns: None,
        inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
            tag: "socks-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: socks_addr.port(),
        })],
        outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
            tag: "direct".into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            routing_mark: None,
            domain_resolver: None,
        })],
        route: RouteConfig {
            final_outbound: "direct".into(),
            rules: vec![],
        },
    };
    let (_guard, trace_buffer) = install_test_subscriber();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    wait_for_listener(socks_addr).await;
    let failure = run_socks_client_expect_relay_failure(socks_addr, unreachable_addr).await;
    assert!(
        failure.contains("failed to read relay response")
            || failure.contains("connection closed before relay response"),
        "unexpected failure: {failure}"
    );

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "tcp_connect_attempt",
        &[
            ("outbound", "direct"),
            ("network", "tcp"),
            ("routing_mark", ""),
            ("level", "DEBUG"),
        ],
    );
    assert_event_has_fields(
        &events,
        "tcp_connect_attempt",
        &[
            "session_id",
            "host",
            "resolved_addr",
            "attempt_index",
            "routing_mark",
        ],
    );
    assert_has_event(
        &events,
        "tcp_connect_failed",
        &[
            ("outbound", "direct"),
            ("network", "tcp"),
            ("routing_mark", ""),
            ("error_kind", "dial"),
            ("level", "WARN"),
        ],
    );
    assert_event_has_fields(
        &events,
        "tcp_connect_failed",
        &[
            "session_id",
            "host",
            "resolved_addr",
            "attempt_index",
            "routing_mark",
            "error_kind",
            "error",
        ],
    );
    assert_has_event(
        &events,
        "session_finish",
        &[
            ("inbound", "socks-in"),
            ("outbound", "direct"),
            ("success", "false"),
            ("level", "WARN"),
        ],
    );
}

#[tokio::test]
async fn runtime_starts_with_redirect_inbound() {
    let redirect_addr = reserve_local_port().await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "info".into(),
            disabled: false,
            timestamp: false,
        },
        dns: None,
        inbounds: vec![InboundConfig::Redirect(
            veex_config::RedirectInboundConfig {
                tag: "redirect-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: redirect_addr.port(),
            },
        )],
        outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
            tag: "direct".into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            routing_mark: None,
            domain_resolver: None,
        })],
        route: RouteConfig {
            final_outbound: "direct".into(),
            rules: vec![],
        },
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });
    tokio::pin!(runtime_task);

    // Avoid a readiness probe connection here. For redirect inbound, an accepted
    // non-redirected socket immediately exercises SO_ORIGINAL_DST handling and can
    // become flaky under CI kernels. The startup signal we care about is simply
    // that the runtime does not exit immediately on bind/serve setup.
    tokio::select! {
        result = &mut runtime_task => {
            panic!("redirect runtime exited before shutdown: {:?}", result);
        }
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), &mut runtime_task)
        .await
        .expect("redirect runtime should stop within timeout")
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");
}

#[tokio::test]
async fn runtime_reports_listener_bind_failure_with_io_error_kind() {
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("occupied listener should bind");
    let occupied_addr = occupied
        .local_addr()
        .expect("occupied listener addr should exist");
    let config = ProxyConfig {
        log: LogConfig {
            level: "info".into(),
            disabled: false,
            timestamp: false,
        },
        dns: None,
        inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
            tag: "socks-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: occupied_addr.port(),
        })],
        outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
            tag: "direct".into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            routing_mark: None,
            domain_resolver: None,
        })],
        route: RouteConfig {
            final_outbound: "direct".into(),
            rules: vec![],
        },
    };
    let (_guard, trace_buffer) = install_test_subscriber();

    let err = tokio::time::timeout(
        Duration::from_secs(2),
        run_with_shutdown(&config, async {
            std::future::pending::<Result<(), String>>().await
        }),
    )
    .await
    .expect("runtime should fail quickly")
    .expect_err("bind failure should fail runtime");

    match err {
        RuntimeError::Task { inbound, source } => {
            assert_eq!(inbound, "socks-in");
            assert_eq!(source.kind(), ErrorKind::Io);
        }
        other => panic!("unexpected runtime error: {other}"),
    }

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "inbound_service_failed",
        &[("inbound", "socks-in"), ("error_kind", "io")],
    );
}

#[tokio::test]
async fn runtime_emits_session_start_and_finish_events() {
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("echo listener should bind");
    let echo_addr = echo_listener
        .local_addr()
        .expect("echo listener should expose local addr");
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener
            .accept()
            .await
            .expect("echo accept should succeed");
        let mut buf = [0u8; 4];
        stream
            .read_exact(&mut buf)
            .await
            .expect("echo server should read payload");
        stream
            .write_all(&buf)
            .await
            .expect("echo server should write payload");
    });

    let socks_addr = reserve_local_port().await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "info".into(),
            disabled: false,
            timestamp: false,
        },
        dns: None,
        inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
            tag: "socks-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: socks_addr.port(),
        })],
        outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
            tag: "direct".into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            routing_mark: None,
            domain_resolver: None,
        })],
        route: RouteConfig {
            final_outbound: "direct".into(),
            rules: vec![],
        },
    };
    let (_guard, trace_buffer) = install_test_subscriber();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    wait_for_listener(socks_addr).await;
    run_socks_client_round_trip(socks_addr, echo_addr)
        .await
        .expect("socks direct round-trip should succeed");

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");
    echo_task.await.expect("echo task should join");

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "session_start",
        &[("inbound", "socks-in"), ("network", "tcp")],
    );
    assert_event_has_fields(&events, "session_start", &["peer", "destination"]);
    assert_has_event(
        &events,
        "session_finish",
        &[
            ("inbound", "socks-in"),
            ("success", "true"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "tcp_connect_attempt",
        &[
            ("outbound", "direct"),
            ("network", "tcp"),
            ("routing_mark", ""),
            ("level", "DEBUG"),
        ],
    );
    assert_event_has_fields(
        &events,
        "tcp_connect_attempt",
        &[
            "session_id",
            "host",
            "resolved_addr",
            "attempt_index",
            "routing_mark",
        ],
    );
    assert_has_event(
        &events,
        "tcp_connect_success",
        &[
            ("outbound", "direct"),
            ("network", "tcp"),
            ("routing_mark", ""),
            ("level", "INFO"),
        ],
    );
    assert_event_has_fields(
        &events,
        "tcp_connect_success",
        &[
            "session_id",
            "host",
            "resolved_addr",
            "attempt_index",
            "routing_mark",
        ],
    );
    assert_has_event(
        &events,
        "relay_start",
        &[
            ("inbound", "socks-in"),
            ("outbound", "direct"),
            ("level", "INFO"),
        ],
    );
    assert_event_has_fields(&events, "relay_start", &["session_id", "destination"]);
    assert_has_event(
        &events,
        "relay_finish",
        &[
            ("inbound", "socks-in"),
            ("outbound", "direct"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "relay_stats_finalized",
        &[("success", "true"), ("level", "INFO")],
    );
}

#[tokio::test]
async fn invalid_socks_request_emits_handshake_failed_event() {
    let socks_addr = reserve_local_port().await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "info".into(),
            disabled: false,
            timestamp: false,
        },
        dns: None,
        inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
            tag: "socks-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: socks_addr.port(),
        })],
        outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
            tag: "direct".into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            routing_mark: None,
            domain_resolver: None,
        })],
        route: RouteConfig {
            final_outbound: "direct".into(),
            rules: vec![],
        },
    };
    let (_guard, trace_buffer) = install_test_subscriber();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    wait_for_listener(socks_addr).await;
    let mut stream = TcpStream::connect(socks_addr)
        .await
        .expect("socks listener should accept connections");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting should be written");
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .expect("method selection should be readable");
    assert_eq!(method, [0x05, 0x00]);

    stream
        .write_all(&[0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50])
        .await
        .expect("invalid request should be written");
    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .expect("failure reply should be readable");
    assert_eq!(reply[1], 0x01);

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "handshake_failed",
        &[("inbound", "socks-in"), ("stage", "request_decode")],
    );
}

async fn reserve_local_port() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("temporary listener should bind");
    listener.local_addr().expect("temporary addr should exist")
}

async fn wait_for_listener(addr: SocketAddr) {
    for _ in 0..50 {
        match TcpStream::connect(addr).await {
            Ok(_) => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }

    panic!("listener did not become ready on {addr}");
}

async fn run_socks_client_round_trip(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
) -> Result<(), String> {
    let mut stream = TcpStream::connect(socks_addr)
        .await
        .map_err(|err| format!("failed to connect to socks listener: {err}"))?;

    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|err| format!("failed to write greeting: {err}"))?;
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|err| format!("failed to read method selection: {err}"))?;
    if method != [0x05, 0x00] {
        return Err(format!("unexpected method selection: {method:?}"));
    }

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    match target_addr.ip() {
        std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => return Err("test target must be IPv4".into()),
    }
    request.extend_from_slice(&target_addr.port().to_be_bytes());

    stream
        .write_all(&request)
        .await
        .map_err(|err| format!("failed to write socks request: {err}"))?;

    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|err| format!("failed to read socks reply: {err}"))?;
    if reply[1] != 0x00 {
        return Err(format!("unexpected socks reply code: 0x{:02x}", reply[1]));
    }

    stream
        .write_all(b"ping")
        .await
        .map_err(|err| format!("failed to write payload: {err}"))?;

    let mut echoed = [0u8; 4];
    stream
        .read_exact(&mut echoed)
        .await
        .map_err(|err| format!("failed to read echoed payload: {err}"))?;
    if &echoed != b"ping" {
        return Err(format!("unexpected echoed payload: {echoed:?}"));
    }

    Ok(())
}

async fn run_socks_domain_client_round_trip(
    socks_addr: SocketAddr,
    domain: &str,
    port: u16,
) -> Result<(), String> {
    let mut stream = TcpStream::connect(socks_addr)
        .await
        .map_err(|err| format!("failed to connect to socks listener: {err}"))?;

    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|err| format!("failed to write greeting: {err}"))?;
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|err| format!("failed to read method selection: {err}"))?;
    if method != [0x05, 0x00] {
        return Err(format!("unexpected method selection: {method:?}"));
    }

    let domain_bytes = domain.as_bytes();
    if domain_bytes.len() > u8::MAX as usize {
        return Err("domain is too long for socks request".into());
    }

    let mut request = vec![0x05, 0x01, 0x00, 0x03, domain_bytes.len() as u8];
    request.extend_from_slice(domain_bytes);
    request.extend_from_slice(&port.to_be_bytes());

    stream
        .write_all(&request)
        .await
        .map_err(|err| format!("failed to write socks request: {err}"))?;

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|err| format!("failed to read socks reply header: {err}"))?;
    if header[1] != 0x00 {
        return Err(format!("unexpected socks reply code: 0x{:02x}", header[1]));
    }

    let trailing_len = match header[3] {
        0x01 => 6,
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|err| format!("failed to read socks domain length: {err}"))?;
            len[0] as usize + 2
        }
        0x04 => 18,
        other => return Err(format!("unexpected socks reply atyp: 0x{other:02x}")),
    };

    let mut trailing = vec![0u8; trailing_len];
    stream
        .read_exact(&mut trailing)
        .await
        .map_err(|err| format!("failed to read socks reply tail: {err}"))?;

    stream
        .write_all(b"ping")
        .await
        .map_err(|err| format!("failed to write payload: {err}"))?;

    let mut echoed = [0u8; 4];
    stream
        .read_exact(&mut echoed)
        .await
        .map_err(|err| format!("failed to read echoed payload: {err}"))?;
    if &echoed != b"ping" {
        return Err(format!("unexpected echoed payload: {echoed:?}"));
    }

    Ok(())
}

async fn run_socks_client_expect_relay_failure(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
) -> String {
    let mut stream = TcpStream::connect(socks_addr)
        .await
        .expect("socks connect should succeed");

    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting write should succeed");
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .expect("method selection should be readable");
    assert_eq!(method, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    match target_addr.ip() {
        std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => panic!("test target must be IPv4"),
    }
    request.extend_from_slice(&target_addr.port().to_be_bytes());

    stream
        .write_all(&request)
        .await
        .expect("request write should succeed");

    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .expect("reply should be readable");
    assert_eq!(reply[1], 0x00, "unexpected socks reply: {reply:?}");

    stream
        .write_all(b"ping")
        .await
        .expect("payload write should succeed");

    let mut echoed = [0u8; 4];
    match stream.read_exact(&mut echoed).await {
        Ok(_) => panic!("relay unexpectedly succeeded with payload {echoed:?}"),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            "connection closed before relay response".into()
        }
        Err(err) => format!("failed to read relay response: {err}"),
    }
}

async fn run_direct_udp_client_round_trip(inbound_addr: SocketAddr) -> Result<(), String> {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|err| format!("failed to bind udp client: {err}"))?;
    let mut echoed = [0u8; 16];

    for _ in 0..100 {
        client
            .send_to(b"ping", inbound_addr)
            .await
            .map_err(|err| format!("failed to send first udp payload: {err}"))?;
        match tokio::time::timeout(Duration::from_millis(50), client.recv_from(&mut echoed)).await {
            Ok(Ok((size, _peer))) if &echoed[..size] == b"ping" => {
                client
                    .send_to(b"pang", inbound_addr)
                    .await
                    .map_err(|err| format!("failed to send second udp payload: {err}"))?;
                let (size, _peer) =
                    tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut echoed))
                        .await
                        .map_err(|_| "timed out waiting for second udp echo".to_string())?
                        .map_err(|err| format!("failed to receive second udp echo: {err}"))?;
                if &echoed[..size] != b"pang" {
                    return Err(format!("unexpected second udp echo: {:?}", &echoed[..size]));
                }
                return Ok(());
            }
            Ok(Ok((_size, _peer))) => {}
            Ok(Err(err)) => return Err(format!("failed to receive first udp echo: {err}")),
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    Err(format!(
        "udp inbound did not become ready on {inbound_addr}"
    ))
}

async fn assert_dns_hijack_round_trip(
    ingress: DnsIngressTransport,
    upstream: DnsUpstreamTransport,
) {
    let query = build_dns_query("trojan.example.com");
    let inbound_addr = match ingress {
        DnsIngressTransport::Udp => reserve_udp_port().await,
        DnsIngressTransport::Tcp => reserve_local_port().await,
    };
    let (upstream_addr, upstream_task) = spawn_dns_upstream_server(upstream).await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "debug".into(),
            disabled: false,
            timestamp: false,
        },
        dns: Some(DnsConfig {
            final_server: "direct-dns".into(),
            servers: vec![DnsServerConfig {
                tag: "direct-dns".into(),
                kind: upstream.as_kind(),
                server: "127.0.0.1".into(),
                server_port: upstream_addr.port(),
                path: dns_server_path(upstream),
                headers: dns_server_headers(upstream),
                detour: "direct".into(),
                domain_resolver: None,
                tls: dns_server_tls_config(upstream),
            }],
            rules: vec![DnsRuleConfig {
                domain: vec!["trojan.example.com".into()],
                server: "direct-dns".into(),
            }],
        }),
        inbounds: vec![InboundConfig::Direct(DirectInboundConfig {
            tag: "dns-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: inbound_addr.port(),
            network: Some(ingress.as_network().into()),
            override_address: None,
            override_port: None,
        })],
        outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
            tag: "direct".into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            routing_mark: None,
            domain_resolver: None,
        })],
        route: RouteConfig {
            final_outbound: "direct".into(),
            rules: vec![RouteRuleConfig {
                domain: vec![],
                domain_suffix: vec![],
                ip_cidr: vec![],
                ip_is_private: false,
                ip_is_loopback: false,
                ip_is_link_local: false,
                port: vec![],
                inbound: vec!["dns-in".into()],
                action: RouteActionConfig::Final(RouteFinalActionConfig::HijackDns),
            }],
        },
    };
    let (_guard, trace_buffer) = install_test_subscriber();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    let response = match ingress {
        DnsIngressTransport::Udp => run_dns_udp_client_round_trip(inbound_addr, query.clone())
            .await
            .expect("udp dns hijack round-trip should succeed"),
        DnsIngressTransport::Tcp => run_dns_tcp_client_round_trip(inbound_addr, query.clone())
            .await
            .expect("tcp dns hijack round-trip should succeed"),
    };

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");

    let upstream_observation = upstream_task.await.expect("dns upstream task should join");
    assert_eq!(upstream_observation.query, query);
    assert_eq!(response, build_dns_noerror_response(&query));
    if matches!(upstream, DnsUpstreamTransport::Https) {
        assert_eq!(upstream_observation.path.as_deref(), Some("/dns-query"));
        assert_eq!(
            upstream_observation
                .headers
                .get("x-veex-dns")
                .map(String::as_str),
            Some("step-b")
        );
        assert_eq!(
            upstream_observation
                .headers
                .get("content-type")
                .map(String::as_str),
            Some("application/dns-message")
        );
    }

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "dns_query_start",
        &[
            ("inbound", "dns-in"),
            ("server", "direct-dns"),
            ("transport", upstream.as_str()),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "dns_query_success",
        &[
            ("inbound", "dns-in"),
            ("server", "direct-dns"),
            ("transport", upstream.as_str()),
            ("level", "INFO"),
        ],
    );

    match ingress {
        DnsIngressTransport::Udp => {
            assert_has_event(
                &events,
                "packet_hijack_dns",
                &[("inbound", "dns-in"), ("level", "INFO")],
            );
            assert_has_event(
                &events,
                "packet_hijack_dns_complete",
                &[("inbound", "dns-in"), ("level", "INFO")],
            );
            assert!(
                !events.iter().any(|event| {
                    event.fields.get("event").map(String::as_str)
                        == Some("packet_association_create")
                }),
                "dns hijack should not create packet associations: {events:?}"
            );
        }
        DnsIngressTransport::Tcp => {
            assert_has_event(
                &events,
                "stream_hijack_dns",
                &[("inbound", "dns-in"), ("level", "INFO")],
            );
            assert_has_event(
                &events,
                "stream_hijack_dns_complete",
                &[("inbound", "dns-in"), ("level", "INFO")],
            );
            assert!(
                !events.iter().any(|event| {
                    event.fields.get("event").map(String::as_str) == Some("relay_start")
                }),
                "tcp dns hijack should not enter relay: {events:?}"
            );
        }
    }

    if matches!(
        upstream,
        DnsUpstreamTransport::Tls | DnsUpstreamTransport::Https
    ) {
        assert_has_event(
            &events,
            "tls_handshake_start",
            &[
                ("outbound", "direct"),
                ("server_name", "localhost"),
                ("level", "INFO"),
            ],
        );
        assert_has_event(
            &events,
            "tls_handshake_success",
            &[
                ("outbound", "direct"),
                ("server_name", "localhost"),
                ("level", "INFO"),
            ],
        );
    }

    if matches!(upstream, DnsUpstreamTransport::Https) {
        assert_has_event(
            &events,
            "dns_https_exchange_start",
            &[("server", "direct-dns"), ("level", "INFO")],
        );
        assert_has_event(
            &events,
            "dns_https_exchange_success",
            &[("server", "direct-dns"), ("level", "INFO")],
        );
    }
}

async fn assert_dns_upstream_self_resolution_round_trip(upstream: DnsUpstreamTransport) {
    let query = build_dns_query("trojan.example.com");
    let inbound_addr = reserve_udp_port().await;
    let (upstream_addr, upstream_task) = spawn_dns_upstream_server(upstream).await;
    let (bootstrap_addr, bootstrap_task) =
        spawn_dns_answer_server(Ipv4Addr::LOCALHOST, upstream_addr.ip()).await;
    let config = ProxyConfig {
        log: LogConfig {
            level: "debug".into(),
            disabled: false,
            timestamp: false,
        },
        dns: Some(DnsConfig {
            final_server: "direct-dns".into(),
            servers: vec![
                DnsServerConfig {
                    tag: "direct-dns".into(),
                    kind: upstream.as_kind(),
                    server: "bootstrap-upstream.test".into(),
                    server_port: upstream_addr.port(),
                    path: dns_server_path(upstream),
                    headers: dns_server_headers(upstream),
                    detour: "direct".into(),
                    domain_resolver: Some(DomainResolverConfig {
                        server: "bootstrap".into(),
                    }),
                    tls: dns_server_tls_config(upstream),
                },
                DnsServerConfig {
                    tag: "bootstrap".into(),
                    kind: DnsServerTypeConfig::Udp,
                    server: "127.0.0.1".into(),
                    server_port: bootstrap_addr.port(),
                    path: None,
                    headers: BTreeMap::new(),
                    detour: "direct".into(),
                    domain_resolver: None,
                    tls: dns_server_tls_config(DnsUpstreamTransport::Udp),
                },
            ],
            rules: vec![DnsRuleConfig {
                domain: vec!["trojan.example.com".into()],
                server: "direct-dns".into(),
            }],
        }),
        inbounds: vec![InboundConfig::Direct(DirectInboundConfig {
            tag: "dns-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: inbound_addr.port(),
            network: Some("udp".into()),
            override_address: None,
            override_port: None,
        })],
        outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
            tag: "direct".into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            routing_mark: None,
            domain_resolver: None,
        })],
        route: RouteConfig {
            final_outbound: "direct".into(),
            rules: vec![RouteRuleConfig {
                domain: vec![],
                domain_suffix: vec![],
                ip_cidr: vec![],
                ip_is_private: false,
                ip_is_loopback: false,
                ip_is_link_local: false,
                port: vec![],
                inbound: vec!["dns-in".into()],
                action: RouteActionConfig::Final(RouteFinalActionConfig::HijackDns),
            }],
        },
    };
    let (_guard, trace_buffer) = install_test_subscriber();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        run_with_shutdown(&config, async move {
            shutdown_rx
                .await
                .map_err(|err| format!("shutdown channel failed: {err}"))?;
            Ok(())
        })
        .await
    });

    let response = run_dns_udp_client_round_trip(inbound_addr, query.clone())
        .await
        .expect("dns self-resolution round-trip should succeed");

    let _ = shutdown_tx.send(());
    runtime_task
        .await
        .expect("runtime task should join")
        .expect("runtime should stop cleanly");

    let upstream_observation = upstream_task.await.expect("dns upstream task should join");
    let bootstrap_observation = bootstrap_task
        .await
        .expect("bootstrap dns task should join");
    assert_eq!(
        parse_dns_query_name(&bootstrap_observation.query),
        "bootstrap-upstream.test"
    );
    assert_eq!(upstream_observation.query, query);
    assert_eq!(response, build_dns_noerror_response(&query));

    let events = captured_events(&trace_buffer);
    assert_has_event(
        &events,
        "domain_resolve_start",
        &[
            ("domain", "bootstrap-upstream.test"),
            ("caller_dns_server", "direct-dns"),
            ("explicit_server", "bootstrap"),
            ("route_reason", "explicit_resolver"),
            ("level", "INFO"),
        ],
    );
    assert_has_event(
        &events,
        "domain_resolve_success",
        &[
            ("domain", "bootstrap-upstream.test"),
            ("server", "bootstrap"),
            ("level", "INFO"),
        ],
    );
}

struct DnsUpstreamObservation {
    query: Vec<u8>,
    path: Option<String>,
    headers: BTreeMap<String, String>,
}

async fn spawn_dns_upstream_server(
    upstream: DnsUpstreamTransport,
) -> (SocketAddr, tokio::task::JoinHandle<DnsUpstreamObservation>) {
    match upstream {
        DnsUpstreamTransport::Udp => {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("udp dns upstream should bind");
            let addr = socket
                .local_addr()
                .expect("udp dns upstream addr should exist");
            let task = tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let (size, peer) = socket
                    .recv_from(&mut buf)
                    .await
                    .expect("udp dns upstream should receive query");
                let response = build_dns_noerror_response(&buf[..size]);
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("udp dns upstream should send response");
                DnsUpstreamObservation {
                    query: buf[..size].to_vec(),
                    path: None,
                    headers: BTreeMap::new(),
                }
            });
            (addr, task)
        }
        DnsUpstreamTransport::Tcp => {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("tcp dns upstream should bind");
            let addr = listener
                .local_addr()
                .expect("tcp dns upstream addr should exist");
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("tcp dns upstream should accept");
                let query = read_dns_tcp_message(&mut stream)
                    .await
                    .expect("tcp dns upstream should read frame")
                    .expect("tcp dns upstream should receive a query");
                let response = build_dns_noerror_response(&query);
                write_dns_tcp_message(&mut stream, &response)
                    .await
                    .expect("tcp dns upstream should write frame");
                DnsUpstreamObservation {
                    query,
                    path: None,
                    headers: BTreeMap::new(),
                }
            });
            (addr, task)
        }
        DnsUpstreamTransport::Tls => spawn_dns_tls_upstream("localhost").await,
        DnsUpstreamTransport::Https => spawn_dns_https_upstream("localhost").await,
    }
}

fn dns_server_tls_config(upstream: DnsUpstreamTransport) -> TrojanTlsConfig {
    TrojanTlsConfig {
        enabled: true,
        server_name: match upstream {
            DnsUpstreamTransport::Tls | DnsUpstreamTransport::Https => Some("localhost".into()),
            DnsUpstreamTransport::Udp | DnsUpstreamTransport::Tcp => None,
        },
        disable_sni: false,
        insecure: matches!(
            upstream,
            DnsUpstreamTransport::Tls | DnsUpstreamTransport::Https
        ),
        certificate_path: None,
        ca_path: None,
        handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
    }
}

fn dns_server_path(upstream: DnsUpstreamTransport) -> Option<String> {
    match upstream {
        DnsUpstreamTransport::Https => Some("/dns-query".into()),
        _ => None,
    }
}

fn dns_server_headers(upstream: DnsUpstreamTransport) -> BTreeMap<String, String> {
    match upstream {
        DnsUpstreamTransport::Https => {
            BTreeMap::from([(String::from("X-VeeX-Dns"), String::from("step-b"))])
        }
        _ => BTreeMap::new(),
    }
}

async fn run_dns_udp_client_round_trip(
    inbound_addr: SocketAddr,
    query: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|err| format!("failed to bind dns udp client: {err}"))?;
    let mut response = [0u8; 1024];

    for _ in 0..100 {
        client
            .send_to(&query, inbound_addr)
            .await
            .map_err(|err| format!("failed to send dns query: {err}"))?;
        match tokio::time::timeout(Duration::from_millis(50), client.recv_from(&mut response)).await
        {
            Ok(Ok((size, _peer))) => return Ok(response[..size].to_vec()),
            Ok(Err(err)) => return Err(format!("failed to receive dns response: {err}")),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }

    Err(format!(
        "dns udp inbound did not become ready on {inbound_addr}"
    ))
}

async fn run_dns_tcp_client_round_trip(
    inbound_addr: SocketAddr,
    query: Vec<u8>,
) -> Result<Vec<u8>, String> {
    wait_for_listener(inbound_addr).await;
    let mut stream = TcpStream::connect(inbound_addr)
        .await
        .map_err(|err| format!("failed to connect dns tcp client: {err}"))?;
    write_dns_tcp_message(&mut stream, &query)
        .await
        .map_err(|err| format!("failed to write dns tcp query: {err}"))?;
    let response = read_dns_tcp_message(&mut stream)
        .await
        .map_err(|err| format!("failed to read dns tcp response: {err}"))?
        .ok_or_else(|| "dns tcp client saw EOF before response".to_string())?;
    Ok(response)
}

fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    query
}

fn build_dns_noerror_response(query: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.len());
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&query[4..6]);
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    response.extend_from_slice(&query[12..]);
    response
}

fn build_dns_a_response(query: &[u8], ip: std::net::IpAddr) -> Vec<u8> {
    let query_name_len = query.len().saturating_sub(12);
    let mut response = Vec::with_capacity(query.len() + 32);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&query[4..6]);
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&query[12..12 + query_name_len]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    match ip {
        std::net::IpAddr::V4(ip) => {
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            response.extend_from_slice(&28u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&16u16.to_be_bytes());
            response.extend_from_slice(&ip.octets());
        }
    }
    response
}

fn parse_dns_query_name(query: &[u8]) -> String {
    parse_query_domain(query).expect("dns query name should parse")
}

async fn spawn_dns_answer_server(
    bind_ip: Ipv4Addr,
    answer_ip: std::net::IpAddr,
) -> (SocketAddr, tokio::task::JoinHandle<DnsUpstreamObservation>) {
    let socket = UdpSocket::bind((bind_ip, 0))
        .await
        .expect("bootstrap dns socket should bind");
    let addr = socket
        .local_addr()
        .expect("bootstrap dns socket addr should exist");
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (size, peer) = socket
            .recv_from(&mut buf)
            .await
            .expect("bootstrap dns server should receive query");
        let response = build_dns_a_response(&buf[..size], answer_ip);
        socket
            .send_to(&response, peer)
            .await
            .expect("bootstrap dns server should send response");
        DnsUpstreamObservation {
            query: buf[..size].to_vec(),
            path: None,
            headers: BTreeMap::new(),
        }
    });
    (addr, task)
}

async fn spawn_dns_tls_upstream(
    server_name: &str,
) -> (SocketAddr, tokio::task::JoinHandle<DnsUpstreamObservation>) {
    let acceptor = build_test_tls_acceptor(server_name);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("tls dns upstream should bind");
    let addr = listener
        .local_addr()
        .expect("tls dns upstream addr should exist");
    let task = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("tls dns upstream should accept");
        let mut stream = acceptor
            .accept(stream)
            .await
            .expect("tls dns upstream should accept tls");
        let query = read_dns_tcp_message(&mut stream)
            .await
            .expect("tls dns upstream should read frame")
            .expect("tls dns upstream should receive a query");
        let response = build_dns_noerror_response(&query);
        write_dns_tcp_message(&mut stream, &response)
            .await
            .expect("tls dns upstream should write frame");
        DnsUpstreamObservation {
            query,
            path: None,
            headers: BTreeMap::new(),
        }
    });
    (addr, task)
}

async fn spawn_dns_https_upstream(
    server_name: &str,
) -> (SocketAddr, tokio::task::JoinHandle<DnsUpstreamObservation>) {
    let acceptor = build_test_tls_acceptor(server_name);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("https dns upstream should bind");
    let addr = listener
        .local_addr()
        .expect("https dns upstream addr should exist");
    let task = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("https dns upstream should accept");
        let mut stream = acceptor
            .accept(stream)
            .await
            .expect("https dns upstream should accept tls");
        let (path, headers, query) = read_http1_request(&mut stream).await;
        let response = build_dns_noerror_response(&query);
        write_http1_dns_response(&mut stream, &response)
            .await
            .expect("https dns upstream should write response");
        DnsUpstreamObservation {
            query,
            path: Some(path),
            headers,
        }
    });
    (addr, task)
}

fn build_test_tls_acceptor(server_name: &str) -> TlsAcceptor {
    let certified = generate_simple_self_signed(vec![server_name.to_string()])
        .expect("certificate generation should succeed");
    let certificate = certified.cert.der().clone();
    let key = certified.key_pair.serialize_der();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.as_ref().to_vec())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)),
        )
        .expect("server config should build");
    TlsAcceptor::from(Arc::new(config))
}

async fn read_http1_request<S>(stream: &mut S) -> (String, BTreeMap<String, String>, Vec<u8>)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut head = Vec::new();
    loop {
        let byte = stream
            .read_u8()
            .await
            .expect("http request should remain readable");
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    head.truncate(head.len() - 4);
    let head = String::from_utf8(head).expect("http request head should be valid utf-8");
    let mut lines = head.split("\r\n");
    let request_line = lines.next().expect("http request line should exist");
    let mut request_parts = request_line.split_whitespace();
    assert_eq!(request_parts.next(), Some("POST"));
    let path = request_parts
        .next()
        .expect("http request path should exist")
        .to_string();

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .expect("http request header should contain ':'");
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    let content_length = headers
        .get("content-length")
        .expect("http request should include content-length")
        .parse::<usize>()
        .expect("content-length should be numeric");
    let mut body = vec![0u8; content_length];
    stream
        .read_exact(&mut body)
        .await
        .expect("http request body should read");

    (path, headers, body)
}

async fn write_http1_dns_response<S>(stream: &mut S, body: &[u8]) -> Result<(), String>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|err| format!("failed to write http response headers: {err}"))?;
    stream
        .write_all(body)
        .await
        .map_err(|err| format!("failed to write http response body: {err}"))?;
    stream
        .flush()
        .await
        .map_err(|err| format!("failed to flush http response: {err}"))?;
    Ok(())
}

async fn reserve_udp_port() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("temporary udp socket should bind");
    socket
        .local_addr()
        .expect("temporary udp addr should exist")
}

struct TrojanServerResult {
    request: Vec<u8>,
    payload: Vec<u8>,
}

struct TestTrojanServer {
    addr: SocketAddr,
    certificate_path: PathBuf,
    handle: tokio::task::JoinHandle<TrojanServerResult>,
}

async fn spawn_trojan_server(server_name: &str, destination: Destination) -> TestTrojanServer {
    spawn_trojan_server_with_mode(
        server_name,
        destination,
        "secret",
        TrojanServerMode::EchoPayload,
    )
    .await
}

async fn spawn_rejecting_trojan_server(
    server_name: &str,
    destination: Destination,
    expected_password: &str,
) -> TestTrojanServer {
    spawn_trojan_server_with_mode(
        server_name,
        destination,
        expected_password,
        TrojanServerMode::RejectAfterPayloadRead,
    )
    .await
}

async fn spawn_trojan_server_with_mode(
    server_name: &str,
    destination: Destination,
    expected_password: &str,
    mode: TrojanServerMode,
) -> TestTrojanServer {
    let certified = generate_simple_self_signed(vec![server_name.to_string()])
        .expect("certificate generation should succeed");
    let certificate = certified.cert.der().clone();
    let key = certified.key_pair.serialize_der();
    let certificate_path = write_temp_certificate(certificate.as_ref(), "veex-cli-trojan");

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.as_ref().to_vec())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)),
        )
        .expect("server config should build");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("trojan listener should bind");
    let addr = listener
        .local_addr()
        .expect("trojan listener should expose local addr");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let expected_request_len = build_trojan_request(expected_password, &destination, &[])
        .expect("request builder should succeed")
        .len();

    let handle = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("trojan accept should succeed");
        let mut stream = acceptor
            .accept(stream)
            .await
            .expect("trojan tls accept should succeed");

        let mut request = vec![0u8; expected_request_len];
        stream
            .read_exact(&mut request)
            .await
            .expect("trojan server should read request");

        let mut payload = vec![0u8; 4];
        stream
            .read_exact(&mut payload)
            .await
            .expect("trojan server should read payload");

        match mode {
            TrojanServerMode::EchoPayload => {
                stream
                    .write_all(&payload)
                    .await
                    .expect("trojan server should echo payload");
            }
            TrojanServerMode::RejectAfterPayloadRead => {
                let _ = stream.shutdown().await;
            }
        }

        TrojanServerResult { request, payload }
    });

    TestTrojanServer {
        addr,
        certificate_path,
        handle,
    }
}

#[derive(Clone, Copy)]
enum TrojanServerMode {
    EchoPayload,
    RejectAfterPayloadRead,
}

fn write_temp_certificate(certificate_der: &[u8], prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{nanos}.pem"));
    let pem = pem_encode_certificate(certificate_der);
    fs::write(&path, pem).expect("temporary certificate should be written");
    path
}

fn pem_encode_certificate(certificate_der: &[u8]) -> String {
    let mut encoded = String::new();
    encoded.push_str("-----BEGIN CERTIFICATE-----\n");

    for chunk in base64_encode(certificate_der).as_bytes().chunks(64) {
        encoded.push_str(std::str::from_utf8(chunk).expect("base64 must be valid utf-8"));
        encoded.push('\n');
    }

    encoded.push_str("-----END CERTIFICATE-----\n");
    encoded
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut index = 0;
    while index < bytes.len() {
        let b0 = bytes[index];
        let b1 = bytes.get(index + 1).copied();
        let b2 = bytes.get(index + 2).copied();

        output.push(TABLE[(b0 >> 2) as usize] as char);
        output.push(TABLE[(((b0 & 0x03) << 4) | (b1.unwrap_or(0) >> 4)) as usize] as char);

        match (b1, b2) {
            (Some(b1), Some(b2)) => {
                output.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
                output.push(TABLE[(b2 & 0x3f) as usize] as char);
            }
            (Some(b1), None) => {
                output.push(TABLE[((b1 & 0x0f) << 2) as usize] as char);
                output.push('=');
            }
            (None, _) => {
                output.push('=');
                output.push('=');
            }
        }

        index += 3;
    }

    output
}
