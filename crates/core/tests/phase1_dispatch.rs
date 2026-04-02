use veex_core::Router;

#[test]
fn router_can_bypass_configured_trojan_server_host() {
    let router = Router::new("proxy", "direct").with_bypass_host("trojan.example.com");
    let ctx = veex_core::SessionContext::new(
        veex_core::SessionMeta {
            id: 1,
            network: veex_core::Network::Tcp,
            inbound_tag: "socks-in".into(),
            peer: std::net::SocketAddr::from(([127, 0, 0, 1], 30000)),
            destination: veex_core::Destination::from_domain("trojan.example.com", 443),
            start: std::time::Instant::now(),
        },
        Vec::new(),
    );

    let decision = router.select(&ctx);
    assert_eq!(decision.outbound_tag, "direct");
}
