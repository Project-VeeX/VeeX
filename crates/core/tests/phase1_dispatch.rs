use veex_core::{
    routing::{RouteRule, Router},
    session::{SessionContext, SessionMeta},
    types::{Destination, Network},
};

#[test]
fn router_can_route_exact_domain_to_direct() {
    let router = Router::with_default_outbound("proxy").with_rule(RouteRule {
        domain: vec!["trojan.example.com".into()],
        ..RouteRule::new("direct")
    });
    let ctx = SessionContext::new(
        SessionMeta {
            id: 1,
            network: Network::Tcp,
            inbound_tag: "socks-in".into(),
            peer: std::net::SocketAddr::from(([127, 0, 0, 1], 30000)),
            destination: Destination::from_domain("trojan.example.com", 443),
            start: std::time::Instant::now(),
        },
        Vec::new(),
    );

    let decision = router.select(&ctx);
    assert_eq!(decision.outbound_tag(), Some("direct"));
}
