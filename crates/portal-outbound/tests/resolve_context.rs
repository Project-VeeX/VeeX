use std::sync::{Arc, Mutex};

use veex_core::{
    ProxyError,
    dns::ResolveContext,
    portal::{Dial, DialContext},
    types::Host,
};
use veex_portal_outbound::{
    direct::build_dialer as build_direct_dialer, trojan::build_dialer as build_trojan_dialer,
};
use veex_transport::{HostResolveRequest, HostResolver};

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
            detour: None,
            connect_timeout: None,
            routing_mark: None,
            domain_resolver: Some("bootstrap".into()),
        },
        capture_contexts(Arc::clone(&direct_contexts)),
    )
    .expect("direct dialer should build");
    let trojan = build_trojan_dialer(
        Dial {
            detour: None,
            connect_timeout: None,
            routing_mark: None,
            domain_resolver: Some("bootstrap".into()),
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

#[tokio::test]
async fn direct_and_trojan_preserve_inherited_resolve_context() {
    let inherited = ResolveContext::outbound_dial("parent", Some("bootstrap".into())).with_depth(2);
    let direct_contexts = Arc::new(Mutex::new(Vec::new()));
    let trojan_contexts = Arc::new(Mutex::new(Vec::new()));
    let direct = build_direct_dialer(
        Dial {
            detour: None,
            connect_timeout: None,
            routing_mark: None,
            domain_resolver: Some("ignored".into()),
        },
        capture_contexts(Arc::clone(&direct_contexts)),
    )
    .expect("direct dialer should build");
    let trojan = build_trojan_dialer(
        Dial {
            detour: None,
            connect_timeout: None,
            routing_mark: None,
            domain_resolver: Some("ignored".into()),
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
        &[inherited.clone()]
    );
    assert_eq!(
        trojan_contexts
            .lock()
            .expect("trojan contexts should lock")
            .as_slice(),
        &[inherited]
    );
}
