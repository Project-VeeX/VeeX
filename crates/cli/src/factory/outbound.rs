use std::{collections::HashMap, sync::Arc};

use veex_config::{ProxyConfig, DEFAULT_DIRECT_OUTBOUND_TAG};
use veex_core::{
    logging::Logger,
    portal::{Dial, Outbound, OutboundMeta},
    ProxyError,
};
use veex_execution::{ExecutionOutbound, OutboundCatalog};
use veex_portal_outbound::direct::{
    build_dialer as build_direct_dialer, build_packet_dialer as build_direct_packet_dialer,
    DirectOutbound,
};
use veex_portal_outbound::trojan::{build_dialer as build_trojan_dialer, TrojanOutbound};

use crate::factory::{lower_outbound, LoweredOutbound, RuntimeServices};

const IMPLICIT_DIRECT_OUTBOUND_TAG: &str = "implicit-direct";

type ExecutionHandle = Arc<dyn ExecutionOutbound>;
type LifecycleHandle = Arc<dyn Outbound>;
type ImplicitDirect = (ExecutionHandle, Option<LifecycleHandle>);

pub(crate) struct RuntimeOutbounds {
    catalog: Arc<OutboundCatalog>,
    lifecycle: Vec<LifecycleHandle>,
}

impl RuntimeOutbounds {
    pub(crate) fn new(catalog: Arc<OutboundCatalog>, lifecycle: Vec<LifecycleHandle>) -> Self {
        Self { catalog, lifecycle }
    }

    pub(crate) fn catalog(&self) -> &Arc<OutboundCatalog> {
        &self.catalog
    }

    pub(crate) fn contains(&self, tag: &str) -> bool {
        self.catalog.contains(tag)
    }

    pub(crate) fn lifecycle(&self) -> impl Iterator<Item = &LifecycleHandle> + '_ {
        self.lifecycle.iter()
    }

    pub(crate) fn len(&self) -> usize {
        self.lifecycle.len()
    }
}

pub fn build_outbounds(
    config: &ProxyConfig,
    services: &RuntimeServices,
) -> Result<Arc<RuntimeOutbounds>, ProxyError> {
    let mut catalog_entries: HashMap<String, ExecutionHandle> = HashMap::new();
    let mut lifecycle: Vec<LifecycleHandle> = Vec::new();
    let mut configured_default_direct: Option<ExecutionHandle> = None;

    for outbound in config.outbounds.iter().map(lower_outbound) {
        match outbound {
            LoweredOutbound::Direct(direct) => {
                let logger = Logger::new(direct.meta.tag.clone(), direct.meta.r#type.clone());
                let dialer =
                    build_direct_dialer(direct.dial.clone(), Arc::clone(&services.host_resolver))?;
                let packet_dialer =
                    build_direct_packet_dialer(direct.dial, Arc::clone(&services.host_resolver))?;
                let instance = Arc::new(DirectOutbound::new(
                    direct.meta,
                    logger,
                    dialer,
                    packet_dialer,
                )?);
                let execution: ExecutionHandle = instance.clone();
                let lifecycle_outbound: LifecycleHandle = instance;
                if lifecycle_outbound.meta().tag == DEFAULT_DIRECT_OUTBOUND_TAG {
                    configured_default_direct = Some(Arc::clone(&execution));
                }
                register_outbound(
                    &mut catalog_entries,
                    &mut lifecycle,
                    execution,
                    lifecycle_outbound,
                )?;
            }
            LoweredOutbound::Trojan(trojan) => {
                let logger = Logger::new(trojan.meta.tag.clone(), trojan.meta.r#type.clone());
                let dialer = build_trojan_dialer(trojan.dial, Arc::clone(&services.host_resolver));
                let instance = Arc::new(TrojanOutbound::new(
                    trojan.meta,
                    logger,
                    dialer,
                    trojan.upstream_addr,
                    trojan.key,
                    trojan.tls,
                )?);
                let execution: ExecutionHandle = instance.clone();
                let lifecycle_outbound: LifecycleHandle = instance;
                register_outbound(
                    &mut catalog_entries,
                    &mut lifecycle,
                    execution,
                    lifecycle_outbound,
                )?;
            }
        }
    }

    let (default_outbound, default_lifecycle) = match configured_default_direct {
        Some(outbound) => (outbound, None),
        None => build_implicit_direct_outbound(services)?,
    };

    if let Some(default_lifecycle) = default_lifecycle {
        lifecycle.push(default_lifecycle);
    }

    Ok(Arc::new(RuntimeOutbounds::new(
        Arc::new(OutboundCatalog::new(catalog_entries, default_outbound)),
        lifecycle,
    )))
}

fn build_implicit_direct_outbound(
    services: &RuntimeServices,
) -> Result<ImplicitDirect, ProxyError> {
    let dialer = build_direct_dialer(Dial::default(), Arc::clone(&services.host_resolver))?;
    let packet_dialer =
        build_direct_packet_dialer(Dial::default(), Arc::clone(&services.host_resolver))?;
    let instance = Arc::new(DirectOutbound::new(
        OutboundMeta::new(IMPLICIT_DIRECT_OUTBOUND_TAG, "direct"),
        Logger::new(IMPLICIT_DIRECT_OUTBOUND_TAG, "direct"),
        dialer,
        packet_dialer,
    )?);
    Ok((
        instance.clone() as ExecutionHandle,
        Some(instance as LifecycleHandle),
    ))
}

fn register_outbound(
    catalog_entries: &mut HashMap<String, ExecutionHandle>,
    lifecycle: &mut Vec<LifecycleHandle>,
    outbound: ExecutionHandle,
    lifecycle_outbound: LifecycleHandle,
) -> Result<(), ProxyError> {
    let tag = outbound.tag().to_string();
    if catalog_entries
        .insert(tag.clone(), Arc::clone(&outbound))
        .is_some()
    {
        return Err(ProxyError::config(format!(
            "duplicate outbound tag in registry: {tag}"
        )));
    }

    lifecycle.push(lifecycle_outbound);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Instant,
    };

    use veex_config::{
        DirectOutboundConfig, LogConfig, OutboundConfig, ProxyConfig, RouteConfig,
        TrojanOutboundConfig, TrojanTlsConfig, DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_DIRECT_OUTBOUND_TAG, DEFAULT_TLS_HANDSHAKE_TIMEOUT,
    };
    use veex_core::{
        session::{SessionContext, SessionMeta},
        types::{Destination, Host, Network},
        ErrorKind,
    };

    use super::{build_outbounds, IMPLICIT_DIRECT_OUTBOUND_TAG};
    use crate::factory::RuntimeServices;

    fn test_context(outbound_tag: &str) -> SessionContext {
        SessionContext::new(
            SessionMeta {
                id: 7,
                network: Network::Tcp,
                inbound_tag: "socks-in".into(),
                peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30000),
                destination: Destination::new(Host::Domain(format!("{outbound_tag}.example")), 443),
                start: Instant::now(),
            },
            Vec::new(),
        )
    }

    #[tokio::test]
    async fn closing_registry_direct_outbound_is_visible_to_dispatch_view() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
                domain_resolver: None,
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
                rules: Vec::new(),
            },
        };
        let built =
            build_outbounds(&config, &RuntimeServices::default()).expect("outbounds should build");
        let registry_outbound = built
            .lifecycle()
            .next()
            .expect("runtime should contain direct outbound");
        registry_outbound
            .close()
            .await
            .expect("registry direct outbound should close");

        let route_outbound = built
            .catalog()
            .get("direct")
            .expect("dispatch view should contain direct outbound");
        let err = match route_outbound.open_stream(&test_context("direct")).await {
            Ok(_) => panic!("dispatch view should observe shutdown"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::Shutdown);
    }

    #[tokio::test]
    async fn closing_registry_trojan_outbound_is_visible_to_dispatch_view() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: "proxy".into(),
                server: "127.0.0.1".into(),
                server_port: 443,
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
            })],
            route: RouteConfig {
                final_outbound: "proxy".into(),
                rules: Vec::new(),
            },
        };
        let built =
            build_outbounds(&config, &RuntimeServices::default()).expect("outbounds should build");
        let registry_outbound = built
            .lifecycle()
            .next()
            .expect("runtime should contain trojan outbound");
        registry_outbound
            .close()
            .await
            .expect("registry trojan outbound should close");

        let route_outbound = built
            .catalog()
            .get("proxy")
            .expect("dispatch view should contain trojan outbound");
        let err = match route_outbound.open_stream(&test_context("proxy")).await {
            Ok(_) => panic!("dispatch view should observe shutdown"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::Shutdown);
    }

    #[test]
    fn build_outbounds_installs_implicit_default_direct_when_tag_direct_is_missing() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: "proxy".into(),
                server: "127.0.0.1".into(),
                server_port: 443,
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
            })],
            route: RouteConfig {
                final_outbound: "proxy".into(),
                rules: Vec::new(),
            },
        };

        let built =
            build_outbounds(&config, &RuntimeServices::default()).expect("outbounds should build");
        let default = built.catalog().default_outbound();

        assert_eq!(default.tag(), IMPLICIT_DIRECT_OUTBOUND_TAG);
    }

    #[test]
    fn build_outbounds_does_not_treat_non_direct_tag_direct_as_default() {
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig::Trojan(TrojanOutboundConfig {
                tag: DEFAULT_DIRECT_OUTBOUND_TAG.into(),
                server: "127.0.0.1".into(),
                server_port: 443,
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
            })],
            route: RouteConfig {
                final_outbound: DEFAULT_DIRECT_OUTBOUND_TAG.into(),
                rules: Vec::new(),
            },
        };

        let built =
            build_outbounds(&config, &RuntimeServices::default()).expect("outbounds should build");
        let default = built.catalog().default_outbound();

        assert_eq!(default.tag(), IMPLICIT_DIRECT_OUTBOUND_TAG);
    }
}
