use std::{net::IpAddr, str::FromStr};

use veex_config::{
    DnsConfig, DnsRuleConfig, DnsServerTypeConfig, InboundConfig, OutboundConfig,
    RouteActionConfig, RouteConfig, RouteFinalActionConfig, RouteRuleConfig,
    RouteUpgradeActionConfig, TrojanTlsConfig,
};
use veex_core::{
    Destination, Dial, Host, InboundMeta, Listen, Network, OutboundMeta, RouteAction,
    RouteFinalAction, RouteRule, RouteTarget, RouteUpgradeAction, SniffAction,
};
use veex_dns::{
    DnsHttpsOptions, DnsRule, DnsRuntimeConfig, DnsServer, DnsServerTransport, DEFAULT_DOH_PATH,
};
use veex_transport::TlsClientOptions;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredSocksInbound {
    pub(crate) meta: InboundMeta,
    pub(crate) listen: Listen,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LoweredDirectNetwork {
    Tcp,
    Udp,
    Both,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredDirectInbound {
    pub(crate) meta: InboundMeta,
    pub(crate) listen: Listen,
    pub(crate) network: LoweredDirectNetwork,
    pub(crate) override_host: Option<Host>,
    pub(crate) override_port: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredRedirectInbound {
    pub(crate) meta: InboundMeta,
    pub(crate) listen: Listen,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredTProxyInbound {
    pub(crate) meta: InboundMeta,
    pub(crate) listen: Listen,
    pub(crate) network: Network,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LoweredInbound {
    Direct(LoweredDirectInbound),
    Socks(LoweredSocksInbound),
    Redirect(LoweredRedirectInbound),
    TProxy(LoweredTProxyInbound),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredDirectOutbound {
    pub(crate) meta: OutboundMeta,
    pub(crate) dial: Dial,
}

#[derive(Clone, Debug)]
pub(crate) struct LoweredTrojanOutbound {
    pub(crate) meta: OutboundMeta,
    pub(crate) dial: Dial,
    pub(crate) upstream_addr: Destination,
    pub(crate) key: String,
    pub(crate) tls: TlsClientOptions,
}

#[derive(Clone, Debug)]
pub(crate) enum LoweredOutbound {
    Direct(LoweredDirectOutbound),
    Trojan(LoweredTrojanOutbound),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredRoute {
    pub(crate) default_final_action: RouteFinalAction,
    pub(crate) rules: Vec<RouteRule>,
}

pub(crate) fn lower_inbound(inbound: &InboundConfig) -> LoweredInbound {
    match inbound {
        InboundConfig::Direct(config) => LoweredInbound::Direct(LoweredDirectInbound {
            meta: InboundMeta::new(config.tag.clone(), "direct"),
            listen: Listen::new(config.listen.clone(), config.listen_port),
            network: normalize_direct_network(config.network.as_deref()),
            override_host: config.override_address.as_deref().map(parse_host),
            override_port: config.override_port,
        }),
        InboundConfig::Socks(config) => LoweredInbound::Socks(LoweredSocksInbound {
            meta: InboundMeta::new(config.tag.clone(), "socks"),
            listen: Listen::new(config.listen.clone(), config.listen_port),
        }),
        InboundConfig::Redirect(config) => LoweredInbound::Redirect(LoweredRedirectInbound {
            meta: InboundMeta::new(config.tag.clone(), "redirect"),
            listen: Listen::new(config.listen.clone(), config.listen_port),
        }),
        InboundConfig::TProxy(config) => LoweredInbound::TProxy(LoweredTProxyInbound {
            meta: InboundMeta::new(config.tag.clone(), "tproxy"),
            listen: Listen::new(config.listen.clone(), config.listen_port),
            network: normalize_tproxy_network(config.network.as_deref()),
        }),
    }
}

pub(crate) fn lower_outbound(outbound: &OutboundConfig) -> LoweredOutbound {
    match outbound {
        OutboundConfig::Direct(config) => LoweredOutbound::Direct(LoweredDirectOutbound {
            meta: OutboundMeta::new(config.tag.clone(), "direct"),
            dial: Dial {
                timeout: Some(config.connect_timeout),
                routing_mark: config.routing_mark,
                domain_resolver: config
                    .domain_resolver
                    .as_ref()
                    .map(|resolver| resolver.server.clone()),
            },
        }),
        OutboundConfig::Trojan(config) => LoweredOutbound::Trojan(LoweredTrojanOutbound {
            meta: OutboundMeta::new(config.tag.clone(), "trojan"),
            dial: Dial {
                timeout: Some(config.connect_timeout),
                routing_mark: None,
                domain_resolver: config
                    .domain_resolver
                    .as_ref()
                    .map(|resolver| resolver.server.clone()),
            },
            upstream_addr: Destination::new(parse_host(&config.server), config.server_port),
            key: config.password.clone(),
            tls: lower_tls_options(&config.tls),
        }),
    }
}

pub(crate) fn lower_route(route: &RouteConfig) -> LoweredRoute {
    LoweredRoute {
        default_final_action: RouteFinalAction::Route(RouteTarget::new(
            route.final_outbound.clone(),
        )),
        rules: route.rules.iter().map(lower_route_rule).collect(),
    }
}

pub(crate) fn lower_dns(dns: &DnsConfig) -> DnsRuntimeConfig {
    DnsRuntimeConfig {
        final_server_tag: dns.final_server.clone(),
        servers: dns.servers.iter().map(lower_dns_server).collect(),
        rules: dns.rules.iter().map(lower_dns_rule).collect(),
    }
}

fn lower_route_rule(rule: &RouteRuleConfig) -> RouteRule {
    RouteRule {
        domain: rule.domain.clone(),
        domain_suffix: rule.domain_suffix.clone(),
        ip_cidr: rule.ip_cidr.clone(),
        ip_is_private: rule.ip_is_private,
        ip_is_loopback: rule.ip_is_loopback,
        ip_is_link_local: rule.ip_is_link_local,
        port: rule.port.clone(),
        inbound: rule.inbound.clone(),
        action: lower_route_action(&rule.action),
    }
}

fn lower_route_action(action: &RouteActionConfig) -> RouteAction {
    match action {
        RouteActionConfig::Upgrade(RouteUpgradeActionConfig::Sniff(sniff)) => {
            RouteAction::Upgrade(RouteUpgradeAction::Sniff(SniffAction {
                timeout: sniff.timeout,
            }))
        }
        RouteActionConfig::Final(RouteFinalActionConfig::Route(target)) => RouteAction::Final(
            RouteFinalAction::Route(RouteTarget::new(target.outbound.clone())),
        ),
        RouteActionConfig::Final(RouteFinalActionConfig::HijackDns) => {
            RouteAction::Final(RouteFinalAction::HijackDns)
        }
    }
}

fn lower_dns_server(server: &veex_config::DnsServerConfig) -> DnsServer {
    DnsServer {
        tag: server.tag.clone(),
        transport: match &server.kind {
            DnsServerTypeConfig::Local => DnsServerTransport::Local,
            DnsServerTypeConfig::Udp => DnsServerTransport::Udp,
            DnsServerTypeConfig::Tcp => DnsServerTransport::Tcp,
            DnsServerTypeConfig::Tls => DnsServerTransport::Tls(lower_tls_options(&server.tls)),
            DnsServerTypeConfig::Https => DnsServerTransport::Https(DnsHttpsOptions {
                path: server
                    .path
                    .clone()
                    .unwrap_or_else(|| DEFAULT_DOH_PATH.to_string()),
                headers: server.headers.clone(),
                tls: lower_tls_options(&server.tls),
            }),
            DnsServerTypeConfig::Unsupported(kind) => DnsServerTransport::Unsupported(kind.clone()),
        },
        destination: match &server.kind {
            DnsServerTypeConfig::Local => Destination::new(Host::Domain("local".into()), 53),
            _ => Destination::new(parse_host(&server.server), server.server_port),
        },
        detour: server.detour.clone(),
        domain_resolver: server
            .domain_resolver
            .as_ref()
            .map(|resolver| resolver.server.clone()),
    }
}

fn lower_dns_rule(rule: &DnsRuleConfig) -> DnsRule {
    DnsRule {
        domain: rule.domain.clone(),
        server_tag: rule.server.clone(),
    }
}

fn lower_tls_options(config: &TrojanTlsConfig) -> TlsClientOptions {
    TlsClientOptions {
        enabled: config.enabled,
        server_name: config.server_name.clone(),
        disable_sni: config.disable_sni,
        insecure: config.insecure,
        certificate_path: config.certificate_path.clone(),
        ca_path: config.ca_path.clone(),
        handshake_timeout: config.handshake_timeout,
    }
}

fn normalize_tproxy_network(_network: Option<&str>) -> Network {
    Network::Tcp
}

fn normalize_direct_network(network: Option<&str>) -> LoweredDirectNetwork {
    match network {
        Some("tcp") => LoweredDirectNetwork::Tcp,
        Some("udp") => LoweredDirectNetwork::Udp,
        None => LoweredDirectNetwork::Both,
        Some(_) => unreachable!("config validation should reject unsupported direct networks"),
    }
}

fn parse_host(value: &str) -> Host {
    match IpAddr::from_str(value) {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(value.to_string()),
    }
}
