use veex_config::{
    InboundConfig, OutboundConfig, RouteActionConfig, RouteConfig, RouteFinalActionConfig,
    RouteRuleConfig, RouteUpgradeActionConfig, TrojanTlsConfig,
};
use veex_core::{
    RouteAction, RouteFinalAction, RouteRule, RouteTarget, RouteUpgradeAction, SniffAction,
};
use veex_transport::TlsClientOptions;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredListenInbound {
    pub(crate) tag: String,
    pub(crate) listen: String,
    pub(crate) listen_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LoweredInbound {
    Socks(LoweredListenInbound),
    Redirect(LoweredListenInbound),
    TProxy(LoweredListenInbound),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredDirectOutbound {
    pub(crate) tag: String,
    pub(crate) connect_timeout: std::time::Duration,
    pub(crate) routing_mark: Option<u32>,
}

#[derive(Clone, Debug)]
pub(crate) struct LoweredTrojanOutbound {
    pub(crate) tag: String,
    pub(crate) server: String,
    pub(crate) server_port: u16,
    pub(crate) password: String,
    pub(crate) connect_timeout: std::time::Duration,
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
        InboundConfig::Socks(config) => LoweredInbound::Socks(LoweredListenInbound {
            tag: config.tag.clone(),
            listen: config.listen.clone(),
            listen_port: config.listen_port,
        }),
        InboundConfig::Redirect(config) => LoweredInbound::Redirect(LoweredListenInbound {
            tag: config.tag.clone(),
            listen: config.listen.clone(),
            listen_port: config.listen_port,
        }),
        InboundConfig::TProxy(config) => LoweredInbound::TProxy(LoweredListenInbound {
            tag: config.tag.clone(),
            listen: config.listen.clone(),
            listen_port: config.listen_port,
        }),
    }
}

pub(crate) fn lower_outbound(outbound: &OutboundConfig) -> LoweredOutbound {
    match outbound {
        OutboundConfig::Direct(config) => LoweredOutbound::Direct(LoweredDirectOutbound {
            tag: config.tag.clone(),
            connect_timeout: config.connect_timeout,
            routing_mark: config.routing_mark,
        }),
        OutboundConfig::Trojan(config) => LoweredOutbound::Trojan(LoweredTrojanOutbound {
            tag: config.tag.clone(),
            server: config.server.clone(),
            server_port: config.server_port,
            password: config.password.clone(),
            connect_timeout: config.connect_timeout,
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
