use veex_config::{
    RouteActionConfig, RouteConfig, RouteFinalActionConfig, RouteRuleConfig,
    RouteUpgradeActionConfig,
};
use veex_router::{
    RouteAction, RouteFinalAction, RouteRule, RouteTarget, RouteUpgradeAction, SniffAction,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredRoute {
    pub(crate) default_final_action: RouteFinalAction,
    pub(crate) rules: Vec<RouteRule>,
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
        RouteActionConfig::Final(RouteFinalActionConfig::HijackDns) => {
            RouteAction::Final(RouteFinalAction::HijackDns)
        }
    }
}
