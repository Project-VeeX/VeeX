use crate::{
    defaults::DEFAULT_SNIFF_TIMEOUT,
    error::ConfigError,
    input::{InputRouteConfig, InputRouteRule},
    schema::{
        RouteActionConfig, RouteConfig, RouteFinalActionConfig, RouteRuleConfig, RouteTargetConfig,
        RouteUpgradeActionConfig, SniffActionConfig,
    },
};

use super::shared::{
    DomainMatcherKind, normalize_domain_matchers, parse_ip_cidr_matchers, parse_port_matchers,
    parse_string_matchers, required_nested_string,
};

pub(crate) fn input_route_into_config(
    input_config: InputRouteConfig,
) -> Result<RouteConfig, ConfigError> {
    Ok(RouteConfig {
        final_outbound: input_config.final_outbound,
        rules: input_config
            .rules
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(index, rule)| input_route_rule_into_config(rule, index))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub(crate) fn input_route_rule_into_config(
    input_rule: InputRouteRule,
    index: usize,
) -> Result<RouteRuleConfig, ConfigError> {
    let action = input_route_rule_action_into_config(&input_rule, index)?;
    Ok(RouteRuleConfig {
        domain: normalize_domain_matchers(
            input_rule.domain,
            format!("$.route.rules[{index}].domain"),
            DomainMatcherKind::Exact,
        )?,
        domain_suffix: normalize_domain_matchers(
            input_rule.domain_suffix,
            format!("$.route.rules[{index}].domain_suffix"),
            DomainMatcherKind::Suffix,
        )?,
        ip_cidr: parse_ip_cidr_matchers(
            input_rule.ip_cidr,
            format!("$.route.rules[{index}].ip_cidr"),
        )?,
        ip_is_private: input_rule.ip_is_private,
        ip_is_loopback: input_rule.ip_is_loopback,
        ip_is_link_local: input_rule.ip_is_link_local,
        port: parse_port_matchers(input_rule.port, format!("$.route.rules[{index}].port"))?,
        inbound: parse_string_matchers(
            input_rule.inbound,
            format!("$.route.rules[{index}].inbound"),
        )?,
        action,
    })
}

fn input_route_rule_action_into_config(
    input_rule: &InputRouteRule,
    index: usize,
) -> Result<RouteActionConfig, ConfigError> {
    if input_rule.timeout.is_some() && input_rule.action.is_none() {
        return Err(ConfigError::semantic(
            format!("$.route.rules[{index}].timeout"),
            "route rule timeout is only supported for action='sniff'",
        ));
    }

    match &input_rule.action {
        Some(Some(action)) => {
            if input_rule.outbound.is_some() {
                return Err(ConfigError::semantic(
                    format!("$.route.rules[{index}]"),
                    "route rule cannot set both action and outbound",
                ));
            }

            match action.trim() {
                "sniff" => Ok(RouteActionConfig::Upgrade(RouteUpgradeActionConfig::Sniff(
                    SniffActionConfig {
                        timeout: input_rule.timeout.unwrap_or(DEFAULT_SNIFF_TIMEOUT),
                    },
                ))),
                "hijack-dns" => Ok(RouteActionConfig::Final(RouteFinalActionConfig::HijackDns)),
                other => Err(ConfigError::semantic(
                    format!("$.route.rules[{index}].action"),
                    format!("unsupported route action '{other}'"),
                )),
            }
        }
        Some(None) => Err(ConfigError::validation(
            format!("$.route.rules[{index}].action"),
            "expected string",
        )),
        None => Ok(RouteActionConfig::Final(RouteFinalActionConfig::Route(
            RouteTargetConfig {
                outbound: required_nested_string(
                    input_rule.outbound.clone(),
                    format!("$.route.rules[{index}].outbound"),
                )?,
            },
        ))),
    }
}
