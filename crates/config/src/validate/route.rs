use std::collections::BTreeSet;

use crate::{
    error::ConfigError,
    schema::{ProxyConfig, RouteActionConfig, RouteFinalActionConfig, RouteRuleConfig},
};

pub(crate) fn validate_route(
    config: &ProxyConfig,
    outbound_tags: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    if !outbound_tags.contains(&config.route.final_outbound) {
        return Err(ConfigError::semantic(
            "$.route.final",
            format!(
                "route.final points to missing outbound '{}'",
                config.route.final_outbound
            ),
        ));
    }

    for (index, rule) in config.route.rules.iter().enumerate() {
        if matches!(
            rule.action,
            RouteActionConfig::Final(RouteFinalActionConfig::HijackDns)
        ) && config.dns.is_none()
        {
            return Err(ConfigError::semantic(
                format!("$.route.rules[{index}].action"),
                "route action 'hijack-dns' requires a dns section",
            ));
        }
        validate_route_rule(rule, index, outbound_tags)?;
    }

    Ok(())
}

fn validate_route_rule(
    rule: &RouteRuleConfig,
    index: usize,
    outbound_tags: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    if !rule.has_matcher() {
        return Err(ConfigError::semantic(
            format!("$.route.rules[{index}]"),
            "route rule requires at least one matcher",
        ));
    }

    match &rule.action {
        RouteActionConfig::Final(RouteFinalActionConfig::Route(target)) => {
            if !outbound_tags.contains(&target.outbound) {
                return Err(ConfigError::semantic(
                    format!("$.route.rules[{index}].outbound"),
                    format!(
                        "route rule points to missing outbound '{}'",
                        target.outbound
                    ),
                ));
            }
        }
        RouteActionConfig::Final(RouteFinalActionConfig::HijackDns) => {}
        RouteActionConfig::Upgrade(_) => {}
    }

    Ok(())
}
