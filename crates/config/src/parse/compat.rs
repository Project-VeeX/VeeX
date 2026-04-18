use crate::{
    error::ConfigError,
    input::{InputConfig, InputDomainResolverValue, InputInboundType, InputOutboundType},
};

use super::{ParseDiagnostics, ParseIgnored, ParseWarning};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IgnoredDisposition {
    Ignore(&'static str),
    Warn(&'static str),
    Error(&'static str),
}

/// 历史兼容与 sing-box 对齐策略目前仍有一部分留在 parse 之后、validate 之前。
/// 本模块把这些 legacy compatibility 路径单独集中，避免继续混在 typed lowering 主路径里。
pub(crate) fn classify_ignored_paths(
    input_config: &InputConfig,
    mut ignored_paths: Vec<String>,
) -> Result<ParseDiagnostics, ConfigError> {
    ignored_paths.extend(protocol_extra_paths(input_config));

    let mut diagnostics = ParseDiagnostics::default();
    for path in ignored_paths {
        let Some(disposition) = classify_ignored_path(input_config, &path) else {
            continue;
        };

        match disposition {
            IgnoredDisposition::Warn(message) => {
                diagnostics.warnings.push(ParseWarning { path, message })
            }
            IgnoredDisposition::Ignore(message) => {
                diagnostics.ignored.push(ParseIgnored { path, message })
            }
            IgnoredDisposition::Error(message) => {
                return Err(ConfigError::semantic(path, message));
            }
        }
    }

    Ok(diagnostics)
}

fn protocol_extra_paths(input_config: &InputConfig) -> Vec<String> {
    let mut paths = Vec::new();

    if let Some(dns) = &input_config.dns {
        for field in dns.extra.keys() {
            paths.push(format!("$.dns.{field}"));
        }

        for (index, server) in dns.servers.iter().enumerate() {
            for field in server.extra.keys() {
                paths.push(format!("$.dns.servers[{index}].{field}"));
            }
            if let Some(InputDomainResolverValue::Structured(resolver)) = &server.domain_resolver {
                for field in resolver.extra.keys() {
                    paths.push(format!("$.dns.servers[{index}].domain_resolver.{field}"));
                }
            }
        }

        for (index, rule) in dns.rules.iter().flatten().enumerate() {
            for field in rule.extra.keys() {
                paths.push(format!("$.dns.rules[{index}].{field}"));
            }
        }
    }

    for (index, inbound) in input_config.inbounds.iter().enumerate() {
        for field in inbound.extra.keys() {
            paths.push(format!("$.inbounds[{index}].{field}"));
        }
    }

    for (index, outbound) in input_config.outbounds.iter().enumerate() {
        for field in outbound.extra.keys() {
            paths.push(format!("$.outbounds[{index}].{field}"));
        }
        if let Some(InputDomainResolverValue::Structured(resolver)) = &outbound.domain_resolver {
            for field in resolver.extra.keys() {
                paths.push(format!("$.outbounds[{index}].domain_resolver.{field}"));
            }
        }
    }

    paths
}

fn classify_ignored_path(input_config: &InputConfig, path: &str) -> Option<IgnoredDisposition> {
    if let Some((index, field)) = indexed_field(path, "$.inbounds[") {
        return match input_config.inbounds.get(index).map(|inbound| inbound.kind) {
            Some(InputInboundType::Direct) => classify_direct_inbound_ignored(field),
            Some(InputInboundType::Socks) => classify_socks_ignored(field),
            Some(InputInboundType::Redirect) => classify_redirect_ignored(field),
            Some(InputInboundType::Tproxy) => classify_tproxy_ignored(field),
            None => None,
        };
    }

    if let Some((index, field)) = indexed_field(path, "$.outbounds[") {
        return match input_config
            .outbounds
            .get(index)
            .map(|outbound| outbound.kind)
        {
            Some(InputOutboundType::Direct) => classify_direct_ignored(field),
            Some(InputOutboundType::Trojan) => classify_trojan_ignored(field),
            None => None,
        };
    }

    if indexed_field(path, "$.route.rules[").is_some() {
        return classify_route_rule_ignored(path);
    }

    if let Some(field) = path.strip_prefix("$.dns.") {
        return classify_dns_ignored(field);
    }

    match path {
        _ if path == "$.route.bypass" || path.starts_with("$.route.bypass[") => {
            Some(IgnoredDisposition::Error(
                "route.bypass has been removed; use route.rules with outbound='direct' instead",
            ))
        }
        "$.domain_resolver" => Some(IgnoredDisposition::Warn(
            "field is accepted for compatibility but ignored by the current config surface",
        )),
        "$.log.output" => Some(IgnoredDisposition::Ignore(
            "log compatibility field is accepted but ignored by the current config surface",
        )),
        _ => None,
    }
}

fn classify_socks_ignored(field: &str) -> Option<IgnoredDisposition> {
    Some(match first_segment(field) {
        "udp" | "sniff" | "sniff_override_destination" | "users" | "auth" => {
            IgnoredDisposition::Warn(
                "field is accepted for compatibility but does not affect the current socks inbound",
            )
        }
        "set_system_proxy" | "tcp_fast_open" => IgnoredDisposition::Ignore(
            "field is accepted for compatibility but ignored by the current socks inbound",
        ),
        _ => return None,
    })
}

fn classify_direct_inbound_ignored(field: &str) -> Option<IgnoredDisposition> {
    Some(match first_segment(field) {
        "udp" => IgnoredDisposition::Error(
            "direct inbound does not support UDP capability declarations in the current runtime",
        ),
        "sniff" | "sniff_override_destination" => IgnoredDisposition::Warn(
            "field is accepted for compatibility but does not affect the current direct inbound",
        ),
        "tcp_fast_open" | "udp_timeout" | "receive_original_destination" => {
            IgnoredDisposition::Ignore(
                "field is accepted for compatibility but ignored by the current direct inbound",
            )
        }
        _ => return None,
    })
}

fn classify_dns_ignored(field: &str) -> Option<IgnoredDisposition> {
    if let Some((_, nested)) = indexed_field(field, "servers[") {
        return Some(match first_segment(nested) {
            "address" | "domain_resolver" | "address_resolver" => IgnoredDisposition::Warn(
                "field is accepted for compatibility but does not affect the current dns server runtime",
            ),
            "client_subnet" => IgnoredDisposition::Ignore(
                "field is accepted for compatibility but ignored by the current dns server runtime",
            ),
            _ => return None,
        });
    }

    if let Some((_, nested)) = indexed_field(field, "rules[") {
        return Some(match first_segment(nested) {
            "disable_cache" | "strategy" => IgnoredDisposition::Ignore(
                "field is accepted for compatibility but ignored by the current dns rule runtime",
            ),
            _ => return None,
        });
    }

    Some(match first_segment(field) {
        "disable_cache" | "reverse_mapping" | "disable_expire" | "independent_cache" => {
            IgnoredDisposition::Ignore(
                "field is accepted for compatibility but ignored by the current dns subsystem",
            )
        }
        "strategy" | "client_subnet" | "cache_capacity" => IgnoredDisposition::Warn(
            "field is accepted for compatibility but does not affect the current dns subsystem",
        ),
        _ => return None,
    })
}

fn classify_redirect_ignored(field: &str) -> Option<IgnoredDisposition> {
    Some(match first_segment(field) {
        "sniff" | "sniff_override_destination" | "udp" => IgnoredDisposition::Warn(
            "field is accepted for compatibility but does not affect the current redirect inbound",
        ),
        "tcp_fast_open" | "receive_original_destination" => IgnoredDisposition::Ignore(
            "field is accepted for compatibility but ignored by the current redirect inbound",
        ),
        _ => return None,
    })
}

fn classify_tproxy_ignored(field: &str) -> Option<IgnoredDisposition> {
    Some(match first_segment(field) {
        "udp" => IgnoredDisposition::Error(
            "tproxy inbound does not support UDP capability declarations in the current runtime",
        ),
        "sniff" | "sniff_override_destination" => IgnoredDisposition::Warn(
            "field is accepted for compatibility but does not affect the current tproxy inbound",
        ),
        "tcp_fast_open" | "udp_timeout" => IgnoredDisposition::Ignore(
            "field is accepted for compatibility but ignored by the current tproxy inbound",
        ),
        _ => return None,
    })
}

fn classify_direct_ignored(field: &str) -> Option<IgnoredDisposition> {
    Some(match first_segment(field) {
        "bind_interface" | "domain_strategy" | "domain_resolver" | "ipv4_only" | "ipv6_only" => {
            IgnoredDisposition::Warn(
                "field is accepted for compatibility but does not affect the current direct outbound",
            )
        }
        "tcp_fast_open" | "fallback_delay" => IgnoredDisposition::Ignore(
            "field is accepted for compatibility but ignored by the current direct outbound",
        ),
        _ => return None,
    })
}

fn classify_trojan_ignored(field: &str) -> Option<IgnoredDisposition> {
    let field = first_segment(field);
    if matches!(
        field,
        "transport"
            | "mux"
            | "multiplex"
            | "packet_encoding"
            | "dialer_proxy"
            | "domain_resolver"
            | "reality"
            | "utls"
    ) || is_udp_related(field)
    {
        return Some(IgnoredDisposition::Warn(
            "field is accepted for compatibility but does not affect the current trojan outbound",
        ));
    }

    match field {
        "tcp_fast_open" => Some(IgnoredDisposition::Ignore(
            "field is accepted for compatibility but ignored by the current trojan outbound",
        )),
        _ => None,
    }
}

fn classify_route_rule_ignored(path: &str) -> Option<IgnoredDisposition> {
    let (_, field) = indexed_field(path, "$.route.rules[")?;

    match first_segment(field) {
        "domain" | "domain_suffix" | "ip_cidr" | "ip_is_private" | "ip_is_loopback"
        | "ip_is_link_local" | "port" | "inbound" | "outbound" | "action" | "timeout" => None,
        _ => Some(IgnoredDisposition::Error(
            "route rule field is not supported by the current route.rules subset",
        )),
    }
}

fn indexed_field<'a>(path: &'a str, prefix: &str) -> Option<(usize, &'a str)> {
    let rest = path.strip_prefix(prefix)?;
    let (index, rest) = rest.split_once(']')?;
    let index = index.parse().ok()?;
    let field = rest.strip_prefix('.')?;
    Some((index, field))
}

fn first_segment(field: &str) -> &str {
    field.split('.').next().unwrap_or(field)
}

fn is_udp_related(field: &str) -> bool {
    field == "udp" || field.starts_with("udp_")
}
