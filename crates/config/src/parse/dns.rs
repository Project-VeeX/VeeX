use crate::{
    error::ConfigError,
    input::{InputDnsConfig, InputDnsRule, InputDnsRuleActionValue, InputDnsServer},
    schema::{DnsConfig, DnsRuleConfig, DnsServerConfig, DnsServerTypeConfig},
};

use super::{
    DEFAULT_DNS_SERVER_PORT, DEFAULT_DOH_PATH, DEFAULT_DOH_SERVER_PORT, DEFAULT_DOT_SERVER_PORT,
    shared::{
        DomainMatcherKind, dial_fields, input_tls_fields_into_config, input_tls_fields_or_default,
        nested_port_or_default, normalize_domain_matchers, optional_nested_string,
        optional_string_map, parse_dns_server_type, required_nested_string,
    },
};

pub(crate) fn input_dns_into_config(
    input_config: InputDnsConfig,
) -> Result<DnsConfig, ConfigError> {
    let servers = input_config
        .servers
        .into_iter()
        .enumerate()
        .map(|(index, server)| input_dns_server_into_config(server, index))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(DnsConfig {
        final_server: parse_dns_final_server(input_config.final_server, &servers)?,
        disable_cache: input_config.disable_cache,
        cache_capacity: input_config.cache_capacity,
        servers,
        rules: input_config
            .rules
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(index, rule)| input_dns_rule_into_config(rule, index))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub(crate) fn input_dns_server_into_config(
    input_server: InputDnsServer,
    index: usize,
) -> Result<DnsServerConfig, ConfigError> {
    let kind = parse_dns_server_type(input_server.kind);
    let server = if matches!(kind, DnsServerTypeConfig::Local) {
        optional_nested_string(
            input_server.server,
            format!("$.dns.servers[{index}].server"),
        )?
        .unwrap_or_default()
    } else {
        required_nested_string(
            input_server.server,
            format!("$.dns.servers[{index}].server"),
        )?
    };
    let detour = optional_nested_string(
        input_server.detour,
        format!("$.dns.servers[{index}].detour"),
    )?
    .filter(|detour| !detour.is_empty());

    Ok(DnsServerConfig {
        tag: input_server.tag,
        kind: kind.clone(),
        server,
        server_port: nested_port_or_default(
            input_server.server_port,
            format!("$.dns.servers[{index}].server_port"),
            default_dns_server_port(&kind),
        )?,
        path: optional_nested_string(input_server.path, format!("$.dns.servers[{index}].path"))?
            .or_else(|| {
                if matches!(kind, DnsServerTypeConfig::Https) {
                    Some(DEFAULT_DOH_PATH.to_string())
                } else {
                    None
                }
            }),
        headers: optional_string_map(
            input_server.headers,
            format!("$.dns.servers[{index}].headers"),
        )?,
        dial: dial_fields(
            detour,
            input_server.connect_timeout,
            input_server.routing_mark,
            input_server.domain_resolver,
            format!("$.dns.servers[{index}].domain_resolver"),
        )?,
        tls: input_tls_fields_into_config(input_tls_fields_or_default(
            input_server.tls,
            format!("$.dns.servers[{index}].tls"),
        )?),
    })
}

pub(crate) fn input_dns_rule_into_config(
    input_rule: InputDnsRule,
    index: usize,
) -> Result<DnsRuleConfig, ConfigError> {
    let disable_cache = match &input_rule.action {
        Some(InputDnsRuleActionValue::Kind(action)) => match action.trim() {
            "route" => false,
            other => {
                return Err(ConfigError::semantic(
                    format!("$.dns.rules[{index}].action"),
                    format!("unsupported dns rule action '{other}'"),
                ));
            }
        },
        Some(InputDnsRuleActionValue::Structured(action)) => action.disable_cache,
        None => false,
    };

    Ok(DnsRuleConfig {
        domain: normalize_domain_matchers(
            input_rule.domain,
            format!("$.dns.rules[{index}].domain"),
            DomainMatcherKind::Exact,
        )?,
        server: required_nested_string(input_rule.server, format!("$.dns.rules[{index}].server"))?,
        disable_cache,
    })
}

fn default_dns_server_port(kind: &DnsServerTypeConfig) -> u16 {
    match kind {
        DnsServerTypeConfig::Local
        | DnsServerTypeConfig::Udp
        | DnsServerTypeConfig::Tcp
        | DnsServerTypeConfig::Unsupported(_) => DEFAULT_DNS_SERVER_PORT,
        DnsServerTypeConfig::Tls => DEFAULT_DOT_SERVER_PORT,
        DnsServerTypeConfig::Https => DEFAULT_DOH_SERVER_PORT,
    }
}

fn parse_dns_final_server(
    value: Option<Option<String>>,
    servers: &[DnsServerConfig],
) -> Result<String, ConfigError> {
    match value {
        Some(Some(value)) if !value.is_empty() => Ok(value),
        Some(Some(_)) | Some(None) | None => Ok(servers
            .first()
            .map(|server| server.tag.clone())
            .unwrap_or_default()),
    }
}
