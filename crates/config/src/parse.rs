use std::{fs, path::Path};

use ipnet::IpNet;

use crate::{
    defaults::{
        DEFAULT_CONNECT_TIMEOUT, DEFAULT_LOG_LEVEL, DEFAULT_SNIFF_TIMEOUT,
        DEFAULT_TLS_HANDSHAKE_TIMEOUT,
    },
    error::{display_path, ConfigError},
    input::{
        InputConfig, InputInbound, InputInboundType, InputLogConfig, InputOutbound,
        InputOutboundType, InputRouteConfig, InputRouteRule, InputTrojanTlsConfig,
    },
    preflight::parse_json,
    schema::{
        DirectOutboundConfig, InboundConfig, LogConfig, OutboundConfig, ProxyConfig,
        RedirectInboundConfig, RouteActionConfig, RouteConfig, RouteFinalActionConfig,
        RouteRuleConfig, RouteTargetConfig, RouteUpgradeActionConfig, SniffActionConfig,
        SocksInboundConfig, TProxyInboundConfig, TrojanOutboundConfig, TrojanTlsConfig,
    },
    validate::validate_config,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParseDiagnostics {
    pub warnings: Vec<ParseWarning>,
    pub ignored: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseWarning {
    pub path: String,
    pub message: &'static str,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
struct ParseReport {
    config: ProxyConfig,
    diagnostics: ParseDiagnostics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IgnoredDisposition {
    Ignore,
    Warn(&'static str),
    Error(&'static str),
}

pub fn load_from_path(path: impl AsRef<Path>) -> Result<ProxyConfig, ConfigError> {
    let config = load_from_path_unvalidated(path)?;
    validate_config(&config)?;
    Ok(config)
}

pub fn load_from_path_with_diagnostics(
    path: impl AsRef<Path>,
) -> Result<(ProxyConfig, ParseDiagnostics), ConfigError> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        return Err(ConfigError::file_path(
            display_path(path),
            "path must not be empty",
        ));
    }

    let content = fs::read_to_string(path).map_err(|err| ConfigError::io_path(path, err))?;
    parse_config_with_diagnostics(&content)
}

pub fn load_from_path_unvalidated(path: impl AsRef<Path>) -> Result<ProxyConfig, ConfigError> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        return Err(ConfigError::file_path(
            display_path(path),
            "path must not be empty",
        ));
    }

    let content = fs::read_to_string(path).map_err(|err| ConfigError::io_path(path, err))?;
    parse_config_unvalidated(&content)
}

pub fn parse_config(input: &str) -> Result<ProxyConfig, ConfigError> {
    let config = parse_config_unvalidated(input)?;
    validate_config(&config)?;
    Ok(config)
}

pub fn parse_config_with_diagnostics(
    input: &str,
) -> Result<(ProxyConfig, ParseDiagnostics), ConfigError> {
    let ParseReport {
        config,
        diagnostics,
    } = parse_config_report_unvalidated(input)?;
    validate_config(&config)?;
    Ok((config, diagnostics))
}

pub fn parse_config_unvalidated(input: &str) -> Result<ProxyConfig, ConfigError> {
    Ok(parse_config_report_unvalidated(input)?.config)
}

fn parse_config_report_unvalidated(input: &str) -> Result<ParseReport, ConfigError> {
    // Preflight keeps duplicate-key rejection and the current JSON subset checks.
    // The typed config comes only from the serde pass below.
    preflight_json_input(input)?;

    let (input_config, ignored_paths) = deserialize_input_config(input)?;
    let diagnostics = classify_ignored_paths(&input_config, ignored_paths)?;
    let config = input_config_into_proxy_config(input_config)?;

    Ok(ParseReport {
        config,
        diagnostics,
    })
}

fn preflight_json_input(input: &str) -> Result<(), ConfigError> {
    let _ = parse_json(input)?;
    Ok(())
}

fn deserialize_input_config(input: &str) -> Result<(InputConfig, Vec<String>), ConfigError> {
    let mut ignored = Vec::new();
    let mut json_deserializer = serde_json::Deserializer::from_str(input);
    let mut track = serde_path_to_error::Track::new();
    let path_deserializer =
        serde_path_to_error::Deserializer::new(&mut json_deserializer, &mut track);
    let input_config = serde_ignored::deserialize(path_deserializer, |path| {
        ignored.push(normalize_path(&path.to_string()));
    })
    .map_err(|err| map_serde_error(err, Some(track.path().to_string())))?;
    json_deserializer
        .end()
        .map_err(|err| map_serde_error(err, None))?;

    Ok((input_config, ignored))
}

fn map_serde_error(err: serde_json::Error, path: Option<String>) -> ConfigError {
    let message = err.to_string();

    if err.is_data() {
        return ConfigError::validation(augment_path(path.unwrap_or_default(), &message), message);
    }

    ConfigError::json("$", message)
}

fn input_config_into_proxy_config(input_config: InputConfig) -> Result<ProxyConfig, ConfigError> {
    Ok(ProxyConfig {
        log: input_log_into_config(input_config.log),
        inbounds: input_config
            .inbounds
            .into_iter()
            .map(input_inbound_into_config)
            .collect(),
        outbounds: input_config
            .outbounds
            .into_iter()
            .enumerate()
            .map(|(index, outbound)| input_outbound_into_config(outbound, index))
            .collect::<Result<Vec<_>, _>>()?,
        route: input_route_into_config(input_config.route)?,
    })
}

fn input_log_into_config(input_config: InputLogConfig) -> LogConfig {
    LogConfig {
        level: input_config
            .level
            .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string()),
        disabled: input_config.disabled,
        timestamp: input_config.timestamp,
    }
}

fn input_inbound_into_config(input_config: InputInbound) -> InboundConfig {
    match input_config.kind {
        InputInboundType::Socks => InboundConfig::Socks(SocksInboundConfig {
            tag: input_config.tag,
            listen: input_config.listen,
            listen_port: input_config.listen_port,
        }),
        InputInboundType::Redirect => InboundConfig::Redirect(RedirectInboundConfig {
            tag: input_config.tag,
            listen: input_config.listen,
            listen_port: input_config.listen_port,
        }),
        InputInboundType::Tproxy => InboundConfig::TProxy(TProxyInboundConfig {
            tag: input_config.tag,
            listen: input_config.listen,
            listen_port: input_config.listen_port,
            network: input_config.network,
        }),
    }
}

fn input_outbound_into_config(
    input_config: InputOutbound,
    index: usize,
) -> Result<OutboundConfig, ConfigError> {
    match input_config.kind {
        InputOutboundType::Direct => Ok(OutboundConfig::Direct(DirectOutboundConfig {
            tag: input_config.tag,
            connect_timeout: input_config
                .connect_timeout
                .unwrap_or(DEFAULT_CONNECT_TIMEOUT),
            routing_mark: input_config.routing_mark,
        })),
        InputOutboundType::Trojan => Ok(OutboundConfig::Trojan(TrojanOutboundConfig {
            tag: input_config.tag,
            server: required_nested_string(
                input_config.server,
                format!("$.outbounds[{index}].server"),
            )?,
            server_port: required_nested_port(
                input_config.server_port,
                format!("$.outbounds[{index}].server_port"),
            )?,
            password: required_nested_string(
                input_config.password,
                format!("$.outbounds[{index}].password"),
            )?,
            connect_timeout: input_config
                .connect_timeout
                .unwrap_or(DEFAULT_CONNECT_TIMEOUT),
            tls: input_trojan_tls_into_config(input_trojan_tls_or_default(
                input_config.tls,
                format!("$.outbounds[{index}].tls"),
            )?),
        })),
    }
}

fn input_trojan_tls_into_config(input_config: InputTrojanTlsConfig) -> TrojanTlsConfig {
    TrojanTlsConfig {
        enabled: input_config.enabled,
        server_name: input_config.server_name,
        disable_sni: input_config.disable_sni,
        insecure: input_config.insecure,
        certificate_path: input_config.certificate_path,
        ca_path: input_config.ca_path,
        handshake_timeout: input_config
            .handshake_timeout
            .unwrap_or(DEFAULT_TLS_HANDSHAKE_TIMEOUT),
    }
}

fn input_route_into_config(input_config: InputRouteConfig) -> Result<RouteConfig, ConfigError> {
    Ok(RouteConfig {
        final_outbound: input_config.final_outbound,
        bypass: input_config.bypass.unwrap_or_default(),
        rules: input_config
            .rules
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(index, rule)| input_route_rule_into_config(rule, index))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn input_route_rule_into_config(
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

fn required_nested_string(
    value: Option<Option<String>>,
    path: impl Into<String>,
) -> Result<String, ConfigError> {
    let path = path.into();
    match value {
        Some(Some(value)) => Ok(value),
        Some(None) => Err(ConfigError::validation(path, "expected string")),
        None => Err(ConfigError::validation(path, "field is required")),
    }
}

fn required_nested_port(
    value: Option<Option<u16>>,
    path: impl Into<String>,
) -> Result<u16, ConfigError> {
    let path = path.into();
    match value {
        Some(Some(value)) => Ok(value),
        Some(None) => Err(ConfigError::validation(path, "expected integer port")),
        None => Err(ConfigError::validation(path, "field is required")),
    }
}

fn input_trojan_tls_or_default(
    value: Option<Option<InputTrojanTlsConfig>>,
    path: impl Into<String>,
) -> Result<InputTrojanTlsConfig, ConfigError> {
    let path = path.into();
    match value {
        Some(Some(value)) => Ok(value),
        Some(None) => Err(ConfigError::validation(path, "expected object")),
        None => Ok(InputTrojanTlsConfig::default()),
    }
}

fn classify_ignored_paths(
    input_config: &InputConfig,
    mut ignored_paths: Vec<String>,
) -> Result<ParseDiagnostics, ConfigError> {
    ignored_paths.extend(protocol_extra_paths(input_config));

    let mut diagnostics = ParseDiagnostics::default();
    for path in ignored_paths {
        match classify_ignored_path(input_config, &path) {
            IgnoredDisposition::Ignore => diagnostics.ignored.push(path),
            IgnoredDisposition::Warn(message) => {
                diagnostics.warnings.push(ParseWarning { path, message })
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

    for (index, inbound) in input_config.inbounds.iter().enumerate() {
        for field in inbound.extra.keys() {
            paths.push(format!("$.inbounds[{index}].{field}"));
        }
    }

    for (index, outbound) in input_config.outbounds.iter().enumerate() {
        for field in outbound.extra.keys() {
            paths.push(format!("$.outbounds[{index}].{field}"));
        }
    }

    paths
}

fn classify_ignored_path(input_config: &InputConfig, path: &str) -> IgnoredDisposition {
    if let Some((index, field)) = indexed_field(path, "$.inbounds[") {
        return match input_config.inbounds.get(index).map(|inbound| inbound.kind) {
            Some(InputInboundType::Socks) => classify_socks_ignored(field),
            Some(InputInboundType::Redirect) => classify_redirect_ignored(field),
            Some(InputInboundType::Tproxy) => classify_tproxy_ignored(field),
            None => IgnoredDisposition::Ignore,
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
            None => IgnoredDisposition::Ignore,
        };
    }

    if indexed_field(path, "$.route.rules[").is_some() {
        return classify_route_rule_ignored(path);
    }

    match path {
        "$.dns" | "$.domain_resolver" => IgnoredDisposition::Warn(
            "field is accepted for compatibility but ignored by the current config surface",
        ),
        "$.log.output" => IgnoredDisposition::Warn(
            "log compatibility field is accepted but ignored by the current config surface",
        ),
        _ if path.starts_with("$.route.") => IgnoredDisposition::Ignore,
        _ if path.starts_with("$.log.") => IgnoredDisposition::Ignore,
        _ => IgnoredDisposition::Ignore,
    }
}

fn classify_socks_ignored(field: &str) -> IgnoredDisposition {
    match first_segment(field) {
        "udp" | "sniff" | "sniff_override_destination" | "users" | "auth" => {
            IgnoredDisposition::Warn(
                "field is accepted for compatibility but does not affect the current socks inbound",
            )
        }
        "set_system_proxy" | "tcp_fast_open" => IgnoredDisposition::Ignore,
        _ => IgnoredDisposition::Ignore,
    }
}

fn classify_redirect_ignored(field: &str) -> IgnoredDisposition {
    match first_segment(field) {
        "sniff" | "sniff_override_destination" | "udp" => IgnoredDisposition::Warn(
            "field is accepted for compatibility but does not affect the current redirect inbound",
        ),
        "tcp_fast_open" | "receive_original_destination" => IgnoredDisposition::Ignore,
        _ => IgnoredDisposition::Ignore,
    }
}

fn classify_tproxy_ignored(field: &str) -> IgnoredDisposition {
    match first_segment(field) {
        "udp" => IgnoredDisposition::Error(
            "tproxy inbound does not support UDP capability declarations in the current runtime",
        ),
        "sniff" | "sniff_override_destination" => IgnoredDisposition::Warn(
            "field is accepted for compatibility but does not affect the current tproxy inbound",
        ),
        "tcp_fast_open" | "udp_timeout" => IgnoredDisposition::Ignore,
        _ => IgnoredDisposition::Ignore,
    }
}

fn classify_direct_ignored(field: &str) -> IgnoredDisposition {
    match first_segment(field) {
        "bind_interface" | "domain_strategy" | "ipv4_only" | "ipv6_only" => {
            IgnoredDisposition::Warn(
                "field is accepted for compatibility but does not affect the current direct outbound",
            )
        }
        "tcp_fast_open" | "fallback_delay" => IgnoredDisposition::Ignore,
        _ => IgnoredDisposition::Ignore,
    }
}

fn classify_trojan_ignored(field: &str) -> IgnoredDisposition {
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
        return IgnoredDisposition::Warn(
            "field is accepted for compatibility but does not affect the current trojan outbound",
        );
    }

    match field {
        "tcp_fast_open" => IgnoredDisposition::Ignore,
        _ => IgnoredDisposition::Ignore,
    }
}

fn classify_route_rule_ignored(path: &str) -> IgnoredDisposition {
    let Some((_, field)) = indexed_field(path, "$.route.rules[") else {
        return IgnoredDisposition::Ignore;
    };

    match first_segment(field) {
        "domain" | "domain_suffix" | "ip_cidr" | "port" | "inbound" | "outbound" | "action"
        | "timeout" => IgnoredDisposition::Ignore,
        _ => IgnoredDisposition::Error(
            "route rule field is not supported by the current route.rules subset",
        ),
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

fn normalize_path(path: &str) -> String {
    let path = path.trim_end_matches('.');
    if path.is_empty() {
        return "$".to_string();
    }

    let mut normalized = String::from("$");
    for segment in path.split('.').filter(|segment| !segment.is_empty()) {
        if segment == "?" {
            continue;
        }

        if segment.starts_with('[') {
            normalized.push_str(segment);
        } else if segment.chars().all(|ch| ch.is_ascii_digit()) {
            normalized.push('[');
            normalized.push_str(segment);
            normalized.push(']');
        } else {
            normalized.push('.');
            normalized.push_str(segment);
        }
    }

    normalized
}

fn augment_path(path: String, message: &str) -> String {
    if let Some(field) = extract_missing_field(message) {
        let base = normalize_path(&path);
        if base == "$" {
            format!("$.{field}")
        } else {
            format!("{base}.{field}")
        }
    } else {
        normalize_path(&path)
    }
}

fn extract_missing_field(message: &str) -> Option<&str> {
    for quote in ['`', '\'', '"'] {
        let prefix = format!("missing field {quote}");
        if let Some(rest) = message.strip_prefix(&prefix) {
            return rest.split_once(quote).map(|(field, _)| field);
        }
    }

    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DomainMatcherKind {
    Exact,
    Suffix,
}

fn normalize_domain_matchers(
    value: Option<Vec<String>>,
    path: impl Into<String>,
    kind: DomainMatcherKind,
) -> Result<Vec<String>, ConfigError> {
    let path = path.into();
    let Some(values) = value else {
        return Ok(Vec::new());
    };

    if values.is_empty() {
        return Err(ConfigError::semantic(
            path,
            "route rule matcher list must not be empty",
        ));
    }

    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let item_path = format!("{path}[{index}]");
            let normalized = normalize_domain_matcher(&value, kind);
            if normalized.is_empty() {
                return Err(ConfigError::semantic(
                    item_path,
                    "route rule matcher must not be empty",
                ));
            }
            Ok(normalized)
        })
        .collect()
}

fn normalize_domain_matcher(value: &str, kind: DomainMatcherKind) -> String {
    let value = value.trim();
    match kind {
        DomainMatcherKind::Exact => value.to_ascii_lowercase(),
        DomainMatcherKind::Suffix => value.trim_start_matches('.').to_ascii_lowercase(),
    }
}

fn parse_ip_cidr_matchers(
    value: Option<Vec<String>>,
    path: impl Into<String>,
) -> Result<Vec<IpNet>, ConfigError> {
    let path = path.into();
    let Some(values) = value else {
        return Ok(Vec::new());
    };

    if values.is_empty() {
        return Err(ConfigError::semantic(
            path,
            "route rule matcher list must not be empty",
        ));
    }

    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let item_path = format!("{path}[{index}]");
            let value = value.trim();
            if value.is_empty() {
                return Err(ConfigError::semantic(
                    item_path,
                    "route rule matcher must not be empty",
                ));
            }

            value
                .parse::<IpNet>()
                .map_err(|_| ConfigError::semantic(item_path, format!("invalid IP CIDR '{value}'")))
        })
        .collect()
}

fn parse_port_matchers(
    value: Option<Vec<u16>>,
    path: impl Into<String>,
) -> Result<Vec<u16>, ConfigError> {
    let path = path.into();
    let Some(values) = value else {
        return Ok(Vec::new());
    };

    if values.is_empty() {
        return Err(ConfigError::semantic(
            path,
            "route rule matcher list must not be empty",
        ));
    }

    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            if value == 0 {
                return Err(ConfigError::semantic(
                    format!("{path}[{index}]"),
                    "port must be in 1..=65535",
                ));
            }
            Ok(value)
        })
        .collect()
}

fn parse_string_matchers(
    value: Option<Vec<String>>,
    path: impl Into<String>,
) -> Result<Vec<String>, ConfigError> {
    let path = path.into();
    let Some(values) = value else {
        return Ok(Vec::new());
    };

    if values.is_empty() {
        return Err(ConfigError::semantic(
            path,
            "route rule matcher list must not be empty",
        ));
    }

    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            if value.trim().is_empty() {
                return Err(ConfigError::semantic(
                    format!("{path}[{index}]"),
                    "route rule matcher must not be empty",
                ));
            }
            Ok(value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        DirectOutboundConfig, InboundConfig, OutboundConfig, RouteActionConfig,
        RouteFinalActionConfig, RouteUpgradeActionConfig, SniffActionConfig, TProxyInboundConfig,
        DEFAULT_CONNECT_TIMEOUT, DEFAULT_SNIFF_TIMEOUT, DEFAULT_TLS_HANDSHAKE_TIMEOUT,
    };

    use super::{parse_config, parse_config_report_unvalidated, parse_config_with_diagnostics};

    #[test]
    fn parses_valid_minimal_config() {
        let input = r#"
        {
          "log": { "level": "info" },
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "tls": { "server_name": "example.com" }
            }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let config = parse_config(input).expect("config should parse");
        assert_eq!(config.route.final_outbound, "proxy");
        assert!(config.route.bypass.is_empty());
        assert_eq!(config.inbounds.len(), 1);
        assert_eq!(config.outbounds.len(), 2);
    }

    #[test]
    fn parses_all_current_supported_protocol_shapes() {
        let input = r#"
        {
          "log": { "level": "debug", "disabled": false },
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 },
            { "type": "redirect", "tag": "redirect-in", "listen": "0.0.0.0", "listen_port": 60080 },
            { "type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": 1041, "network": "tcp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct", "routing_mark": 255 },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "trojan.example.com",
              "server_port": 443,
              "password": "secret",
              "tls": {
                "enabled": true,
                "server_name": "trojan.example.com",
                "disable_sni": false,
                "insecure": false
              }
            }
          ],
          "route": {
            "final": "proxy",
            "bypass": ["trojan.example.com", "192.168.0.1"]
          }
        }
        "#;

        let config = parse_config(input).expect("supported protocol mix should parse");
        assert_eq!(config.inbounds.len(), 3);
        assert_eq!(config.outbounds.len(), 2);
        assert_eq!(config.route.final_outbound, "proxy");
        assert_eq!(
            config.route.bypass,
            vec!["trojan.example.com".to_string(), "192.168.0.1".to_string()]
        );
    }

    #[test]
    fn parses_route_rules_minimal_subset() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "tls": { "server_name": "example.com" }
            }
          ],
          "route": {
            "final": "proxy",
            "rules": [
              {
                "domain": [" Example.COM "],
                "outbound": "proxy"
              },
              {
                "domain_suffix": [".Google.com"],
                "outbound": "proxy"
              },
              {
                "ip_cidr": ["192.168.0.0/16"],
                "outbound": "direct"
              },
              {
                "port": [53],
                "outbound": "direct"
              },
              {
                "inbound": ["socks-in"],
                "outbound": "direct"
              }
            ]
          }
        }
        "#;

        let config = parse_config(input).expect("route rules should parse");
        assert_eq!(config.route.rules.len(), 5);
        assert_eq!(
            config.route.rules[0].domain,
            vec!["example.com".to_string()]
        );
        assert_eq!(
            config.route.rules[1].domain_suffix,
            vec!["google.com".to_string()]
        );
        assert_eq!(
            config.route.rules[2].ip_cidr[0].to_string(),
            "192.168.0.0/16"
        );
        assert_eq!(config.route.rules[3].port, vec![53]);
        assert_eq!(config.route.rules[4].inbound, vec!["socks-in".to_string()]);
        assert!(matches!(
            config.route.rules[0].action,
            RouteActionConfig::Final(RouteFinalActionConfig::Route(_))
        ));
    }

    #[test]
    fn parses_sniff_route_rule_and_defaults_timeout() {
        let input = r#"
        {
          "inbounds": [
            { "type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": 1041, "network": "tcp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "inbound": ["tproxy-in"],
                "action": "sniff"
              }
            ]
          }
        }
        "#;

        let config = parse_config(input).expect("sniff route rule should parse");
        assert!(matches!(
            &config.route.rules[0].action,
            RouteActionConfig::Upgrade(RouteUpgradeActionConfig::Sniff(SniffActionConfig {
                timeout
            })) if *timeout == DEFAULT_SNIFF_TIMEOUT
        ));
    }

    #[test]
    fn parses_sniff_route_rule_timeout_with_humantime() {
        let input = r#"
        {
          "inbounds": [
            { "type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": 1041, "network": "tcp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "inbound": ["tproxy-in"],
                "action": "sniff",
                "timeout": "300ms"
              }
            ]
          }
        }
        "#;

        let config = parse_config(input).expect("sniff timeout should parse");
        assert!(matches!(
            &config.route.rules[0].action,
            RouteActionConfig::Upgrade(RouteUpgradeActionConfig::Sniff(SniffActionConfig {
                timeout
            })) if *timeout == Duration::from_millis(300)
        ));
    }

    #[test]
    fn rejects_duplicate_tags() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "same", "listen": "127.0.0.1", "listen_port": 1080 },
            { "type": "redirect", "tag": "same", "listen": "127.0.0.1", "listen_port": 60080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let err = parse_config(input).expect_err("duplicate tags should fail");
        assert!(err.to_string().contains("duplicate inbound tag"));
    }

    #[test]
    fn rejects_missing_route_target() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let err = parse_config(input).expect_err("missing outbound should fail");
        assert!(err.to_string().contains("missing outbound"));
    }

    #[test]
    fn collects_warning_and_ignore_paths_with_explicit_policy() {
        let input = r#"
        {
          "log": { "level": "debug", "timestamp": true, "noise": true },
          "dns": { "servers": ["223.5.5.5"] },
          "experimental": { "enabled": true },
          "inbounds": [
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "127.0.0.1",
              "listen_port": 1080,
              "sniff": true,
              "users": [],
              "tcp_fast_open": true
            }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct", "connect_timeout": "5s", "tcp_fast_open": true },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "domain_resolver": "local",
              "transport": { "type": "ws" },
              "tls": { "server_name": "example.com" }
            }
          ],
          "route": { "final": "proxy", "rules": [] }
        }
        "#;

        let report =
            parse_config_report_unvalidated(input).expect("compatibility fields should not block");
        let warning_paths: Vec<&str> = report
            .diagnostics
            .warnings
            .iter()
            .map(|warning| warning.path.as_str())
            .collect();

        assert!(report.config.log.timestamp);
        assert!(warning_paths.contains(&"$.dns"));
        assert!(warning_paths.contains(&"$.inbounds[0].sniff"));
        assert!(warning_paths.contains(&"$.inbounds[0].users"));
        assert!(!warning_paths.contains(&"$.outbounds[0].connect_timeout"));
        assert!(warning_paths.contains(&"$.outbounds[1].domain_resolver"));
        assert!(warning_paths.contains(&"$.outbounds[1].transport"));
        assert!(report.config.route.rules.is_empty());
        assert!(report
            .diagnostics
            .ignored
            .contains(&"$.experimental".to_string()));
        assert!(report
            .diagnostics
            .ignored
            .contains(&"$.inbounds[0].tcp_fast_open".to_string()));
        assert!(report
            .diagnostics
            .ignored
            .contains(&"$.outbounds[0].tcp_fast_open".to_string()));
        assert!(report
            .diagnostics
            .ignored
            .contains(&"$.log.noise".to_string()));
    }

    #[test]
    fn parses_log_timestamp_as_supported_field_without_warning() {
        let input = r#"
        {
          "log": { "level": "info", "timestamp": true },
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let (config, diagnostics) =
            parse_config_with_diagnostics(input).expect("timestamp field should parse");

        assert!(config.log.timestamp);
        assert!(!diagnostics
            .warnings
            .iter()
            .any(|warning| warning.path == "$.log.timestamp"));
    }

    #[test]
    fn top_level_unknown_fields_still_parse_successfully() {
        let input = r#"
        {
          "dns": { "servers": ["223.5.5.5"] },
          "extra_top_level": { "anything": true },
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        parse_config(input).expect("top-level compatibility fields should be tolerated");
    }

    #[test]
    fn parse_config_with_diagnostics_exposes_warnings_without_changing_default_parse() {
        let input = r#"
        {
          "dns": { "servers": ["223.5.5.5"] },
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080, "sniff": true }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let (config, diagnostics) =
            parse_config_with_diagnostics(input).expect("diagnostics parse should succeed");
        let warning_paths: Vec<&str> = diagnostics
            .warnings
            .iter()
            .map(|warning| warning.path.as_str())
            .collect();

        assert_eq!(config.route.final_outbound, "direct");
        assert!(warning_paths.contains(&"$.dns"));
        assert!(warning_paths.contains(&"$.inbounds[0].sniff"));
        parse_config(input).expect("default parse should remain silent and succeed");
    }

    #[test]
    fn rejects_unknown_fields_that_declare_unsupported_tproxy_udp_capability() {
        let input = r#"
        {
          "inbounds": [
            {
              "type": "tproxy",
              "tag": "tproxy-in",
              "listen": "0.0.0.0",
              "listen_port": 1041,
              "udp": true
            }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let err = parse_config(input).expect_err("tproxy udp declaration should fail");
        assert!(err.to_string().contains("$.inbounds[0].udp"));
        assert!(err.to_string().contains("does not support UDP"));
    }

    #[test]
    fn rejects_unknown_inbound_type_with_type_path() {
        let input = r#"
        {
          "inbounds": [
            { "type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 8080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let err = parse_config(input).expect_err("unsupported inbound type should fail");
        assert!(err.to_string().contains("$.inbounds[0].type"));
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn rejects_missing_required_trojan_fields_with_precise_paths() {
        let missing_server = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "trojan", "tag": "proxy", "server_port": 443, "password": "secret" }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let err = parse_config(missing_server).expect_err("missing server should fail");
        assert!(err.to_string().contains("$.outbounds[1].server"));

        let missing_password = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "trojan", "tag": "proxy", "server": "example.com", "server_port": 443 }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let err = parse_config(missing_password).expect_err("missing password should fail");
        assert!(err.to_string().contains("$.outbounds[1].password"));
    }

    #[test]
    fn parses_tproxy_inbound_with_optional_network() {
        let input = r#"
        {
          "inbounds": [
            { "type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": 1041 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let config = parse_config(input).expect("tproxy config should parse");
        assert_eq!(
            config.inbounds,
            vec![InboundConfig::TProxy(TProxyInboundConfig {
                tag: "tproxy-in".into(),
                listen: "0.0.0.0".into(),
                listen_port: 1041,
                network: None,
            })]
        );
    }

    #[test]
    fn parses_direct_outbound_with_optional_routing_mark() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct", "routing_mark": 1 }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let config = parse_config(input).expect("direct config with routing_mark should parse");
        assert_eq!(
            config.outbounds,
            vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: Some(1),
            })]
        );
    }

    #[test]
    fn parses_timeout_fields_with_humantime_durations() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct", "connect_timeout": "300ms" },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "connect_timeout": "5s",
              "tls": {
                "server_name": "example.com",
                "handshake_timeout": "1s"
              }
            }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let config = parse_config(input).expect("timeout fields should parse");

        match &config.outbounds[0] {
            OutboundConfig::Direct(direct) => {
                assert_eq!(direct.connect_timeout, Duration::from_millis(300));
            }
            other => panic!("expected direct outbound, got {other:?}"),
        }

        match &config.outbounds[1] {
            OutboundConfig::Trojan(trojan) => {
                assert_eq!(trojan.connect_timeout, Duration::from_secs(5));
                assert_eq!(trojan.tls.handshake_timeout, Duration::from_secs(1));
            }
            other => panic!("expected trojan outbound, got {other:?}"),
        }
    }

    #[test]
    fn timeout_fields_default_in_runtime_config_when_omitted() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "tls": { "server_name": "example.com" }
            }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let config = parse_config(input).expect("default timeout config should parse");

        match &config.outbounds[0] {
            OutboundConfig::Direct(direct) => {
                assert_eq!(direct.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
            }
            other => panic!("expected direct outbound, got {other:?}"),
        }

        match &config.outbounds[1] {
            OutboundConfig::Trojan(trojan) => {
                assert_eq!(trojan.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
                assert_eq!(trojan.tls.handshake_timeout, DEFAULT_TLS_HANDSHAKE_TIMEOUT);
            }
            other => panic!("expected trojan outbound, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_connect_timeout_with_indexed_path() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct", "connect_timeout": "soon" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let err = parse_config(input).expect_err("invalid connect_timeout should fail");
        assert!(err.to_string().contains("$.outbounds[0].connect_timeout"));
        assert!(err
            .to_string()
            .contains("invalid duration, expected formats like 300ms, 5s, 2m"));
    }

    #[test]
    fn rejects_invalid_tls_handshake_timeout_with_nested_path() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "tls": {
                "server_name": "example.com",
                "handshake_timeout": "later"
              }
            }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let err = parse_config(input).expect_err("invalid handshake_timeout should fail");
        assert!(err
            .to_string()
            .contains("$.outbounds[1].tls.handshake_timeout"));
        assert!(err
            .to_string()
            .contains("invalid duration, expected formats like 300ms, 5s, 2m"));
    }

    #[test]
    fn rejects_invalid_tls_combination() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "tls": { "disable_sni": true, "insecure": false }
            }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let err = parse_config(input).expect_err("invalid tls combination should fail");
        assert!(err.to_string().contains("$.outbounds[1].tls"));
        assert!(err.to_string().contains("disable_sni=true"));
    }

    #[test]
    fn rejects_disabled_trojan_tls_with_indexed_path() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "tls": { "enabled": false }
            }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let err = parse_config(input).expect_err("tls.enabled=false should fail");
        assert!(err.to_string().contains("$.outbounds[1].tls.enabled"));
        assert!(err.to_string().contains("requires TLS"));
    }

    #[test]
    fn trojan_tls_wrong_type_is_validation_error_at_tls_path() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "tls": true
            }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let err = parse_config(input).expect_err("non-object tls should fail");
        assert!(err.to_string().contains("$.outbounds[1].tls"));
        assert!(err
            .to_string()
            .contains("expected struct InputTrojanTlsConfig"));
    }

    #[test]
    fn rejects_tproxy_network_other_than_tcp() {
        let input = r#"
        {
          "inbounds": [
            {
              "type": "tproxy",
              "tag": "tproxy-in",
              "listen": "0.0.0.0",
              "listen_port": 1041,
              "network": "udp"
            }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let err = parse_config(input).expect_err("non-tcp tproxy network should fail");
        assert!(err.to_string().contains("$.inbounds[0].network"));
        assert!(err.to_string().contains("only supports network='tcp'"));
    }

    #[test]
    fn rejects_direct_routing_mark_with_wrong_type() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct", "routing_mark": "1" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let err = parse_config(input).expect_err("string routing_mark should fail");
        assert!(err.to_string().contains("$.outbounds[0].routing_mark"));
    }

    #[test]
    fn rejects_direct_routing_mark_outside_u32_range() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct", "routing_mark": -1 }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let err = parse_config(input).expect_err("negative routing_mark should fail");
        assert!(err.to_string().contains("$.outbounds[0].routing_mark"));
    }

    #[test]
    fn rejects_route_rule_without_outbound() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "domain": ["example.com"]
              }
            ]
          }
        }
        "#;

        let err = parse_config(input).expect_err("route rule without outbound should fail");
        assert!(err.to_string().contains("$.route.rules[0].outbound"));
        assert!(err.to_string().contains("field is required"));
    }

    #[test]
    fn rejects_route_rule_without_any_matchers() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "outbound": "direct"
              }
            ]
          }
        }
        "#;

        let err = parse_config(input).expect_err("route rule without matchers should fail");
        assert!(err.to_string().contains("$.route.rules[0]"));
        assert!(err.to_string().contains("at least one matcher"));
    }

    #[test]
    fn rejects_invalid_sniff_timeout_with_indexed_path() {
        let input = r#"
        {
          "inbounds": [
            { "type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": 1041, "network": "tcp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "inbound": ["tproxy-in"],
                "action": "sniff",
                "timeout": "soon"
              }
            ]
          }
        }
        "#;

        let err = parse_config(input).expect_err("invalid sniff timeout should fail");
        assert!(err.to_string().contains("$.route.rules[0].timeout"));
        assert!(err.to_string().contains("invalid duration"));
    }

    #[test]
    fn rejects_sniff_timeout_without_sniff_action() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "port": [443],
                "timeout": "300ms",
                "outbound": "direct"
              }
            ]
          }
        }
        "#;

        let err = parse_config(input).expect_err("timeout without sniff action should fail");
        assert!(err.to_string().contains("$.route.rules[0].timeout"));
        assert!(err
            .to_string()
            .contains("only supported for action='sniff'"));
    }

    #[test]
    fn rejects_route_rule_with_missing_outbound_target() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "domain": ["example.com"],
                "outbound": "proxy"
              }
            ]
          }
        }
        "#;

        let err = parse_config(input).expect_err("unknown route rule outbound should fail");
        assert!(err.to_string().contains("$.route.rules[0].outbound"));
        assert!(err.to_string().contains("missing outbound 'proxy'"));
    }

    #[test]
    fn rejects_route_rule_with_invalid_ip_cidr() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "ip_cidr": ["192.168.0.0/33"],
                "outbound": "direct"
              }
            ]
          }
        }
        "#;

        let err = parse_config(input).expect_err("invalid CIDR should fail");
        assert!(err.to_string().contains("$.route.rules[0].ip_cidr[0]"));
        assert!(err.to_string().contains("invalid IP CIDR"));
    }

    #[test]
    fn rejects_route_rule_with_port_zero() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "port": [0],
                "outbound": "direct"
              }
            ]
          }
        }
        "#;

        let err = parse_config(input).expect_err("port zero should fail");
        assert!(err.to_string().contains("$.route.rules[0].port[0]"));
        assert!(err.to_string().contains("1..=65535"));
    }

    #[test]
    fn rejects_unsupported_route_rule_field() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "source_ip": ["192.0.2.1"],
                "outbound": "direct"
              }
            ]
          }
        }
        "#;

        let err = parse_config(input).expect_err("unsupported route rule field should fail");
        assert!(err.to_string().contains("$.route.rules[0].source_ip"));
        assert!(err.to_string().contains("current route.rules subset"));
    }

    #[test]
    fn parses_route_bypass_as_string_list() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "bypass": [" trojan.example.com ", "192.0.2.10"]
          }
        }
        "#;

        let config = parse_config(input).expect("route bypass should parse");
        assert_eq!(
            config.route.bypass,
            vec![" trojan.example.com ".to_string(), "192.0.2.10".to_string()]
        );
    }

    #[test]
    fn rejects_route_bypass_with_non_string_items() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "bypass": ["example.com", 1]
          }
        }
        "#;

        let err = parse_config(input).expect_err("non-string bypass item should fail");
        assert!(err.to_string().contains("$.route.bypass[1]"));
    }

    #[test]
    fn rejects_route_bypass_wildcard_patterns() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "bypass": ["*.example.com"]
          }
        }
        "#;

        let err = parse_config(input).expect_err("wildcard bypass should fail");
        assert!(err.to_string().contains("$.route.bypass[0]"));
        assert!(err.to_string().contains("unsupported bypass pattern"));
    }

    #[test]
    fn rejects_route_bypass_suffix_patterns() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "bypass": [".example.com"]
          }
        }
        "#;

        let err = parse_config(input).expect_err("suffix bypass should fail");
        assert!(err.to_string().contains("$.route.bypass[0]"));
        assert!(err.to_string().contains("unsupported bypass pattern"));
    }

    #[test]
    fn rejects_duplicate_object_keys_before_serde_can_overwrite_them() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct", "tag": "shadow" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let err = parse_config(input).expect_err("duplicate keys should fail");
        assert!(err.to_string().contains("duplicate object key `tag`"));
        assert!(err.to_string().contains("$.outbounds[0].tag"));
    }

    #[test]
    fn parses_tproxy_compat_example_with_ignored_fields() {
        let input = include_str!("../../../examples/tproxy-compat.json");

        let report =
            parse_config_report_unvalidated(input).expect("compat example should parse cleanly");
        let warning_paths: Vec<&str> = report
            .diagnostics
            .warnings
            .iter()
            .map(|warning| warning.path.as_str())
            .collect();

        assert_eq!(report.config.route.final_outbound, "proxy");
        assert!(report.config.log.timestamp);
        assert_eq!(
            report.config.route.bypass,
            vec!["trojan.example.com".to_string(), "192.168.0.1".to_string()]
        );
        assert_eq!(report.config.route.rules.len(), 2);
        assert_eq!(report.config.route.rules[0].inbound, vec!["tproxy-in".to_string()]);
        assert!(matches!(
            &report.config.route.rules[0].action,
            RouteActionConfig::Upgrade(RouteUpgradeActionConfig::Sniff(SniffActionConfig {
                timeout
            })) if *timeout == DEFAULT_SNIFF_TIMEOUT
        ));
        assert_eq!(
            report.config.route.rules[1].domain_suffix,
            vec!["lan".to_string()]
        );
        assert!(warning_paths.contains(&"$.dns"));
        assert!(warning_paths.contains(&"$.outbounds[1].domain_resolver"));
        assert!(!warning_paths.contains(&"$.log.timestamp"));
        parse_config(input).expect("compat example should remain loadable");
    }

    #[test]
    fn preserves_utf8_tags_and_route_targets() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "入口", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
              "type": "trojan",
              "tag": "日用 [0.2]",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "tls": { "server_name": "example.com" }
            }
          ],
          "route": { "final": "日用 [0.2]" }
        }
        "#;

        let config = parse_config(input).expect("config should parse");
        assert_eq!(config.route.final_outbound, "日用 [0.2]");
        assert_eq!(config.inbounds[0].tag(), "入口");
        assert_eq!(config.outbounds[0].tag(), "direct");
        assert_eq!(config.outbounds[1].tag(), "日用 [0.2]");
    }

    #[test]
    fn trojan_tls_unknown_field_is_ignored() {
        let input = r#"
        {
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "tls": {
                "enabled": true,
                "unknown_field": 123
              }
            }
          ],
          "route": { "final": "proxy" }
        }
        "#;

        let (_config, diagnostics) =
            parse_config_with_diagnostics(input).expect("unknown tls field should not block");

        assert!(diagnostics
            .ignored
            .contains(&"$.outbounds[1].tls.unknown_field".to_string()));
        assert!(diagnostics
            .warnings
            .iter()
            .all(|warning| warning.path != "$.outbounds[1].tls.unknown_field"));
    }
}
