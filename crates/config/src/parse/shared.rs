use std::collections::BTreeMap;

use ipnet::IpNet;

use crate::{
    defaults::{DEFAULT_LOG_LEVEL, DEFAULT_TLS_HANDSHAKE_TIMEOUT},
    error::ConfigError,
    input::{InputDomainResolverValue, InputLogConfig, InputTrojanTlsConfig},
    schema::{DnsServerTypeConfig, DomainResolverConfig, LogConfig, TrojanTlsConfig},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainMatcherKind {
    Exact,
    Suffix,
}

pub(crate) fn input_log_into_config(input_config: InputLogConfig) -> LogConfig {
    LogConfig {
        level: input_config
            .level
            .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string()),
        disabled: input_config.disabled,
        timestamp: input_config.timestamp,
    }
}

pub(crate) fn input_trojan_tls_into_config(input_config: InputTrojanTlsConfig) -> TrojanTlsConfig {
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

pub(crate) fn required_nested_string(
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

pub(crate) fn required_nested_port(
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

pub(crate) fn nested_port_or_default(
    value: Option<Option<u16>>,
    path: impl Into<String>,
    default: u16,
) -> Result<u16, ConfigError> {
    let path = path.into();
    match value {
        Some(Some(value)) => Ok(value),
        Some(None) => Err(ConfigError::validation(path, "expected integer port")),
        None => Ok(default),
    }
}

pub(crate) fn optional_nested_string(
    value: Option<Option<String>>,
    path: impl Into<String>,
) -> Result<Option<String>, ConfigError> {
    let path = path.into();
    match value {
        Some(Some(value)) => Ok(Some(value)),
        Some(None) => Err(ConfigError::validation(path, "expected string")),
        None => Ok(None),
    }
}

pub(crate) fn optional_string_map(
    value: Option<Option<BTreeMap<String, String>>>,
    path: impl Into<String>,
) -> Result<BTreeMap<String, String>, ConfigError> {
    let path = path.into();
    match value {
        Some(Some(value)) => Ok(value),
        Some(None) => Err(ConfigError::validation(path, "expected object")),
        None => Ok(BTreeMap::new()),
    }
}

pub(crate) fn optional_domain_resolver(
    value: Option<InputDomainResolverValue>,
    path: impl Into<String>,
) -> Result<Option<DomainResolverConfig>, ConfigError> {
    let path = path.into();
    match value {
        Some(InputDomainResolverValue::Tag(server)) => {
            if server.trim().is_empty() {
                return Err(ConfigError::semantic(
                    path,
                    "domain_resolver server must not be empty",
                ));
            }
            Ok(Some(DomainResolverConfig { server }))
        }
        Some(InputDomainResolverValue::Structured(config)) => Ok(Some(DomainResolverConfig {
            server: required_nested_string(config.server, format!("{path}.server"))?,
        })),
        None => Ok(None),
    }
}

pub(crate) fn input_trojan_tls_or_default(
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

pub(crate) fn map_serde_error(err: serde_json::Error, path: Option<String>) -> ConfigError {
    let message = err.to_string();

    if err.is_data() {
        return ConfigError::validation(augment_path(path.unwrap_or_default(), &message), message);
    }

    ConfigError::json("$", message)
}

pub(crate) fn normalize_path(path: &str) -> String {
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

pub(crate) fn normalize_domain_matchers(
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

pub(crate) fn parse_ip_cidr_matchers(
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

pub(crate) fn parse_port_matchers(
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

pub(crate) fn parse_string_matchers(
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

pub(crate) fn parse_dns_server_type(value: String) -> DnsServerTypeConfig {
    match value.trim().to_ascii_lowercase().as_str() {
        "local" => DnsServerTypeConfig::Local,
        "udp" => DnsServerTypeConfig::Udp,
        "tcp" => DnsServerTypeConfig::Tcp,
        "tls" => DnsServerTypeConfig::Tls,
        "https" => DnsServerTypeConfig::Https,
        other => DnsServerTypeConfig::Unsupported(other.to_string()),
    }
}
