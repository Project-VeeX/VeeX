use std::{collections::BTreeMap, fs, io, path::Path};

use crate::{
    defaults::DEFAULT_LOG_LEVEL,
    json::{parse_json, JsonValue},
    schema::{
        DirectOutboundConfig, InboundConfig, LogConfig, OutboundConfig, ProxyConfig,
        RedirectInboundConfig, RouteConfig, SocksInboundConfig, TProxyInboundConfig,
        TrojanOutboundConfig, TrojanTlsConfig,
    },
    validate::validate_config,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitCodeHint {
    Config = 2,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Json { path: String, message: String },
    Validation { path: String, message: String },
}

impl ConfigError {
    pub fn json(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Json {
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn validation(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn exit_code_hint(&self) -> ExitCodeHint {
        ExitCodeHint::Config
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "failed to read config file: {err}"),
            Self::Json { path, message } => write!(f, "json parse error at {path}: {message}"),
            Self::Validation { path, message } => {
                write!(f, "config validation error at {path}: {message}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn load_from_path(path: impl AsRef<Path>) -> Result<ProxyConfig, ConfigError> {
    let content = fs::read_to_string(path)?;
    parse_config(&content)
}

pub fn parse_config(input: &str) -> Result<ProxyConfig, ConfigError> {
    let config = parse_proxy_config(input)?;
    validate_config(&config)?;
    Ok(config)
}

fn parse_proxy_config(input: &str) -> Result<ProxyConfig, ConfigError> {
    let root = parse_json(input)?;
    let root = expect_object(&root, "$")?;

    Ok(ProxyConfig {
        log: parse_log(root.get("log"))?,
        inbounds: parse_inbounds(root.get("inbounds"))?,
        outbounds: parse_outbounds(root.get("outbounds"))?,
        route: parse_route(root.get("route"))?,
    })
}

fn parse_log(value: Option<&JsonValue>) -> Result<LogConfig, ConfigError> {
    let Some(value) = value else {
        return Ok(LogConfig {
            level: DEFAULT_LOG_LEVEL.to_string(),
            disabled: false,
        });
    };
    let object = expect_object(value, "$.log")?;

    Ok(LogConfig {
        level: optional_string(object.get("level"), "$.log.level")?
            .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string()),
        disabled: optional_bool(object.get("disabled"), "$.log.disabled")?.unwrap_or(false),
    })
}

fn parse_inbounds(value: Option<&JsonValue>) -> Result<Vec<InboundConfig>, ConfigError> {
    let Some(value) = value else {
        return Err(ConfigError::validation("$.inbounds", "field is required"));
    };
    let items = expect_array(value, "$.inbounds")?;
    let mut inbounds = Vec::with_capacity(items.len());

    for (index, item) in items.iter().enumerate() {
        let path = format!("$.inbounds[{index}]");
        let object = expect_object(item, &path)?;
        let kind = required_string(object.get("type"), format!("{path}.type"))?;
        let tag = required_string(object.get("tag"), format!("{path}.tag"))?;
        let listen = required_string(object.get("listen"), format!("{path}.listen"))?;
        let listen_port = required_port(object.get("listen_port"), format!("{path}.listen_port"))?;

        let inbound = match kind.as_str() {
            "socks" => InboundConfig::Socks(SocksInboundConfig {
                tag,
                listen,
                listen_port,
            }),
            "redirect" => InboundConfig::Redirect(RedirectInboundConfig {
                tag,
                listen,
                listen_port,
            }),
            "tproxy" => {
                let network = optional_string(object.get("network"), format!("{path}.network"))?;
                if let Some(network) = network.as_deref() {
                    if network != "tcp" {
                        return Err(ConfigError::validation(
                            format!("{path}.network"),
                            "tproxy inbound only supports network='tcp'",
                        ));
                    }
                }

                InboundConfig::TProxy(TProxyInboundConfig {
                    tag,
                    listen,
                    listen_port,
                    network,
                })
            }
            _ => {
                return Err(ConfigError::validation(
                    format!("{path}.type"),
                    format!("unsupported inbound type '{kind}'"),
                ))
            }
        };

        inbounds.push(inbound);
    }

    Ok(inbounds)
}

fn parse_outbounds(value: Option<&JsonValue>) -> Result<Vec<OutboundConfig>, ConfigError> {
    let Some(value) = value else {
        return Err(ConfigError::validation("$.outbounds", "field is required"));
    };
    let items = expect_array(value, "$.outbounds")?;
    let mut outbounds = Vec::with_capacity(items.len());

    for (index, item) in items.iter().enumerate() {
        let path = format!("$.outbounds[{index}]");
        let object = expect_object(item, &path)?;
        let kind = required_string(object.get("type"), format!("{path}.type"))?;
        let tag = required_string(object.get("tag"), format!("{path}.tag"))?;

        let outbound = match kind.as_str() {
            "direct" => OutboundConfig::Direct(DirectOutboundConfig {
                tag,
                routing_mark: optional_u32(
                    object.get("routing_mark"),
                    format!("{path}.routing_mark"),
                )?,
            }),
            "trojan" => {
                let server = required_string(object.get("server"), format!("{path}.server"))?;
                let server_port =
                    required_port(object.get("server_port"), format!("{path}.server_port"))?;
                let password = required_string(object.get("password"), format!("{path}.password"))?;
                let tls = parse_trojan_tls(object.get("tls"), &path)?;
                OutboundConfig::Trojan(TrojanOutboundConfig {
                    tag,
                    server,
                    server_port,
                    password,
                    tls,
                })
            }
            _ => {
                return Err(ConfigError::validation(
                    format!("{path}.type"),
                    format!("unsupported outbound type '{kind}'"),
                ))
            }
        };

        outbounds.push(outbound);
    }

    Ok(outbounds)
}

fn parse_trojan_tls(
    value: Option<&JsonValue>,
    parent_path: &str,
) -> Result<TrojanTlsConfig, ConfigError> {
    let path = format!("{parent_path}.tls");
    let object = match value {
        Some(value) => expect_object(value, &path)?,
        None => {
            return Ok(TrojanTlsConfig {
                enabled: true,
                server_name: None,
                disable_sni: false,
                insecure: false,
                certificate_path: None,
                ca_path: None,
            })
        }
    };

    Ok(TrojanTlsConfig {
        enabled: optional_bool(object.get("enabled"), format!("{path}.enabled"))?.unwrap_or(true),
        server_name: optional_string(object.get("server_name"), format!("{path}.server_name"))?,
        disable_sni: optional_bool(object.get("disable_sni"), format!("{path}.disable_sni"))?
            .unwrap_or(false),
        insecure: optional_bool(object.get("insecure"), format!("{path}.insecure"))?
            .unwrap_or(false),
        certificate_path: optional_string(
            object.get("certificate_path"),
            format!("{path}.certificate_path"),
        )?,
        ca_path: optional_string(object.get("ca_path"), format!("{path}.ca_path"))?,
    })
}

fn parse_route(value: Option<&JsonValue>) -> Result<RouteConfig, ConfigError> {
    let Some(value) = value else {
        return Err(ConfigError::validation("$.route", "field is required"));
    };
    let object = expect_object(value, "$.route")?;

    Ok(RouteConfig {
        final_outbound: required_string(object.get("final"), "$.route.final")?,
        bypass: optional_string_array(object.get("bypass"), "$.route.bypass")?.unwrap_or_default(),
    })
}

fn expect_object(
    value: &JsonValue,
    path: impl Into<String>,
) -> Result<&BTreeMap<String, JsonValue>, ConfigError> {
    match value {
        JsonValue::Object(object) => Ok(object),
        _ => Err(ConfigError::validation(path, "expected object")),
    }
}

fn expect_array(value: &JsonValue, path: impl Into<String>) -> Result<&[JsonValue], ConfigError> {
    match value {
        JsonValue::Array(items) => Ok(items),
        _ => Err(ConfigError::validation(path, "expected array")),
    }
}

fn required_string(
    value: Option<&JsonValue>,
    path: impl Into<String>,
) -> Result<String, ConfigError> {
    let path = path.into();
    let Some(value) = value else {
        return Err(ConfigError::validation(path, "field is required"));
    };

    match value {
        JsonValue::String(content) => Ok(content.clone()),
        _ => Err(ConfigError::validation(path, "expected string")),
    }
}

fn optional_string(
    value: Option<&JsonValue>,
    path: impl Into<String>,
) -> Result<Option<String>, ConfigError> {
    let path = path.into();
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        JsonValue::Null => Ok(None),
        JsonValue::String(content) => Ok(Some(content.clone())),
        _ => Err(ConfigError::validation(path, "expected string")),
    }
}

fn optional_bool(
    value: Option<&JsonValue>,
    path: impl Into<String>,
) -> Result<Option<bool>, ConfigError> {
    let path = path.into();
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        JsonValue::Bool(flag) => Ok(Some(*flag)),
        _ => Err(ConfigError::validation(path, "expected boolean")),
    }
}

fn optional_u32(
    value: Option<&JsonValue>,
    path: impl Into<String>,
) -> Result<Option<u32>, ConfigError> {
    let path = path.into();
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        JsonValue::Null => Ok(None),
        JsonValue::Number(number) if *number >= 0 && *number <= u32::MAX as i64 => {
            Ok(Some(*number as u32))
        }
        JsonValue::Number(_) => Err(ConfigError::validation(
            path,
            "expected non-negative integer within u32 range",
        )),
        _ => Err(ConfigError::validation(
            path,
            "expected non-negative integer",
        )),
    }
}

fn optional_string_array(
    value: Option<&JsonValue>,
    path: impl Into<String>,
) -> Result<Option<Vec<String>>, ConfigError> {
    let path = path.into();
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        JsonValue::Null => Ok(None),
        JsonValue::Array(items) => {
            let mut values = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                match item {
                    JsonValue::String(content) => values.push(content.clone()),
                    _ => {
                        return Err(ConfigError::validation(
                            format!("{path}[{index}]"),
                            "expected string",
                        ))
                    }
                }
            }
            Ok(Some(values))
        }
        _ => Err(ConfigError::validation(path, "expected array")),
    }
}

fn required_port(value: Option<&JsonValue>, path: impl Into<String>) -> Result<u16, ConfigError> {
    let path = path.into();
    let Some(value) = value else {
        return Err(ConfigError::validation(path, "field is required"));
    };

    match value {
        JsonValue::Number(number) if (1..=65535).contains(number) => Ok(*number as u16),
        JsonValue::Number(_) => Err(ConfigError::validation(
            path,
            "port must be within 1..=65535",
        )),
        _ => Err(ConfigError::validation(path, "expected integer port")),
    }
}

#[cfg(test)]
mod tests {
    use crate::{DirectOutboundConfig, InboundConfig, OutboundConfig, TProxyInboundConfig};

    use super::parse_config;

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
    fn ignores_unknown_fields_but_rejects_wrong_type() {
        let input = r#"
        {
          "log": { "level": "debug", "ignored": { "nested": true } },
          "inbounds": [
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "127.0.0.1",
              "listen_port": 1080,
              "users": []
            }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
              "type": "trojan",
              "tag": "proxy",
              "server": "example.com",
              "server_port": 443,
              "password": "secret",
              "tls": { "server_name": "example.com", "multiplex": { "enabled": true } }
            }
          ],
          "route": { "final": "proxy", "rules": [] }
        }
        "#;

        parse_config(input).expect("unknown fields should be ignored");

        let invalid = input.replace(r#""listen_port": 1080"#, r#""listen_port": "1080""#);
        let err = parse_config(&invalid).expect_err("wrong type should fail");
        assert!(err.to_string().contains("$.inbounds[0].listen_port"));
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
                routing_mark: Some(1),
            })]
        );
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
        assert!(err.to_string().contains("disable_sni=true"));
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
        assert!(err.to_string().contains("u32 range"));
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
    fn parses_tproxy_compat_example_with_ignored_fields() {
        let input = include_str!("../../../examples/tproxy-compat.json");

        let config = parse_config(input).expect("compat example should parse");
        assert_eq!(config.route.final_outbound, "proxy");
        assert_eq!(
            config.route.bypass,
            vec!["trojan.example.com".to_string(), "192.168.0.1".to_string()]
        );
    }
}
