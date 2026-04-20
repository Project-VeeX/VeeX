mod compat;
mod dns;
mod inbound;
mod outbound;
mod route;
mod shared;

use std::{fs, path::Path};

use crate::{
    error::{ConfigError, display_path},
    input::InputConfig,
    preflight::parse_json,
    schema::ProxyConfig,
    validate::validate_config,
};

use self::{
    compat::classify_ignored_paths,
    dns::input_dns_into_config,
    inbound::input_inbound_into_config,
    outbound::input_outbound_into_config,
    route::input_route_into_config,
    shared::{input_log_into_config, map_serde_error, normalize_path},
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParseDiagnostics {
    pub warnings: Vec<ParseWarning>,
    pub ignored: Vec<ParseIgnored>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseWarning {
    pub path: String,
    pub message: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseIgnored {
    pub path: String,
    pub message: &'static str,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
struct ParseReport {
    config: ProxyConfig,
    diagnostics: ParseDiagnostics,
}

const DEFAULT_DNS_SERVER_PORT: u16 = 53;
const DEFAULT_DOT_SERVER_PORT: u16 = 853;
const DEFAULT_DOH_SERVER_PORT: u16 = 443;
const DEFAULT_DOH_PATH: &str = "/dns-query";

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

fn input_config_into_proxy_config(input_config: InputConfig) -> Result<ProxyConfig, ConfigError> {
    Ok(ProxyConfig {
        log: input_log_into_config(input_config.log),
        dns: input_config.dns.map(input_dns_into_config).transpose()?,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        DEFAULT_CONNECT_TIMEOUT, DEFAULT_SNIFF_TIMEOUT, DEFAULT_TLS_HANDSHAKE_TIMEOUT, DialFields,
        DirectInboundConfig, DirectOutboundConfig, DnsServerTypeConfig, InboundConfig,
        ListenFields, OutboundConfig, RouteActionConfig, RouteFinalActionConfig,
        RouteUpgradeActionConfig, SniffActionConfig, TProxyInboundConfig, TrojanOutboundConfig,
    };

    use super::{
        DEFAULT_DNS_SERVER_PORT, DEFAULT_DOH_PATH, DEFAULT_DOH_SERVER_PORT,
        DEFAULT_DOT_SERVER_PORT, parse_config, parse_config_report_unvalidated,
        parse_config_with_diagnostics,
    };

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
        assert_eq!(config.inbounds.len(), 1);
        assert_eq!(config.outbounds.len(), 2);
    }

    #[test]
    fn parses_all_current_supported_protocol_shapes() {
        let input = r#"
        {
          "log": { "level": "debug", "disabled": false },
          "inbounds": [
            {
              "type": "direct",
              "tag": "direct-in",
              "listen": "127.0.0.1",
              "listen_port": 9000,
              "override_address": "example.com",
              "override_port": 443
            },
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
            "final": "proxy"
          }
        }
        "#;

        let config = parse_config(input).expect("supported protocol mix should parse");
        assert_eq!(config.inbounds.len(), 4);
        assert_eq!(config.outbounds.len(), 2);
        assert_eq!(config.route.final_outbound, "proxy");
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
    fn parses_private_and_local_ip_route_matchers() {
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
                "ip_is_private": true,
                "outbound": "direct"
              },
              {
                "ip_is_loopback": true,
                "outbound": "direct"
              },
              {
                "ip_is_link_local": true,
                "outbound": "direct"
              }
            ]
          }
        }
        "#;

        let config = parse_config(input).expect("private/local ip matchers should parse");
        assert!(config.route.rules[0].ip_is_private);
        assert!(config.route.rules[1].ip_is_loopback);
        assert!(config.route.rules[2].ip_is_link_local);
    }

    #[test]
    fn parses_hijack_dns_action_with_string_inbound_matcher_and_dns_config() {
        let input = r#"
        {
          "dns": {
            "final": "direct-dns",
            "servers": [
              {
                "tag": "direct-dns",
                "type": "udp",
                "server": "223.5.5.5",
                "server_port": 53,
                "detour": "direct"
              }
            ],
            "rules": [
              {
                "domain": "trojan.example.com",
                "server": "direct-dns",
                "action": "route"
              }
            ]
          },
          "inbounds": [
            {
              "type": "direct",
              "tag": "dns-in",
              "listen": "127.0.0.1",
              "listen_port": 15353,
              "network": "udp"
            }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct",
            "rules": [
              {
                "inbound": "dns-in",
                "action": "hijack-dns"
              }
            ]
          }
        }
        "#;

        let config = parse_config(input).expect("dns hijack config should parse");

        assert_eq!(config.route.rules[0].inbound, vec!["dns-in".to_string()]);
        assert!(matches!(
            config.route.rules[0].action,
            RouteActionConfig::Final(RouteFinalActionConfig::HijackDns)
        ));
        let dns = config.dns.expect("dns config should be present");
        assert_eq!(dns.final_server, "direct-dns");
        assert_eq!(dns.rules[0].domain, vec!["trojan.example.com".to_string()]);
        assert_eq!(dns.rules[0].server, "direct-dns");
    }

    #[test]
    fn parses_dns_tcp_server_type() {
        let input = r#"
        {
          "dns": {
            "final": "tcp-dns",
            "servers": [
              {
                "tag": "tcp-dns",
                "type": "tcp",
                "server": "223.5.5.5",
                "server_port": 53,
                "detour": "direct"
              }
            ]
          },
          "inbounds": [
            { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 15353, "network": "udp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct"
          }
        }
        "#;

        let config = parse_config(input).expect("dns tcp config should parse");
        let dns = config.dns.expect("dns config should exist");
        assert!(matches!(dns.servers[0].kind, DnsServerTypeConfig::Tcp));
    }

    #[test]
    fn defaults_dns_final_to_first_server_when_omitted() {
        let input = r#"
        {
          "dns": {
            "servers": [
              {
                "tag": "first-dns",
                "type": "udp",
                "server": "223.5.5.5",
                "detour": "direct"
              },
              {
                "tag": "second-dns",
                "type": "udp",
                "server": "1.1.1.1",
                "detour": "direct"
              }
            ]
          },
          "inbounds": [
            { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 15353, "network": "udp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct"
          }
        }
        "#;

        let config = parse_config(input).expect("dns final should default");
        let dns = config.dns.expect("dns config should exist");

        assert_eq!(dns.final_server, "first-dns");
    }

    #[test]
    fn defaults_dns_final_to_first_server_when_null() {
        let input = r#"
        {
          "dns": {
            "final": null,
            "servers": [
              {
                "tag": "first-dns",
                "type": "udp",
                "server": "223.5.5.5",
                "detour": "direct"
              },
              {
                "tag": "second-dns",
                "type": "udp",
                "server": "1.1.1.1",
                "detour": "direct"
              }
            ]
          },
          "inbounds": [
            { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 15353, "network": "udp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct"
          }
        }
        "#;

        let config = parse_config(input).expect("dns final null should default");
        let dns = config.dns.expect("dns config should exist");

        assert_eq!(dns.final_server, "first-dns");
    }

    #[test]
    fn defaults_dns_final_to_first_server_when_empty_string() {
        let input = r#"
        {
          "dns": {
            "final": "",
            "servers": [
              {
                "tag": "first-dns",
                "type": "udp",
                "server": "223.5.5.5",
                "detour": "direct"
              },
              {
                "tag": "second-dns",
                "type": "udp",
                "server": "1.1.1.1",
                "detour": "direct"
              }
            ]
          },
          "inbounds": [
            { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 15353, "network": "udp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct"
          }
        }
        "#;

        let config = parse_config(input).expect("dns final empty string should default");
        let dns = config.dns.expect("dns config should exist");

        assert_eq!(dns.final_server, "first-dns");
    }

    #[test]
    fn parses_dns_local_server_type_without_detour_or_server() {
        let input = r#"
        {
          "dns": {
            "final": "local-dns",
            "servers": [
              {
                "tag": "local-dns",
                "type": "local"
              }
            ]
          },
          "inbounds": [
            { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 15353, "network": "udp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct"
          }
        }
        "#;

        let config = parse_config(input).expect("dns local config should parse");
        let dns = config.dns.expect("dns config should exist");

        assert!(matches!(dns.servers[0].kind, DnsServerTypeConfig::Local));
        assert!(dns.servers[0].server.is_empty());
        assert!(dns.servers[0].dial.detour.is_none());
        assert_eq!(dns.servers[0].server_port, DEFAULT_DNS_SERVER_PORT);
    }

    #[test]
    fn parses_dns_udp_server_type_without_detour() {
        let input = r#"
        {
          "dns": {
            "final": "remote-dns",
            "servers": [
              {
                "tag": "remote-dns",
                "type": "udp",
                "server": "223.5.5.5"
              }
            ]
          },
          "inbounds": [
            { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 15353, "network": "udp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct"
          }
        }
        "#;

        let config = parse_config(input).expect("dns udp config without detour should parse");
        let dns = config.dns.expect("dns config should exist");

        assert!(matches!(dns.servers[0].kind, DnsServerTypeConfig::Udp));
        assert!(dns.servers[0].dial.detour.is_none());
    }

    #[test]
    fn parses_dns_tls_server_type_with_default_port() {
        let input = r#"
        {
          "dns": {
            "final": "dot-dns",
            "servers": [
              {
                "tag": "dot-dns",
                "type": "tls",
                "server": "dns.example.com",
                "detour": "direct",
                "tls": {
                  "server_name": "dns.example.com",
                  "insecure": true
                }
              }
            ]
          },
          "inbounds": [
            { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 15353, "network": "udp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct"
          }
        }
        "#;

        let config = parse_config(input).expect("dns tls config should parse");
        let dns = config.dns.expect("dns config should exist");
        assert!(matches!(dns.servers[0].kind, DnsServerTypeConfig::Tls));
        assert_eq!(dns.servers[0].server_port, DEFAULT_DOT_SERVER_PORT);
        assert_eq!(
            dns.servers[0].tls.server_name.as_deref(),
            Some("dns.example.com")
        );
    }

    #[test]
    fn parses_dns_https_server_type_with_default_port_and_path() {
        let input = r#"
        {
          "dns": {
            "final": "doh-dns",
            "servers": [
              {
                "tag": "doh-dns",
                "type": "https",
                "server": "dns.example.com",
                "headers": {
                  "X-Test": "true"
                },
                "detour": "direct",
                "tls": {
                  "server_name": "dns.example.com",
                  "insecure": true
                }
              }
            ]
          },
          "inbounds": [
            { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 15353, "network": "udp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct"
          }
        }
        "#;

        let config = parse_config(input).expect("dns https config should parse");
        let dns = config.dns.expect("dns config should exist");
        assert!(matches!(dns.servers[0].kind, DnsServerTypeConfig::Https));
        assert_eq!(dns.servers[0].server_port, DEFAULT_DOH_SERVER_PORT);
        assert_eq!(dns.servers[0].path.as_deref(), Some(DEFAULT_DOH_PATH));
        assert_eq!(
            dns.servers[0].headers.get("X-Test").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn parses_dns_cache_fields_and_rule_action_disable_cache_without_diagnostics() {
        let input = r#"
        {
          "dns": {
            "final": "remote-dns",
            "disable_cache": true,
            "cache_capacity": 2048,
            "servers": [
              {
                "tag": "remote-dns",
                "type": "udp",
                "server": "223.5.5.5",
                "detour": "direct"
              }
            ],
            "rules": [
              {
                "domain": ["cache-bypass.example.com"],
                "server": "remote-dns",
                "action": { "disable_cache": true }
              }
            ]
          },
          "inbounds": [
            { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 15353, "network": "udp" }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "final": "direct"
          }
        }
        "#;

        let (config, diagnostics) =
            parse_config_with_diagnostics(input).expect("dns cache config should parse");
        let dns = config.dns.expect("dns config should exist");
        let warning_paths: Vec<&str> = diagnostics
            .warnings
            .iter()
            .map(|warning| warning.path.as_str())
            .collect();
        let ignored_paths: Vec<&str> = diagnostics
            .ignored
            .iter()
            .map(|ignored| ignored.path.as_str())
            .collect();

        assert!(dns.disable_cache);
        assert_eq!(dns.cache_capacity, Some(2048));
        assert!(dns.rules[0].disable_cache);
        assert!(!warning_paths.contains(&"$.dns.disable_cache"));
        assert!(!warning_paths.contains(&"$.dns.cache_capacity"));
        assert!(!ignored_paths.contains(&"$.dns.disable_cache"));
        assert!(!ignored_paths.contains(&"$.dns.cache_capacity"));
        assert!(!ignored_paths.contains(&"$.dns.rules[0].action.disable_cache"));
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
          "log": { "level": "debug", "timestamp": true, "output": "stdout", "noise": true },
          "dns": {
            "final": "local",
            "strategy": "prefer_ipv4",
            "servers": [
              {
                "tag": "local",
                "type": "udp",
                "server": "223.5.5.5",
                "server_port": 53,
                "detour": "direct"
              }
            ]
          },
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
        assert!(warning_paths.contains(&"$.dns.strategy"));
        assert!(warning_paths.contains(&"$.inbounds[0].sniff"));
        assert!(warning_paths.contains(&"$.inbounds[0].users"));
        assert!(!warning_paths.contains(&"$.outbounds[0].connect_timeout"));
        assert!(!warning_paths.contains(&"$.outbounds[1].domain_resolver"));
        assert!(warning_paths.contains(&"$.outbounds[1].transport"));
        assert!(matches!(
            &report.config.outbounds[1],
            OutboundConfig::Trojan(TrojanOutboundConfig {
                dial: DialFields {
                    domain_resolver: Some(resolver),
                    ..
                },
                ..
            }) if resolver.server == "local"
        ));
        assert!(report.config.route.rules.is_empty());
        assert!(
            report
                .diagnostics
                .ignored
                .iter()
                .all(|ignored| ignored.path != "$.experimental")
        );
        assert!(
            report
                .diagnostics
                .ignored
                .iter()
                .any(|ignored| ignored.path == "$.inbounds[0].tcp_fast_open")
        );
        assert!(
            report
                .diagnostics
                .ignored
                .iter()
                .any(|ignored| ignored.path == "$.outbounds[0].tcp_fast_open")
        );
        assert!(
            report
                .diagnostics
                .ignored
                .iter()
                .any(|ignored| ignored.path == "$.log.output")
        );
        assert!(
            report
                .diagnostics
                .ignored
                .iter()
                .all(|ignored| ignored.path != "$.log.noise")
        );
    }

    #[test]
    fn parses_structured_domain_resolver_and_warns_on_extra_fields() {
        let input = r#"
        {
          "dns": {
            "final": "bootstrap",
            "servers": [
              {
                "tag": "bootstrap",
                "type": "udp",
                "server": "223.5.5.5",
                "server_port": 53,
                "detour": "direct"
              }
            ]
          },
          "inbounds": [
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct", "domain_resolver": { "server": "bootstrap", "strategy": "prefer_ipv6" } }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let report =
            parse_config_report_unvalidated(input).expect("structured resolver should parse");
        assert!(matches!(
            &report.config.outbounds[0],
            OutboundConfig::Direct(DirectOutboundConfig {
                dial: DialFields {
                    domain_resolver: Some(resolver),
                    ..
                },
                ..
            }) if resolver.server == "bootstrap"
        ));
        assert!(
            report
                .diagnostics
                .warnings
                .iter()
                .any(|warning| warning.path == "$.outbounds[0].domain_resolver.strategy")
        );
    }

    #[test]
    fn parses_direct_inbound_with_optional_override_fields() {
        let input = r#"
        {
          "inbounds": [
            {
              "type": "direct",
              "tag": "direct-in",
              "listen": "::",
              "listen_port": 9000,
              "network": "tcp",
              "override_address": "example.com",
              "override_port": 8443
            }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let config = parse_config(input).expect("direct inbound config should parse");
        assert_eq!(
            config.inbounds,
            vec![InboundConfig::Direct(DirectInboundConfig {
                tag: "direct-in".into(),
                listen: ListenFields::new("::", 9000),
                network: Some("tcp".into()),
                override_address: Some("example.com".into()),
                override_port: Some(8443),
            })]
        );
    }

    #[test]
    fn collects_direct_inbound_warning_and_ignore_paths() {
        let input = r#"
        {
          "inbounds": [
            {
              "type": "direct",
              "tag": "direct-in",
              "listen": "127.0.0.1",
              "listen_port": 9000,
              "sniff": true,
              "udp_timeout": "5m",
              "tcp_fast_open": true
            }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
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
        let ignored_paths: Vec<&str> = report
            .diagnostics
            .ignored
            .iter()
            .map(|ignored| ignored.path.as_str())
            .collect();

        assert!(warning_paths.contains(&"$.inbounds[0].sniff"));
        assert!(ignored_paths.contains(&"$.inbounds[0].udp_timeout"));
        assert!(ignored_paths.contains(&"$.inbounds[0].tcp_fast_open"));
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
        assert!(
            !diagnostics
                .warnings
                .iter()
                .any(|warning| warning.path == "$.log.timestamp")
        );
    }

    #[test]
    fn top_level_unknown_fields_still_parse_successfully() {
        let input = r#"
        {
          "dns": {
            "final": "local",
            "servers": [
              {
                "tag": "local",
                "type": "udp",
                "server": "223.5.5.5",
                "server_port": 53,
                "detour": "direct"
              }
            ]
          },
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
          "dns": {
            "final": "local",
            "strategy": "prefer_ipv4",
            "servers": [
              {
                "tag": "local",
                "type": "udp",
                "server": "223.5.5.5",
                "server_port": 53,
                "detour": "direct"
              }
            ]
          },
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
        assert!(warning_paths.contains(&"$.dns.strategy"));
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
                listen: ListenFields::new("0.0.0.0", 1041),
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
                dial: DialFields {
                    routing_mark: Some(1),
                    ..DialFields::new(DEFAULT_CONNECT_TIMEOUT)
                },
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
                assert_eq!(direct.dial.connect_timeout, Duration::from_millis(300));
            }
            other => panic!("expected direct outbound, got {other:?}"),
        }

        match &config.outbounds[1] {
            OutboundConfig::Trojan(trojan) => {
                assert_eq!(trojan.dial.connect_timeout, Duration::from_secs(5));
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
                assert_eq!(direct.dial.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
            }
            other => panic!("expected direct outbound, got {other:?}"),
        }

        match &config.outbounds[1] {
            OutboundConfig::Trojan(trojan) => {
                assert_eq!(trojan.dial.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
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
        assert!(
            err.to_string()
                .contains("invalid duration, expected formats like 300ms, 5s, 2m")
        );
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
        assert!(
            err.to_string()
                .contains("$.outbounds[1].tls.handshake_timeout")
        );
        assert!(
            err.to_string()
                .contains("invalid duration, expected formats like 300ms, 5s, 2m")
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
        assert!(err.to_string().contains("expected struct InputTlsFields"));
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
    fn rejects_direct_inbound_network_other_than_supported_values() {
        let input = r#"
        {
          "inbounds": [
            {
              "type": "direct",
              "tag": "direct-in",
              "listen": "0.0.0.0",
              "listen_port": 9000,
              "network": "quic"
            }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let err = parse_config(input).expect_err("unsupported direct inbound network should fail");
        assert!(err.to_string().contains("$.inbounds[0].network"));
        assert!(
            err.to_string()
                .contains("only supports network='tcp' or network='udp'")
        );
    }

    #[test]
    fn accepts_direct_inbound_udp_network() {
        let input = r#"
        {
          "inbounds": [
            {
              "type": "direct",
              "tag": "direct-in",
              "listen": "127.0.0.1",
              "listen_port": 9000,
              "network": "udp",
              "override_address": "127.0.0.1",
              "override_port": 53
            }
          ],
          "outbounds": [
            { "type": "direct", "tag": "direct" }
          ],
          "route": { "final": "direct" }
        }
        "#;

        let config = parse_config(input).expect("udp direct inbound should parse");
        assert_eq!(
            config.inbounds,
            vec![InboundConfig::Direct(DirectInboundConfig {
                tag: "direct-in".into(),
                listen: ListenFields::new("127.0.0.1", 9000),
                network: Some("udp".into()),
                override_address: Some("127.0.0.1".into()),
                override_port: Some(53),
            })]
        );
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
        assert!(
            err.to_string()
                .contains("only supported for action='sniff'")
        );
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
    fn rejects_removed_route_bypass_field() {
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

        let err = parse_config(input).expect_err("route bypass should be rejected");
        assert!(err.to_string().contains("$.route.bypass"));
        assert!(err.to_string().contains("route.bypass has been removed"));
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
        let input = include_str!("../../../../examples/tproxy-compat.json");

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
        assert_eq!(report.config.route.rules.len(), 6);
        assert!(report.config.route.rules[0].ip_is_loopback);
        assert!(report.config.route.rules[1].ip_is_private);
        assert!(report.config.route.rules[2].ip_is_link_local);
        assert_eq!(
            report.config.route.rules[3].inbound,
            vec!["tproxy-in".to_string()]
        );
        assert!(matches!(
            &report.config.route.rules[3].action,
            RouteActionConfig::Upgrade(RouteUpgradeActionConfig::Sniff(SniffActionConfig {
                timeout
            })) if *timeout == DEFAULT_SNIFF_TIMEOUT
        ));
        assert_eq!(
            report.config.route.rules[5].domain_suffix,
            vec!["lan".to_string()]
        );
        assert!(warning_paths.contains(&"$.dns.strategy"));
        assert!(!warning_paths.contains(&"$.outbounds[1].domain_resolver"));
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

        assert!(
            diagnostics
                .ignored
                .iter()
                .all(|ignored| ignored.path != "$.outbounds[1].tls.unknown_field")
        );
        assert!(
            diagnostics
                .warnings
                .iter()
                .all(|warning| warning.path != "$.outbounds[1].tls.unknown_field")
        );
    }
}
