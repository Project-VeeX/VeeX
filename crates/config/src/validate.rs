use std::collections::BTreeSet;

use crate::{
    defaults::DEFAULT_DIRECT_OUTBOUND_TAG,
    error::ConfigError,
    schema::{
        DirectInboundConfig, DnsConfig, DnsRuleConfig, DnsServerConfig, InboundConfig,
        OutboundConfig, ProxyConfig, RouteActionConfig, RouteFinalActionConfig, RouteRuleConfig,
    },
};

pub fn validate_config(config: &ProxyConfig) -> Result<(), ConfigError> {
    validate_log(config)?;
    let inbound_tags = validate_inbounds(config)?;
    let outbound_tags = validate_outbounds(config)?;
    validate_dns(config.dns.as_ref(), &outbound_tags)?;
    validate_route(config, &outbound_tags)?;

    debug_assert!(
        !inbound_tags.is_empty(),
        "validated configs always contain at least one inbound"
    );

    Ok(())
}

fn validate_log(config: &ProxyConfig) -> Result<(), ConfigError> {
    match config.log.level.as_str() {
        "error" | "warn" | "warning" | "info" | "debug" => Ok(()),
        other => Err(ConfigError::semantic(
            "$.log.level",
            format!("unsupported log level '{other}'"),
        )),
    }
}

fn validate_inbounds(config: &ProxyConfig) -> Result<BTreeSet<String>, ConfigError> {
    if config.inbounds.is_empty() {
        return Err(ConfigError::semantic(
            "$.inbounds",
            "at least one inbound is required",
        ));
    }

    let mut inbound_tags = BTreeSet::new();
    for (index, inbound) in config.inbounds.iter().enumerate() {
        let tag = inbound.tag();
        if !inbound_tags.insert(tag.to_string()) {
            return Err(ConfigError::validation(
                "$.inbounds",
                format!("duplicate inbound tag '{tag}'"),
            ));
        }

        if let InboundConfig::Direct(direct) = inbound {
            validate_direct_inbound(direct, index)?;
        }

        if let InboundConfig::TProxy(tproxy) = inbound {
            if let Some(network) = tproxy.network.as_deref() {
                if network != "tcp" {
                    return Err(ConfigError::semantic(
                        format!("$.inbounds[{index}].network"),
                        "tproxy inbound only supports network='tcp'",
                    ));
                }
            }
        }
    }

    Ok(inbound_tags)
}

fn validate_direct_inbound(direct: &DirectInboundConfig, index: usize) -> Result<(), ConfigError> {
    if let Some(network) = direct.network.as_deref() {
        if network != "tcp" && network != "udp" {
            return Err(ConfigError::semantic(
                format!("$.inbounds[{index}].network"),
                "direct inbound only supports network='tcp' or network='udp'",
            ));
        }
    }

    if let Some(address) = direct.override_address.as_deref() {
        if address.trim().is_empty() {
            return Err(ConfigError::semantic(
                format!("$.inbounds[{index}].override_address"),
                "override_address must not be empty",
            ));
        }
    }

    if matches!(direct.override_port, Some(0)) {
        return Err(ConfigError::semantic(
            format!("$.inbounds[{index}].override_port"),
            "override_port must be in 1..=65535",
        ));
    }

    Ok(())
}

fn validate_outbounds(config: &ProxyConfig) -> Result<BTreeSet<String>, ConfigError> {
    let mut outbound_tags = BTreeSet::new();
    for (index, outbound) in config.outbounds.iter().enumerate() {
        let tag = outbound.tag();
        if !outbound_tags.insert(tag.to_string()) {
            return Err(ConfigError::semantic(
                "$.outbounds",
                format!("duplicate outbound tag '{tag}'"),
            ));
        }

        if let OutboundConfig::Trojan(trojan) = outbound {
            if !trojan.tls.enabled {
                return Err(ConfigError::semantic(
                    format!("$.outbounds[{index}].tls.enabled"),
                    "trojan outbound requires TLS to be enabled",
                ));
            }

            if trojan.tls.disable_sni && !trojan.tls.insecure && trojan.tls.server_name.is_none() {
                return Err(ConfigError::semantic(
                    format!("$.outbounds[{index}].tls"),
                    "disable_sni=true requires server_name or insecure=true",
                ));
            }
        }
    }

    Ok(outbound_tags)
}

fn validate_route(
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

    if !outbound_tags.contains(DEFAULT_DIRECT_OUTBOUND_TAG) {
        return Err(ConfigError::semantic(
            "$.outbounds",
            format!(
                "required direct outbound tag '{}' is missing",
                DEFAULT_DIRECT_OUTBOUND_TAG
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

fn validate_dns(
    dns: Option<&DnsConfig>,
    outbound_tags: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    let Some(dns) = dns else {
        return Ok(());
    };

    if dns.servers.is_empty() {
        return Err(ConfigError::semantic(
            "$.dns.servers",
            "dns.servers must contain at least one server",
        ));
    }

    let mut server_tags = BTreeSet::new();
    for (index, server) in dns.servers.iter().enumerate() {
        validate_dns_server(server, index, outbound_tags)?;
        if !server_tags.insert(server.tag.clone()) {
            return Err(ConfigError::semantic(
                "$.dns.servers",
                format!("duplicate dns server tag '{}'", server.tag),
            ));
        }
    }

    if !server_tags.contains(&dns.final_server) {
        return Err(ConfigError::semantic(
            "$.dns.final",
            format!(
                "dns.final points to missing dns server '{}'",
                dns.final_server
            ),
        ));
    }

    for (index, rule) in dns.rules.iter().enumerate() {
        validate_dns_rule(rule, index, &server_tags)?;
    }

    Ok(())
}

fn validate_dns_server(
    server: &DnsServerConfig,
    index: usize,
    outbound_tags: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    if server.tag.trim().is_empty() {
        return Err(ConfigError::semantic(
            format!("$.dns.servers[{index}].tag"),
            "dns server tag must not be empty",
        ));
    }

    if server.server.trim().is_empty() {
        return Err(ConfigError::semantic(
            format!("$.dns.servers[{index}].server"),
            "dns server address must not be empty",
        ));
    }

    if server.server_port == 0 {
        return Err(ConfigError::semantic(
            format!("$.dns.servers[{index}].server_port"),
            "dns server port must be in 1..=65535",
        ));
    }

    if server.detour.trim().is_empty() {
        return Err(ConfigError::semantic(
            format!("$.dns.servers[{index}].detour"),
            "dns server detour must not be empty",
        ));
    }

    if !outbound_tags.contains(&server.detour) {
        return Err(ConfigError::semantic(
            format!("$.dns.servers[{index}].detour"),
            format!(
                "dns server detour points to missing outbound '{}'",
                server.detour
            ),
        ));
    }

    Ok(())
}

fn validate_dns_rule(
    rule: &DnsRuleConfig,
    index: usize,
    server_tags: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    if !rule.has_matcher() {
        return Err(ConfigError::semantic(
            format!("$.dns.rules[{index}]"),
            "dns rule requires at least one matcher",
        ));
    }

    if !server_tags.contains(&rule.server) {
        return Err(ConfigError::semantic(
            format!("$.dns.rules[{index}].server"),
            format!("dns rule points to missing dns server '{}'", rule.server),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        DirectInboundConfig, DirectOutboundConfig, DnsConfig, DnsServerConfig, DnsServerTypeConfig,
        InboundConfig, LogConfig, OutboundConfig, ProxyConfig, RouteActionConfig, RouteConfig,
        RouteFinalActionConfig, RouteRuleConfig, RouteTargetConfig, RouteUpgradeActionConfig,
        SniffActionConfig, SocksInboundConfig, TProxyInboundConfig, DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_SNIFF_TIMEOUT,
    };

    use super::validate_config;

    fn valid_config() -> ProxyConfig {
        ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            dns: None,
            inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
                tag: "socks-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: 1080,
            })],
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                routing_mark: None,
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
                rules: vec![],
            },
        }
    }

    #[test]
    fn rejects_unsupported_log_level() {
        let mut config = valid_config();
        config.log.level = "trace".into();

        let err = validate_config(&config).expect_err("unsupported log level should fail");
        assert!(err.to_string().contains("$.log.level"));
        assert!(err.to_string().contains("unsupported log level"));
    }

    #[test]
    fn rejects_empty_inbounds_before_bootstrap() {
        let mut config = valid_config();
        config.inbounds.clear();

        let err = validate_config(&config).expect_err("empty inbound list should fail");
        assert!(err.to_string().contains("$.inbounds"));
        assert!(err.to_string().contains("at least one inbound"));
    }

    #[test]
    fn validates_tproxy_network_as_a_cross_field_rule() {
        let mut config = valid_config();
        config.inbounds = vec![InboundConfig::TProxy(TProxyInboundConfig {
            tag: "tproxy-in".into(),
            listen: "0.0.0.0".into(),
            listen_port: 1041,
            network: Some("udp".into()),
        })];

        let err = validate_config(&config).expect_err("non-tcp tproxy network should fail");
        assert!(err.to_string().contains("$.inbounds[0].network"));
        assert!(err.to_string().contains("only supports network='tcp'"));
    }

    #[test]
    fn validates_direct_inbound_network_as_a_cross_field_rule() {
        let mut config = valid_config();
        config.inbounds = vec![InboundConfig::Direct(DirectInboundConfig {
            tag: "direct-in".into(),
            listen: "0.0.0.0".into(),
            listen_port: 9000,
            network: Some("quic".into()),
            override_address: None,
            override_port: None,
        })];

        let err = validate_config(&config).expect_err("unsupported direct network should fail");
        assert!(err.to_string().contains("$.inbounds[0].network"));
        assert!(err
            .to_string()
            .contains("only supports network='tcp' or network='udp'"));
    }

    #[test]
    fn accepts_udp_direct_inbound_network() {
        let mut config = valid_config();
        config.inbounds = vec![InboundConfig::Direct(DirectInboundConfig {
            tag: "direct-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: 9000,
            network: Some("udp".into()),
            override_address: Some("127.0.0.1".into()),
            override_port: Some(53),
        })];

        validate_config(&config).expect("udp direct inbound should validate");
    }

    #[test]
    fn rejects_empty_direct_inbound_override_address() {
        let mut config = valid_config();
        config.inbounds = vec![InboundConfig::Direct(DirectInboundConfig {
            tag: "direct-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: 9000,
            network: None,
            override_address: Some("   ".into()),
            override_port: None,
        })];

        let err = validate_config(&config).expect_err("empty override_address should fail");
        assert!(err.to_string().contains("$.inbounds[0].override_address"));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn rejects_hijack_dns_route_rule_when_dns_section_is_missing() {
        let mut config = valid_config();
        config.route.rules.push(RouteRuleConfig {
            domain: vec![],
            domain_suffix: vec![],
            ip_cidr: vec![],
            ip_is_private: false,
            ip_is_loopback: false,
            ip_is_link_local: false,
            port: vec![],
            inbound: vec!["dns-in".into()],
            action: RouteActionConfig::Final(RouteFinalActionConfig::HijackDns),
        });

        let err = validate_config(&config).expect_err("missing dns section should fail");
        assert!(err.to_string().contains("$.route.rules[0].action"));
        assert!(err.to_string().contains("requires a dns section"));
    }

    #[test]
    fn accepts_dns_section_with_udp_server_detour() {
        let mut config = valid_config();
        config.dns = Some(DnsConfig {
            final_server: "local".into(),
            servers: vec![DnsServerConfig {
                tag: "local".into(),
                kind: DnsServerTypeConfig::Udp,
                server: "223.5.5.5".into(),
                server_port: 53,
                detour: "direct".into(),
            }],
            rules: vec![],
        });

        validate_config(&config).expect("minimal dns section should validate");
    }

    #[test]
    fn accepts_dns_section_with_tcp_server_detour() {
        let mut config = valid_config();
        config.dns = Some(DnsConfig {
            final_server: "local".into(),
            servers: vec![DnsServerConfig {
                tag: "local".into(),
                kind: DnsServerTypeConfig::Tcp,
                server: "223.5.5.5".into(),
                server_port: 53,
                detour: "direct".into(),
            }],
            rules: vec![],
        });

        validate_config(&config).expect("tcp dns section should validate");
    }

    #[test]
    fn rejects_route_rule_without_any_matchers() {
        let mut config = valid_config();
        config.route.rules.push(RouteRuleConfig {
            domain: vec![],
            domain_suffix: vec![],
            ip_cidr: vec![],
            ip_is_private: false,
            ip_is_loopback: false,
            ip_is_link_local: false,
            port: vec![],
            inbound: vec![],
            action: RouteActionConfig::Final(RouteFinalActionConfig::Route(RouteTargetConfig {
                outbound: "direct".into(),
            })),
        });

        let err = validate_config(&config).expect_err("route rule without matchers should fail");
        assert!(err.to_string().contains("$.route.rules[0]"));
        assert!(err.to_string().contains("at least one matcher"));
    }

    #[test]
    fn rejects_route_rule_with_missing_outbound_target() {
        let mut config = valid_config();
        config.route.rules.push(RouteRuleConfig {
            domain: vec!["example.com".into()],
            domain_suffix: vec![],
            ip_cidr: vec![],
            ip_is_private: false,
            ip_is_loopback: false,
            ip_is_link_local: false,
            port: vec![],
            inbound: vec![],
            action: RouteActionConfig::Final(RouteFinalActionConfig::Route(RouteTargetConfig {
                outbound: "proxy".into(),
            })),
        });

        let err = validate_config(&config).expect_err("missing outbound target should fail");
        assert!(err.to_string().contains("$.route.rules[0].outbound"));
        assert!(err.to_string().contains("missing outbound 'proxy'"));
    }

    #[test]
    fn accepts_sniff_upgrade_rule_without_outbound_target() {
        let mut config = valid_config();
        config.route.rules.push(RouteRuleConfig {
            domain: vec![],
            domain_suffix: vec![],
            ip_cidr: vec![],
            ip_is_private: false,
            ip_is_loopback: false,
            ip_is_link_local: false,
            port: vec![443],
            inbound: vec!["tproxy-in".into()],
            action: RouteActionConfig::Upgrade(RouteUpgradeActionConfig::Sniff(
                SniffActionConfig {
                    timeout: DEFAULT_SNIFF_TIMEOUT,
                },
            )),
        });

        validate_config(&config).expect("sniff upgrade rule should validate");
    }

    #[test]
    fn accepts_private_ip_route_rule_matcher() {
        let mut config = valid_config();
        config.route.rules.push(RouteRuleConfig {
            domain: vec![],
            domain_suffix: vec![],
            ip_cidr: vec![],
            ip_is_private: true,
            ip_is_loopback: false,
            ip_is_link_local: false,
            port: vec![],
            inbound: vec![],
            action: RouteActionConfig::Final(RouteFinalActionConfig::Route(RouteTargetConfig {
                outbound: "direct".into(),
            })),
        });

        validate_config(&config).expect("private-ip route rule should validate");
    }
}
