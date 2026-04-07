use std::collections::BTreeSet;

use crate::{
    defaults::DEFAULT_DIRECT_OUTBOUND_TAG,
    error::ConfigError,
    schema::{InboundConfig, OutboundConfig, ProxyConfig},
};

pub fn validate_config(config: &ProxyConfig) -> Result<(), ConfigError> {
    validate_log(config)?;
    let inbound_tags = validate_inbounds(config)?;
    let outbound_tags = validate_outbounds(config)?;
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

    for (index, bypass) in config.route.bypass.iter().enumerate() {
        let bypass = bypass.trim();
        if bypass.starts_with("*.") || bypass.starts_with('.') {
            return Err(ConfigError::semantic(
                format!("$.route.bypass[{index}]"),
                "unsupported bypass pattern",
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        DirectOutboundConfig, InboundConfig, LogConfig, OutboundConfig, ProxyConfig, RouteConfig,
        SocksInboundConfig, TProxyInboundConfig,
    };

    use super::validate_config;

    fn valid_config() -> ProxyConfig {
        ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
                timestamp: false,
            },
            inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
                tag: "socks-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: 1080,
            })],
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                routing_mark: None,
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
                bypass: vec![],
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
}
