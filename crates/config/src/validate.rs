use std::collections::BTreeSet;

use crate::{
    defaults::DEFAULT_DIRECT_OUTBOUND_TAG,
    error::ConfigError,
    schema::{OutboundConfig, ProxyConfig},
};

pub fn validate_config(config: &ProxyConfig) -> Result<(), ConfigError> {
    let mut inbound_tags = BTreeSet::new();
    for inbound in &config.inbounds {
        let tag = inbound.tag();
        if !inbound_tags.insert(tag.to_string()) {
            return Err(ConfigError::validation(
                "$.inbounds",
                format!("duplicate inbound tag '{tag}'"),
            ));
        }
    }

    let mut outbound_tags = BTreeSet::new();
    for outbound in &config.outbounds {
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
                    format!("$.outbounds[{tag}].tls.enabled"),
                    "trojan outbound requires TLS to be enabled",
                ));
            }

            if trojan.tls.disable_sni && !trojan.tls.insecure && trojan.tls.server_name.is_none() {
                return Err(ConfigError::semantic(
                    format!("$.outbounds[{tag}].tls"),
                    "disable_sni=true requires server_name or insecure=true",
                ));
            }
        }
    }

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
