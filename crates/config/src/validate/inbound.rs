use std::collections::BTreeSet;

use crate::{
    error::ConfigError,
    schema::{DirectInboundConfig, InboundConfig, ProxyConfig},
};

pub(crate) fn validate_inbounds(config: &ProxyConfig) -> Result<BTreeSet<String>, ConfigError> {
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
