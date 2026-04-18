use std::collections::BTreeSet;

use crate::{
    error::ConfigError,
    schema::{OutboundConfig, ProxyConfig},
};

pub(crate) fn validate_outbounds(config: &ProxyConfig) -> Result<BTreeSet<String>, ConfigError> {
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
