use std::collections::BTreeSet;

use crate::{
    error::ConfigError,
    schema::{DnsConfig, DnsRuleConfig, DnsServerConfig, DnsServerTypeConfig},
};

use super::shared::contains_http_newline;

pub(crate) fn validate_dns(
    dns: Option<&DnsConfig>,
    outbound_tags: &BTreeSet<String>,
) -> Result<Option<BTreeSet<String>>, ConfigError> {
    let Some(dns) = dns else {
        return Ok(None);
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

    Ok(Some(server_tags))
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

    if matches!(server.kind, DnsServerTypeConfig::Local) {
        return Ok(());
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

    if !server.detour.trim().is_empty() && !outbound_tags.contains(&server.detour) {
        return Err(ConfigError::semantic(
            format!("$.dns.servers[{index}].detour"),
            format!(
                "dns server detour points to missing outbound '{}'",
                server.detour
            ),
        ));
    }

    if matches!(
        server.kind,
        DnsServerTypeConfig::Tls | DnsServerTypeConfig::Https
    ) {
        if !server.tls.enabled {
            return Err(ConfigError::semantic(
                format!("$.dns.servers[{index}].tls.enabled"),
                "dns tls/https server requires tls.enabled=true",
            ));
        }

        if server.tls.disable_sni && !server.tls.insecure && server.tls.server_name.is_none() {
            return Err(ConfigError::semantic(
                format!("$.dns.servers[{index}].tls"),
                "disable_sni=true requires server_name or insecure=true",
            ));
        }
    }

    if matches!(server.kind, DnsServerTypeConfig::Https) {
        let path = server.path.as_deref().ok_or_else(|| {
            ConfigError::semantic(
                format!("$.dns.servers[{index}].path"),
                "https dns server requires a request path",
            )
        })?;
        if path.trim().is_empty() {
            return Err(ConfigError::semantic(
                format!("$.dns.servers[{index}].path"),
                "https dns server path must not be empty",
            ));
        }
        if !path.starts_with('/') {
            return Err(ConfigError::semantic(
                format!("$.dns.servers[{index}].path"),
                "https dns server path must start with '/'",
            ));
        }
    }

    for (header_name, header_value) in &server.headers {
        if header_name.trim().is_empty() {
            return Err(ConfigError::semantic(
                format!("$.dns.servers[{index}].headers"),
                "dns https header name must not be empty",
            ));
        }
        if contains_http_newline(header_name) || contains_http_newline(header_value) {
            return Err(ConfigError::semantic(
                format!("$.dns.servers[{index}].headers"),
                "dns https headers must not contain CR or LF characters",
            ));
        }
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
