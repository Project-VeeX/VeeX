use std::collections::BTreeSet;

use crate::{
    error::ConfigError,
    schema::{DnsServerTypeConfig, OutboundConfig, ProxyConfig},
};

pub(crate) fn validate_log(config: &ProxyConfig) -> Result<(), ConfigError> {
    match config.log.level.as_str() {
        "error" | "warn" | "warning" | "info" | "debug" => Ok(()),
        other => Err(ConfigError::semantic(
            "$.log.level",
            format!("unsupported log level '{other}'"),
        )),
    }
}

pub(crate) fn validate_domain_resolvers(
    config: &ProxyConfig,
    dns_server_tags: Option<&BTreeSet<String>>,
) -> Result<(), ConfigError> {
    for (index, outbound) in config.outbounds.iter().enumerate() {
        let domain_resolver = match outbound {
            OutboundConfig::Direct(config) => config.dial.domain_resolver.as_ref(),
            OutboundConfig::Trojan(config) => config.dial.domain_resolver.as_ref(),
        };

        if let Some(resolver) = domain_resolver {
            validate_domain_resolver_reference(
                dns_server_tags,
                &resolver.server,
                format!("$.outbounds[{index}].domain_resolver.server"),
            )?;
        }
    }

    if let Some(dns) = config.dns.as_ref() {
        for (index, server) in dns.servers.iter().enumerate() {
            if matches!(server.kind, DnsServerTypeConfig::Local) {
                continue;
            }
            if let Some(resolver) = server.dial.domain_resolver.as_ref() {
                validate_domain_resolver_reference(
                    dns_server_tags,
                    &resolver.server,
                    format!("$.dns.servers[{index}].domain_resolver.server"),
                )?;
                if resolver.server == server.tag {
                    return Err(ConfigError::semantic(
                        format!("$.dns.servers[{index}].domain_resolver.server"),
                        "dns server domain_resolver must not point to itself",
                    ));
                }
            }
        }
    }

    Ok(())
}

fn validate_domain_resolver_reference(
    dns_server_tags: Option<&BTreeSet<String>>,
    server_tag: &str,
    path: String,
) -> Result<(), ConfigError> {
    let Some(dns_server_tags) = dns_server_tags else {
        return Err(ConfigError::semantic(
            path,
            "domain_resolver requires a dns section",
        ));
    };

    if !dns_server_tags.contains(server_tag) {
        return Err(ConfigError::semantic(
            path,
            format!("domain_resolver points to missing dns server '{server_tag}'"),
        ));
    }

    Ok(())
}

pub(crate) fn contains_http_newline(value: &str) -> bool {
    value.contains('\r') || value.contains('\n')
}
