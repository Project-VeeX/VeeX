use veex_config::{DnsConfig, DnsRuleConfig, DnsServerConfig, DnsServerTypeConfig};
use veex_core::types::{Destination, Host};
use veex_dns::{
    DEFAULT_DNS_CACHE_CAPACITY, DEFAULT_DOH_PATH, DnsHttpsOptions, DnsRule, DnsRuntimeConfig,
    DnsServer, DnsServerTransport, MIN_DNS_CACHE_CAPACITY,
};

use crate::factory::lowering::shared::{lower_dial_fields, lower_tls_fields, parse_host};

pub(crate) fn lower_dns(dns: &DnsConfig) -> DnsRuntimeConfig {
    DnsRuntimeConfig {
        final_server_tag: dns.final_server.clone(),
        disable_cache: dns.disable_cache,
        cache_capacity: lower_dns_cache_capacity(dns.cache_capacity),
        servers: dns.servers.iter().map(lower_dns_server).collect(),
        rules: dns.rules.iter().map(lower_dns_rule).collect(),
    }
}

fn lower_dns_server(server: &DnsServerConfig) -> DnsServer {
    DnsServer {
        tag: server.tag.clone(),
        transport: match &server.kind {
            DnsServerTypeConfig::Local => DnsServerTransport::Local,
            DnsServerTypeConfig::Udp => DnsServerTransport::Udp,
            DnsServerTypeConfig::Tcp => DnsServerTransport::Tcp,
            DnsServerTypeConfig::Tls => DnsServerTransport::Tls(lower_tls_fields(&server.tls)),
            DnsServerTypeConfig::Https => DnsServerTransport::Https(DnsHttpsOptions {
                path: server
                    .path
                    .clone()
                    .unwrap_or_else(|| DEFAULT_DOH_PATH.to_string()),
                headers: server.headers.clone(),
                tls: lower_tls_fields(&server.tls),
            }),
            DnsServerTypeConfig::Unsupported(kind) => DnsServerTransport::Unsupported(kind.clone()),
        },
        destination: match &server.kind {
            DnsServerTypeConfig::Local => Destination::new(Host::Domain("local".into()), 53),
            _ => Destination::new(parse_host(&server.server), server.server_port),
        },
        dial: lower_dial_fields(&server.dial),
    }
}

fn lower_dns_rule(rule: &DnsRuleConfig) -> DnsRule {
    DnsRule {
        domain: rule.domain.clone(),
        server_tag: rule.server.clone(),
        disable_cache: rule.disable_cache,
    }
}

fn lower_dns_cache_capacity(value: Option<usize>) -> usize {
    match value {
        Some(capacity) if capacity >= MIN_DNS_CACHE_CAPACITY => capacity,
        _ => DEFAULT_DNS_CACHE_CAPACITY,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use veex_config::{
        DEFAULT_CONNECT_TIMEOUT, DialFields, DnsConfig, DnsRuleConfig, DnsServerConfig,
        DnsServerTypeConfig, TlsFields,
    };
    use veex_dns::DEFAULT_DNS_CACHE_CAPACITY;

    use super::lower_dns;

    fn dns_server(tag: &str) -> DnsServerConfig {
        DnsServerConfig {
            tag: tag.into(),
            kind: DnsServerTypeConfig::Udp,
            server: "223.5.5.5".into(),
            server_port: 53,
            path: None,
            headers: BTreeMap::new(),
            dial: DialFields {
                detour: Some("direct".into()),
                ..DialFields::new(DEFAULT_CONNECT_TIMEOUT)
            },
            tls: TlsFields {
                enabled: true,
                alpn: None,
                server_name: None,
                disable_sni: false,
                insecure: false,
                certificate_path: None,
                ca_path: None,
                handshake_timeout: veex_config::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
            },
        }
    }

    #[test]
    fn lower_dns_keeps_supported_cache_capacity_and_rule_disable_cache() {
        let runtime = lower_dns(&DnsConfig {
            final_server: "remote".into(),
            disable_cache: false,
            cache_capacity: Some(2048),
            servers: vec![dns_server("remote")],
            rules: vec![DnsRuleConfig {
                domain: vec!["cache-bypass.example.com".into()],
                server: "remote".into(),
                disable_cache: true,
            }],
        });

        assert_eq!(runtime.cache_capacity, 2048);
        assert!(runtime.rules[0].disable_cache);
    }

    #[test]
    fn lower_dns_ignores_cache_capacity_smaller_than_minimum() {
        let runtime = lower_dns(&DnsConfig {
            final_server: "remote".into(),
            disable_cache: false,
            cache_capacity: Some(512),
            servers: vec![dns_server("remote")],
            rules: Vec::new(),
        });

        assert_eq!(runtime.cache_capacity, DEFAULT_DNS_CACHE_CAPACITY);
    }
}
