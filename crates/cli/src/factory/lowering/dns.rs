use veex_config::{DnsConfig, DnsRuleConfig, DnsServerConfig, DnsServerTypeConfig};
use veex_core::{
    portal::Dial,
    types::{Destination, Host},
};
use veex_dns::{
    DnsHttpsOptions, DnsRule, DnsRuntimeConfig, DnsServer, DnsServerTransport, DEFAULT_DOH_PATH,
};

use crate::factory::lowering::shared::{lower_tls_options, parse_host};

pub(crate) fn lower_dns(dns: &DnsConfig) -> DnsRuntimeConfig {
    DnsRuntimeConfig {
        final_server_tag: dns.final_server.clone(),
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
            DnsServerTypeConfig::Tls => DnsServerTransport::Tls(lower_tls_options(&server.tls)),
            DnsServerTypeConfig::Https => DnsServerTransport::Https(DnsHttpsOptions {
                path: server
                    .path
                    .clone()
                    .unwrap_or_else(|| DEFAULT_DOH_PATH.to_string()),
                headers: server.headers.clone(),
                tls: lower_tls_options(&server.tls),
            }),
            DnsServerTypeConfig::Unsupported(kind) => DnsServerTransport::Unsupported(kind.clone()),
        },
        destination: match &server.kind {
            DnsServerTypeConfig::Local => Destination::new(Host::Domain("local".into()), 53),
            _ => Destination::new(parse_host(&server.server), server.server_port),
        },
        dial: Dial {
            detour: (!server.detour.is_empty()).then(|| server.detour.clone()),
            connect_timeout: None,
            routing_mark: None,
            domain_resolver: server
                .domain_resolver
                .as_ref()
                .map(|resolver| resolver.server.clone()),
        },
    }
}

fn lower_dns_rule(rule: &DnsRuleConfig) -> DnsRule {
    DnsRule {
        domain: rule.domain.clone(),
        server_tag: rule.server.clone(),
    }
}
