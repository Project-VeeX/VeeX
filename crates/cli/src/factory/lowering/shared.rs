use std::{net::IpAddr, str::FromStr};

use veex_config::{DialFields, ListenFields, TlsFields};
use veex_core::{
    portal::{Dial, Listen},
    types::Host,
};
use veex_transport::OutboundTls;

pub(super) fn lower_listen_fields(config: &ListenFields) -> Listen {
    Listen::new(config.listen.clone(), config.listen_port)
}

pub(super) fn lower_dial_fields(config: &DialFields) -> Dial {
    Dial {
        detour: config.detour.clone(),
        connect_timeout: Some(config.connect_timeout),
        routing_mark: config.routing_mark,
        domain_resolver: config
            .domain_resolver
            .as_ref()
            .map(|resolver| resolver.server.clone()),
    }
}

pub(super) fn lower_tls_fields(config: &TlsFields) -> OutboundTls {
    OutboundTls {
        enabled: config.enabled,
        alpn: config.alpn.clone(),
        server_name: config.server_name.clone(),
        disable_sni: config.disable_sni,
        insecure: config.insecure,
        certificate_path: config.certificate_path.clone(),
        ca_path: config.ca_path.clone(),
        handshake_timeout: config.handshake_timeout,
    }
}

pub(super) fn parse_host(value: &str) -> Host {
    match IpAddr::from_str(value) {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use veex_config::TlsFields;

    use super::lower_tls_fields;

    #[test]
    fn lower_tls_fields_keeps_alpn_list() {
        let tls = lower_tls_fields(&TlsFields {
            enabled: true,
            alpn: Some(vec!["h2".into(), "http/1.1".into()]),
            server_name: Some("example.com".into()),
            disable_sni: false,
            insecure: false,
            certificate_path: None,
            ca_path: None,
            handshake_timeout: veex_config::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
        });

        assert_eq!(
            tls.alpn.as_deref(),
            Some(&["h2".to_string(), "http/1.1".to_string()][..])
        );
    }
}
