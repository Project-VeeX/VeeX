mod dns;
mod inbound;
mod outbound;
mod route;
mod shared;

use crate::{error::ConfigError, schema::ProxyConfig};

use self::{
    dns::validate_dns,
    inbound::validate_inbounds,
    outbound::validate_outbounds,
    route::validate_route,
    shared::{validate_domain_resolvers, validate_log},
};

pub fn validate_config(config: &ProxyConfig) -> Result<(), ConfigError> {
    validate_log(config)?;
    let inbound_tags = validate_inbounds(config)?;
    let outbound_tags = validate_outbounds(config)?;
    let dns_server_tags = validate_dns(config.dns.as_ref(), &outbound_tags)?;
    validate_domain_resolvers(config, dns_server_tags.as_ref())?;
    validate_route(config, &outbound_tags)?;

    debug_assert!(
        !inbound_tags.is_empty(),
        "validated configs always contain at least one inbound"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        DEFAULT_CONNECT_TIMEOUT, DEFAULT_SNIFF_TIMEOUT, DialFields, DirectInboundConfig,
        DirectOutboundConfig, DnsConfig, DnsServerConfig, DnsServerTypeConfig,
        DomainResolverConfig, InboundConfig, ListenFields, LogConfig, OutboundConfig, ProxyConfig,
        RouteActionConfig, RouteConfig, RouteFinalActionConfig, RouteRuleConfig, RouteTargetConfig,
        RouteUpgradeActionConfig, SniffActionConfig, SocksInboundConfig, TProxyInboundConfig,
        TlsFields,
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
                listen: ListenFields::new("127.0.0.1", 1080),
            })],
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                dial: DialFields::new(DEFAULT_CONNECT_TIMEOUT),
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
            listen: ListenFields::new("0.0.0.0", 1041),
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
            listen: ListenFields::new("0.0.0.0", 9000),
            network: Some("quic".into()),
            override_address: None,
            override_port: None,
        })];

        let err = validate_config(&config).expect_err("unsupported direct network should fail");
        assert!(err.to_string().contains("$.inbounds[0].network"));
        assert!(
            err.to_string()
                .contains("only supports network='tcp' or network='udp'")
        );
    }

    #[test]
    fn accepts_udp_direct_inbound_network() {
        let mut config = valid_config();
        config.inbounds = vec![InboundConfig::Direct(DirectInboundConfig {
            tag: "direct-in".into(),
            listen: ListenFields::new("127.0.0.1", 9000),
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
            listen: ListenFields::new("127.0.0.1", 9000),
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
            disable_cache: false,
            cache_capacity: None,
            servers: vec![DnsServerConfig {
                tag: "local".into(),
                kind: DnsServerTypeConfig::Udp,
                server: "223.5.5.5".into(),
                server_port: 53,
                path: None,
                headers: Default::default(),
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
                    handshake_timeout: crate::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
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
            disable_cache: false,
            cache_capacity: None,
            servers: vec![DnsServerConfig {
                tag: "local".into(),
                kind: DnsServerTypeConfig::Tcp,
                server: "223.5.5.5".into(),
                server_port: 53,
                path: None,
                headers: Default::default(),
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
                    handshake_timeout: crate::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }],
            rules: vec![],
        });

        validate_config(&config).expect("tcp dns section should validate");
    }

    #[test]
    fn accepts_dns_section_with_tls_server_detour() {
        let mut config = valid_config();
        config.dns = Some(DnsConfig {
            final_server: "dot".into(),
            disable_cache: false,
            cache_capacity: None,
            servers: vec![DnsServerConfig {
                tag: "dot".into(),
                kind: DnsServerTypeConfig::Tls,
                server: "dns.example.com".into(),
                server_port: 853,
                path: None,
                headers: Default::default(),
                dial: DialFields {
                    detour: Some("direct".into()),
                    ..DialFields::new(DEFAULT_CONNECT_TIMEOUT)
                },
                tls: TlsFields {
                    enabled: true,
                    alpn: None,
                    server_name: Some("dns.example.com".into()),
                    disable_sni: false,
                    insecure: false,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: crate::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }],
            rules: vec![],
        });

        validate_config(&config).expect("tls dns section should validate");
    }

    #[test]
    fn accepts_dns_section_with_https_server_detour() {
        let mut config = valid_config();
        config.dns = Some(DnsConfig {
            final_server: "doh".into(),
            disable_cache: false,
            cache_capacity: None,
            servers: vec![DnsServerConfig {
                tag: "doh".into(),
                kind: DnsServerTypeConfig::Https,
                server: "dns.example.com".into(),
                server_port: 443,
                path: Some("/dns-query".into()),
                headers: std::collections::BTreeMap::from([(
                    String::from("X-Test"),
                    String::from("true"),
                )]),
                dial: DialFields {
                    detour: Some("direct".into()),
                    ..DialFields::new(DEFAULT_CONNECT_TIMEOUT)
                },
                tls: TlsFields {
                    enabled: true,
                    alpn: None,
                    server_name: Some("dns.example.com".into()),
                    disable_sni: false,
                    insecure: false,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: crate::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }],
            rules: vec![],
        });

        validate_config(&config).expect("https dns section should validate");
    }

    #[test]
    fn accepts_dns_section_with_local_server_without_detour() {
        let mut config = valid_config();
        config.dns = Some(DnsConfig {
            final_server: "local".into(),
            disable_cache: false,
            cache_capacity: None,
            servers: vec![DnsServerConfig {
                tag: "local".into(),
                kind: DnsServerTypeConfig::Local,
                server: String::new(),
                server_port: 0,
                path: Some(String::new()),
                headers: std::collections::BTreeMap::from([(
                    String::from(""),
                    String::from("value"),
                )]),
                dial: DialFields {
                    domain_resolver: Some(DomainResolverConfig {
                        server: "missing".into(),
                    }),
                    ..DialFields::new(DEFAULT_CONNECT_TIMEOUT)
                },
                tls: TlsFields {
                    enabled: false,
                    alpn: None,
                    server_name: None,
                    disable_sni: false,
                    insecure: false,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: crate::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }],
            rules: vec![],
        });

        validate_config(&config).expect("local dns section should validate");
    }

    #[test]
    fn accepts_dns_section_with_remote_server_without_detour() {
        let mut config = valid_config();
        config.dns = Some(DnsConfig {
            final_server: "remote".into(),
            disable_cache: false,
            cache_capacity: None,
            servers: vec![DnsServerConfig {
                tag: "remote".into(),
                kind: DnsServerTypeConfig::Udp,
                server: "223.5.5.5".into(),
                server_port: 53,
                path: None,
                headers: Default::default(),
                dial: DialFields::new(DEFAULT_CONNECT_TIMEOUT),
                tls: TlsFields {
                    enabled: false,
                    alpn: None,
                    server_name: None,
                    disable_sni: false,
                    insecure: false,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: crate::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }],
            rules: vec![],
        });

        validate_config(&config).expect("remote dns section without detour should validate");
    }

    #[test]
    fn accepts_config_without_explicit_direct_outbound_tag() {
        let mut config = valid_config();
        config.outbounds = vec![OutboundConfig::Trojan(crate::TrojanOutboundConfig {
            tag: "proxy".into(),
            server: "trojan.example.com".into(),
            server_port: 443,
            password: "secret".into(),
            dial: DialFields::new(DEFAULT_CONNECT_TIMEOUT),
            tls: TlsFields {
                enabled: true,
                alpn: None,
                server_name: Some("trojan.example.com".into()),
                disable_sni: false,
                insecure: false,
                certificate_path: None,
                ca_path: None,
                handshake_timeout: crate::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
            },
        })];
        config.route.final_outbound = "proxy".into();

        validate_config(&config).expect("config should validate without explicit direct outbound");
    }

    #[test]
    fn rejects_dns_final_empty_string_when_explicitly_set() {
        let mut config = valid_config();
        config.dns = Some(DnsConfig {
            final_server: String::new(),
            disable_cache: false,
            cache_capacity: None,
            servers: vec![DnsServerConfig {
                tag: "local".into(),
                kind: DnsServerTypeConfig::Local,
                server: String::new(),
                server_port: 53,
                path: None,
                headers: Default::default(),
                dial: DialFields::new(DEFAULT_CONNECT_TIMEOUT),
                tls: TlsFields {
                    enabled: true,
                    alpn: None,
                    server_name: None,
                    disable_sni: false,
                    insecure: false,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: crate::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }],
            rules: vec![],
        });

        let err = validate_config(&config).expect_err("explicit empty dns.final should fail");
        assert!(err.to_string().contains("$.dns.final"));
        assert!(
            err.to_string()
                .contains("dns.final points to missing dns server")
        );
    }

    #[test]
    fn rejects_outbound_domain_resolver_without_dns_section() {
        let mut config = valid_config();
        config.outbounds = vec![
            OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
                dial: DialFields::new(DEFAULT_CONNECT_TIMEOUT),
            }),
            OutboundConfig::Trojan(crate::TrojanOutboundConfig {
                tag: "proxy".into(),
                server: "trojan.example.com".into(),
                server_port: 443,
                password: "secret".into(),
                dial: DialFields {
                    domain_resolver: Some(DomainResolverConfig {
                        server: "bootstrap".into(),
                    }),
                    ..DialFields::new(DEFAULT_CONNECT_TIMEOUT)
                },
                tls: TlsFields {
                    enabled: true,
                    alpn: None,
                    server_name: Some("trojan.example.com".into()),
                    disable_sni: false,
                    insecure: false,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: crate::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }),
        ];
        config.route.final_outbound = "proxy".into();

        let err = validate_config(&config).expect_err("domain_resolver without dns should fail");
        assert!(
            err.to_string()
                .contains("$.outbounds[1].domain_resolver.server")
        );
        assert!(err.to_string().contains("requires a dns section"));
    }

    #[test]
    fn rejects_dns_server_domain_resolver_self_reference() {
        let mut config = valid_config();
        config.dns = Some(DnsConfig {
            final_server: "dot".into(),
            disable_cache: false,
            cache_capacity: None,
            servers: vec![DnsServerConfig {
                tag: "dot".into(),
                kind: DnsServerTypeConfig::Tls,
                server: "dns.example.com".into(),
                server_port: 853,
                path: None,
                headers: Default::default(),
                dial: DialFields {
                    detour: Some("direct".into()),
                    domain_resolver: Some(DomainResolverConfig {
                        server: "dot".into(),
                    }),
                    ..DialFields::new(DEFAULT_CONNECT_TIMEOUT)
                },
                tls: TlsFields {
                    enabled: true,
                    alpn: None,
                    server_name: Some("dns.example.com".into()),
                    disable_sni: false,
                    insecure: false,
                    certificate_path: None,
                    ca_path: None,
                    handshake_timeout: crate::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
                },
            }],
            rules: vec![],
        });

        let err =
            validate_config(&config).expect_err("dns server self resolver reference should fail");
        assert!(
            err.to_string()
                .contains("$.dns.servers[0].domain_resolver.server")
        );
        assert!(err.to_string().contains("must not point to itself"));
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
