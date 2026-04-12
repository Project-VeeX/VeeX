use veex_core::ResolveContext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRouteReason {
    Rule,
    Final,
    ExplicitResolver,
    SafeDefault,
}

impl DnsRouteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Final => "final",
            Self::ExplicitResolver => "explicit_resolver",
            Self::SafeDefault => "safe_default",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRule {
    pub domain: Vec<String>,
    pub server_tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsSelection {
    pub server_tag: String,
    pub reason: DnsRouteReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsServerRouteMeta<'a> {
    pub tag: &'a str,
    pub detour: &'a str,
}

#[derive(Clone, Debug)]
pub struct DnsRouter {
    final_server_tag: String,
    rules: Vec<DnsRule>,
}

impl DnsRouter {
    pub fn new(final_server_tag: impl Into<String>, rules: Vec<DnsRule>) -> Self {
        Self {
            final_server_tag: final_server_tag.into(),
            rules,
        }
    }

    pub fn select_client_query(&self, domain: &str) -> DnsSelection {
        let domain = normalize_domain(domain);

        for rule in &self.rules {
            if rule.domain.iter().any(|candidate| candidate == &domain) {
                return DnsSelection {
                    server_tag: rule.server_tag.clone(),
                    reason: DnsRouteReason::Rule,
                };
            }
        }

        DnsSelection {
            server_tag: self.final_server_tag.clone(),
            reason: DnsRouteReason::Final,
        }
    }

    pub fn select_resolution_server<'a>(
        &self,
        context: &ResolveContext,
        servers: &[DnsServerRouteMeta<'a>],
    ) -> Option<DnsSelection> {
        if let Some(server_tag) = &context.explicit_server_tag {
            return Some(DnsSelection {
                server_tag: server_tag.clone(),
                reason: DnsRouteReason::ExplicitResolver,
            });
        }

        if let Some(selection) = self
            .find_server(servers, self.final_server_tag.as_str())
            .filter(|server| is_safe_for_context(server, context))
            .map(|server| DnsSelection {
                server_tag: server.tag.to_string(),
                reason: DnsRouteReason::Final,
            })
        {
            return Some(selection);
        }

        servers
            .iter()
            .find(|server| server.detour == "direct" && is_safe_for_context(server, context))
            .or_else(|| {
                servers
                    .iter()
                    .find(|server| is_safe_for_context(server, context))
            })
            .map(|server| DnsSelection {
                server_tag: server.tag.to_string(),
                reason: DnsRouteReason::SafeDefault,
            })
    }

    fn find_server<'a>(
        &self,
        servers: &'a [DnsServerRouteMeta<'a>],
        tag: &str,
    ) -> Option<&'a DnsServerRouteMeta<'a>> {
        servers.iter().find(|server| server.tag == tag)
    }
}

fn is_safe_for_context(server: &DnsServerRouteMeta<'_>, context: &ResolveContext) -> bool {
    if context
        .caller_dns_server_tag
        .as_deref()
        .is_some_and(|tag| tag == server.tag)
    {
        return false;
    }

    if context
        .caller_outbound_tag
        .as_deref()
        .is_some_and(|tag| tag == server.detour)
    {
        return false;
    }

    true
}

fn normalize_domain(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use veex_core::ResolveContext;

    use super::{DnsRouteReason, DnsRouter, DnsRule, DnsServerRouteMeta};

    #[test]
    fn dns_router_prefers_matching_rule_before_final() {
        let router = DnsRouter::new(
            "remote",
            vec![DnsRule {
                domain: vec!["trojan.example.com".into()],
                server_tag: "direct".into(),
            }],
        );

        let matched = router.select_client_query("Trojan.Example.Com.");
        let fallback = router.select_client_query("www.example.com");

        assert_eq!(matched.server_tag, "direct");
        assert_eq!(matched.reason, DnsRouteReason::Rule);
        assert_eq!(fallback.server_tag, "remote");
        assert_eq!(fallback.reason, DnsRouteReason::Final);
    }

    #[test]
    fn resolution_selection_bypasses_rules_for_explicit_resolver() {
        let router = DnsRouter::new("remote", Vec::new());
        let servers = [DnsServerRouteMeta {
            tag: "bootstrap",
            detour: "direct",
        }];

        let selection = router
            .select_resolution_server(
                &ResolveContext::outbound_dial("proxy", Some("bootstrap".into())),
                &servers,
            )
            .expect("explicit resolver should select a server");

        assert_eq!(selection.server_tag, "bootstrap");
        assert_eq!(selection.reason, DnsRouteReason::ExplicitResolver);
    }

    #[test]
    fn resolution_selection_falls_back_to_safe_direct_server() {
        let router = DnsRouter::new("remote", Vec::new());
        let servers = [
            DnsServerRouteMeta {
                tag: "remote",
                detour: "proxy",
            },
            DnsServerRouteMeta {
                tag: "bootstrap",
                detour: "direct",
            },
        ];

        let selection = router
            .select_resolution_server(&ResolveContext::outbound_dial("proxy", None), &servers)
            .expect("safe default should select a server");

        assert_eq!(selection.server_tag, "bootstrap");
        assert_eq!(selection.reason, DnsRouteReason::SafeDefault);
    }
}
