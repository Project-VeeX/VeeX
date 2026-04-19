use veex_core::{ProxyError, dns::ResolveContext};

use crate::types::{DnsRouteReason, DnsRule, DnsSelection};

#[derive(Clone)]
pub(crate) struct DnsServerRoute<'a> {
    pub tag: &'a str,
    pub detour: Option<&'a str>,
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

    pub(crate) fn select_client_upstream<'a>(
        &self,
        domain: &str,
        servers: &[DnsServerRoute<'a>],
    ) -> veex_core::Result<DnsSelection> {
        let domain = normalize_domain(domain);

        for rule in &self.rules {
            if rule.domain.iter().any(|candidate| candidate == &domain) {
                return self.selection_for_tag(
                    rule.server_tag.clone(),
                    DnsRouteReason::Rule,
                    rule.disable_cache,
                    servers,
                );
            }
        }

        self.selection_for_tag(
            self.final_server_tag.clone(),
            DnsRouteReason::Final,
            false,
            servers,
        )
    }

    pub(crate) fn select_resolution_upstream<'a>(
        &self,
        context: &ResolveContext,
        servers: &[DnsServerRoute<'a>],
    ) -> veex_core::Result<Option<DnsSelection>> {
        if let Some(server_tag) = &context.explicit_server_tag {
            self.find_server(servers, server_tag).ok_or_else(|| {
                ProxyError::config(format!(
                    "explicit domain_resolver points to missing dns server tag: {server_tag}"
                ))
            })?;
            return Ok(Some(DnsSelection {
                server_tag: server_tag.clone(),
                candidate_server_tags: vec![server_tag.clone()],
                reason: DnsRouteReason::ExplicitResolver,
                disable_cache: context.disable_cache,
            }));
        }

        let mut safe_direct = Vec::new();
        let mut safe_other = Vec::new();
        for server in servers {
            if !is_safe_for_context(server, context) {
                continue;
            }
            if server.tag == self.final_server_tag {
                continue;
            }
            if server.detour == Some("direct") {
                safe_direct.push(server.tag.to_string());
            } else {
                safe_other.push(server.tag.to_string());
            }
        }

        if self
            .find_server(servers, self.final_server_tag.as_str())
            .is_some_and(|server| is_safe_for_context(server, context))
        {
            let mut candidates = vec![self.final_server_tag.clone()];
            candidates.extend(safe_direct);
            candidates.extend(safe_other);
            return Ok(Some(DnsSelection {
                server_tag: self.final_server_tag.clone(),
                candidate_server_tags: candidates,
                reason: DnsRouteReason::Final,
                disable_cache: context.disable_cache,
            }));
        }

        let mut candidates = safe_direct;
        candidates.extend(safe_other);
        let Some(server_tag) = candidates.first().cloned() else {
            return Ok(None);
        };

        Ok(Some(DnsSelection {
            server_tag,
            candidate_server_tags: candidates,
            reason: DnsRouteReason::SafeDefault,
            disable_cache: context.disable_cache,
        }))
    }

    fn find_server<'a>(
        &self,
        servers: &'a [DnsServerRoute<'a>],
        tag: &str,
    ) -> Option<&'a DnsServerRoute<'a>> {
        servers.iter().find(|server| server.tag == tag)
    }

    fn selection_for_tag<'a>(
        &self,
        server_tag: String,
        reason: DnsRouteReason,
        disable_cache: bool,
        servers: &[DnsServerRoute<'a>],
    ) -> veex_core::Result<DnsSelection> {
        self.find_server(servers, &server_tag)
            .ok_or_else(|| ProxyError::config(format!("missing dns server tag: {server_tag}")))?;
        Ok(DnsSelection {
            candidate_server_tags: vec![server_tag.clone()],
            server_tag,
            reason,
            disable_cache,
        })
    }
}

fn is_safe_for_context(server: &DnsServerRoute<'_>, context: &ResolveContext) -> bool {
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
        .is_some_and(|tag| server.detour.is_some_and(|detour| tag == detour))
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
    use veex_core::dns::{ResolveContext, ResolvePurpose};

    use crate::types::DnsRouteReason;

    use super::{DnsRouter, DnsRule, DnsServerRoute};

    #[test]
    fn dns_router_prefers_matching_rule_before_final() {
        let router = DnsRouter::new(
            "remote",
            vec![DnsRule {
                domain: vec!["trojan.example.com".into()],
                server_tag: "direct".into(),
                disable_cache: true,
            }],
        );

        let servers = [
            DnsServerRoute {
                tag: "direct",
                detour: Some("direct"),
            },
            DnsServerRoute {
                tag: "remote",
                detour: Some("proxy"),
            },
        ];

        let matched = router
            .select_client_upstream("Trojan.Example.Com.", &servers)
            .expect("matching rule should select an upstream");
        let fallback = router
            .select_client_upstream("www.example.com", &servers)
            .expect("final server should select an upstream");

        assert_eq!(matched.server_tag, "direct");
        assert_eq!(matched.reason, DnsRouteReason::Rule);
        assert!(matched.disable_cache);
        assert_eq!(fallback.server_tag, "remote");
        assert_eq!(fallback.reason, DnsRouteReason::Final);
        assert_eq!(fallback.candidate_server_tags, vec!["remote".to_string()]);
    }

    #[test]
    fn resolution_selection_bypasses_rules_for_explicit_resolver() {
        let router = DnsRouter::new("remote", Vec::new());
        let servers = [DnsServerRoute {
            tag: "bootstrap",
            detour: Some("direct"),
        }];

        let selection = router
            .select_resolution_upstream(
                &ResolveContext::outbound_dial("proxy", Some("bootstrap".into())),
                &servers,
            )
            .expect("router should resolve explicit upstream")
            .expect("explicit resolver should select a server");

        assert_eq!(selection.server_tag, "bootstrap");
        assert_eq!(selection.reason, DnsRouteReason::ExplicitResolver);
        assert_eq!(
            selection.candidate_server_tags,
            vec!["bootstrap".to_string()]
        );
    }

    #[test]
    fn resolution_selection_falls_back_to_safe_direct_server() {
        let router = DnsRouter::new("remote", Vec::new());
        let servers = [
            DnsServerRoute {
                tag: "remote",
                detour: Some("proxy"),
            },
            DnsServerRoute {
                tag: "bootstrap",
                detour: Some("direct"),
            },
        ];

        let selection = router
            .select_resolution_upstream(&ResolveContext::outbound_dial("proxy", None), &servers)
            .expect("router should resolve safe default upstream")
            .expect("safe default should select a server");

        assert_eq!(selection.server_tag, "bootstrap");
        assert_eq!(selection.reason, DnsRouteReason::SafeDefault);
        assert_eq!(
            selection.candidate_server_tags,
            vec!["bootstrap".to_string()]
        );
    }

    #[test]
    fn resolution_selection_prefers_safe_final_server_before_safe_default() {
        let router = DnsRouter::new("remote", Vec::new());
        let servers = [
            DnsServerRoute {
                tag: "remote",
                detour: Some("dns-egress"),
            },
            DnsServerRoute {
                tag: "bootstrap",
                detour: Some("direct"),
            },
        ];

        let selection = router
            .select_resolution_upstream(&ResolveContext::outbound_dial("proxy", None), &servers)
            .expect("router should resolve safe final upstream")
            .expect("safe final should select a server");

        assert_eq!(selection.server_tag, "remote");
        assert_eq!(selection.reason, DnsRouteReason::Final);
        assert_eq!(
            selection.candidate_server_tags,
            vec!["remote".to_string(), "bootstrap".to_string()]
        );
    }

    #[test]
    fn resolution_selection_skips_final_server_when_caller_dns_server_matches() {
        let router = DnsRouter::new("remote", Vec::new());
        let servers = [
            DnsServerRoute {
                tag: "remote",
                detour: Some("proxy"),
            },
            DnsServerRoute {
                tag: "bootstrap",
                detour: Some("direct"),
            },
        ];
        let context = ResolveContext {
            purpose: ResolvePurpose::DnsUpstreamDial,
            caller_outbound_tag: Some("proxy".into()),
            caller_dns_server_tag: Some("remote".into()),
            explicit_server_tag: None,
            disable_cache: false,
            recursion_depth: 1,
        };

        let selection = router
            .select_resolution_upstream(&context, &servers)
            .expect("router should resolve safe fallback upstream")
            .expect("safe fallback should select a server");

        assert_eq!(selection.server_tag, "bootstrap");
        assert_eq!(selection.reason, DnsRouteReason::SafeDefault);
    }

    #[test]
    fn resolution_selection_returns_none_when_no_safe_server_exists() {
        let router = DnsRouter::new("remote", Vec::new());
        let servers = [DnsServerRoute {
            tag: "remote",
            detour: Some("proxy"),
        }];

        let selection = router
            .select_resolution_upstream(&ResolveContext::outbound_dial("proxy", None), &servers)
            .expect("unsafe-only resolver set should not error");

        assert!(selection.is_none());
    }

    #[test]
    fn explicit_resolver_missing_server_returns_config_error() {
        let router = DnsRouter::new("remote", Vec::new());

        let err = match router.select_resolution_upstream(
            &ResolveContext::outbound_dial("proxy", Some("missing".into())),
            &[],
        ) {
            Ok(_) => panic!("missing explicit resolver should fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("explicit domain_resolver points to missing dns server tag: missing")
        );
    }
}
