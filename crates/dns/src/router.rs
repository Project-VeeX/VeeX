use std::sync::Arc;

use veex_core::{ProxyError, dns::ResolveContext};

use crate::{
    traits::DnsUpstream,
    types::{DnsRouteReason, DnsRule, DnsSelection},
};

#[derive(Clone)]
pub(crate) struct DnsServerRoute<'a> {
    pub tag: &'a str,
    pub detour: Option<&'a str>,
    pub upstream: Arc<dyn DnsUpstream>,
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
                    servers,
                );
            }
        }

        self.selection_for_tag(
            self.final_server_tag.clone(),
            DnsRouteReason::Final,
            servers,
        )
    }

    pub(crate) fn select_resolution_upstream<'a>(
        &self,
        context: &ResolveContext,
        servers: &[DnsServerRoute<'a>],
    ) -> veex_core::Result<Option<DnsSelection>> {
        if let Some(server_tag) = &context.explicit_server_tag {
            return self
                .selection_for_tag(
                    server_tag.clone(),
                    DnsRouteReason::ExplicitResolver,
                    servers,
                )
                .map(Some);
        }

        if let Some(selection) = self
            .find_server(servers, self.final_server_tag.as_str())
            .filter(|server| is_safe_for_context(server, context))
            .map(|server| {
                self.selection_for_tag(server.tag.to_string(), DnsRouteReason::Final, servers)
            })
        {
            return selection.map(Some);
        }

        let selection = servers
            .iter()
            .find(|server| server.detour == Some("direct") && is_safe_for_context(server, context))
            .or_else(|| {
                servers
                    .iter()
                    .find(|server| is_safe_for_context(server, context))
            })
            .map(|server| {
                self.selection_for_tag(server.tag.to_string(), DnsRouteReason::SafeDefault, servers)
            });

        selection.transpose()
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
        servers: &[DnsServerRoute<'a>],
    ) -> veex_core::Result<DnsSelection> {
        let upstream = self
            .find_server(servers, &server_tag)
            .map(|server| Arc::clone(&server.upstream))
            .ok_or_else(|| ProxyError::config(format!("missing dns server tag: {server_tag}")))?;
        Ok(DnsSelection {
            server_tag,
            reason,
            upstream,
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
    use std::sync::Arc;

    use async_trait::async_trait;
    use veex_core::dns::{DnsRequest, DnsResponse, ResolveContext};

    use crate::{traits::DnsUpstream, types::DnsRouteReason};

    use super::{DnsRouter, DnsRule, DnsServerRoute};

    struct TestUpstream;

    #[async_trait]
    impl DnsUpstream for TestUpstream {
        async fn exchange(&self, _req: DnsRequest) -> veex_core::Result<DnsResponse> {
            Err(veex_core::ProxyError::protocol("unused"))
        }
    }

    #[test]
    fn dns_router_prefers_matching_rule_before_final() {
        let router = DnsRouter::new(
            "remote",
            vec![DnsRule {
                domain: vec!["trojan.example.com".into()],
                server_tag: "direct".into(),
            }],
        );

        let servers = [
            DnsServerRoute {
                tag: "direct",
                detour: Some("direct"),
                upstream: Arc::new(TestUpstream),
            },
            DnsServerRoute {
                tag: "remote",
                detour: Some("proxy"),
                upstream: Arc::new(TestUpstream),
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
        assert_eq!(fallback.server_tag, "remote");
        assert_eq!(fallback.reason, DnsRouteReason::Final);
    }

    #[test]
    fn resolution_selection_bypasses_rules_for_explicit_resolver() {
        let router = DnsRouter::new("remote", Vec::new());
        let servers = [DnsServerRoute {
            tag: "bootstrap",
            detour: Some("direct"),
            upstream: Arc::new(TestUpstream),
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
    }

    #[test]
    fn resolution_selection_falls_back_to_safe_direct_server() {
        let router = DnsRouter::new("remote", Vec::new());
        let servers = [
            DnsServerRoute {
                tag: "remote",
                detour: Some("proxy"),
                upstream: Arc::new(TestUpstream),
            },
            DnsServerRoute {
                tag: "bootstrap",
                detour: Some("direct"),
                upstream: Arc::new(TestUpstream),
            },
        ];

        let selection = router
            .select_resolution_upstream(&ResolveContext::outbound_dial("proxy", None), &servers)
            .expect("router should resolve safe default upstream")
            .expect("safe default should select a server");

        assert_eq!(selection.server_tag, "bootstrap");
        assert_eq!(selection.reason, DnsRouteReason::SafeDefault);
    }
}
