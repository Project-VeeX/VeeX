#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRouteReason {
    Rule,
    Final,
}

impl DnsRouteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Final => "final",
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

    pub fn select(&self, domain: &str) -> DnsSelection {
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
}

fn normalize_domain(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{DnsRouteReason, DnsRouter, DnsRule};

    #[test]
    fn dns_router_prefers_matching_rule_before_final() {
        let router = DnsRouter::new(
            "remote",
            vec![DnsRule {
                domain: vec!["trojan.example.com".into()],
                server_tag: "direct".into(),
            }],
        );

        let matched = router.select("Trojan.Example.Com.");
        let fallback = router.select("www.example.com");

        assert_eq!(matched.server_tag, "direct");
        assert_eq!(matched.reason, DnsRouteReason::Rule);
        assert_eq!(fallback.server_tag, "remote");
        assert_eq!(fallback.reason, DnsRouteReason::Final);
    }
}
