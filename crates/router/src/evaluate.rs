use crate::{
    context::RouteInput,
    result::{RouteRuleMissReason, RouteRuleTrace, RouteStep},
    router::Router,
    rule::{
        is_link_local, is_loopback, is_private_or_unique_local, matches_domain_suffix,
        normalize_domain_str, CompiledRouteRule, RouteAction, RouteDecision, RouteFinalAction,
        RouteReason,
    },
};
use veex_core::types::Host;

pub(crate) fn evaluate_final_decision(router: &Router, input: RouteInput<'_>) -> RouteDecision {
    let mut next_index = 0;
    loop {
        match evaluate_current_state(router, input, next_index) {
            RouteStep::Miss {
                next_index: resume_at,
                ..
            }
            | RouteStep::Upgrade {
                next_index: resume_at,
                ..
            } => {
                next_index = resume_at;
            }
            RouteStep::Final { decision, .. } | RouteStep::DefaultFinal { decision } => {
                return decision;
            }
        }
    }
}

pub(crate) fn evaluate_current_state<'a>(
    router: &'a Router,
    input: RouteInput<'_>,
    start_index: usize,
) -> RouteStep<'a> {
    let Some(rule) = router.rules.get(start_index) else {
        return RouteStep::DefaultFinal {
            decision: default_final_decision(router),
        };
    };

    let normalized_domain = input.domain.map(normalize_domain_str);
    let trace = RouteRuleTrace {
        rule_index: rule.rule_index,
        action_kind: rule.action.kind(),
        matcher_summary: rule.matcher_summary.as_str(),
    };

    match evaluate_rule(rule, input, normalized_domain.as_deref()) {
        Ok(()) => match &rule.action {
            RouteAction::Upgrade(action) => RouteStep::Upgrade {
                trace,
                action,
                next_index: start_index + 1,
            },
            RouteAction::Final(action) => RouteStep::Final {
                trace,
                decision: final_action_decision(action, RouteReason::Rule),
            },
        },
        Err(reason) => RouteStep::Miss {
            trace,
            reason,
            next_index: start_index + 1,
        },
    }
}

fn final_action_decision(action: &RouteFinalAction, reason: RouteReason) -> RouteDecision {
    RouteDecision {
        final_action: action.clone(),
        reason,
    }
}

fn default_final_decision(router: &Router) -> RouteDecision {
    final_action_decision(&router.default_final_action, RouteReason::Final)
}

fn evaluate_rule(
    rule: &CompiledRouteRule,
    input: RouteInput<'_>,
    normalized_domain: Option<&str>,
) -> Result<(), RouteRuleMissReason> {
    matches_exact_domain(rule, normalized_domain)?;
    matches_domain_suffix_rule(rule, normalized_domain)?;
    matches_ip_cidr(rule, input.host())?;
    matches_ip_is_private(rule, input.host())?;
    matches_ip_is_loopback(rule, input.host())?;
    matches_ip_is_link_local(rule, input.host())?;
    matches_port(rule, input.destination.port)?;
    matches_inbound(rule, input.inbound_tag)?;
    Ok(())
}

fn matches_exact_domain(
    rule: &CompiledRouteRule,
    normalized_domain: Option<&str>,
) -> Result<(), RouteRuleMissReason> {
    if rule.domain.is_empty() {
        return Ok(());
    }

    match normalized_domain {
        Some(domain) if rule.domain.iter().any(|candidate| candidate == domain) => Ok(()),
        Some(_) => Err(RouteRuleMissReason::DomainMismatch),
        None => Err(RouteRuleMissReason::DomainAbsent),
    }
}

fn matches_domain_suffix_rule(
    rule: &CompiledRouteRule,
    normalized_domain: Option<&str>,
) -> Result<(), RouteRuleMissReason> {
    if rule.domain_suffix.is_empty() {
        return Ok(());
    }

    match normalized_domain {
        Some(domain)
            if rule
                .domain_suffix
                .iter()
                .any(|suffix| matches_domain_suffix(domain, suffix)) =>
        {
            Ok(())
        }
        Some(_) => Err(RouteRuleMissReason::DomainSuffixMismatch),
        None => Err(RouteRuleMissReason::DomainAbsent),
    }
}

fn matches_ip_cidr(rule: &CompiledRouteRule, host: &Host) -> Result<(), RouteRuleMissReason> {
    if rule.ip_cidr.is_empty() {
        return Ok(());
    }

    match host {
        Host::Ip(ip) if rule.ip_cidr.iter().any(|cidr| cidr.contains(ip)) => Ok(()),
        Host::Ip(_) => Err(RouteRuleMissReason::IpCidrMismatch),
        Host::Domain(_) => Err(RouteRuleMissReason::DestinationNotIp),
    }
}

fn matches_ip_is_private(rule: &CompiledRouteRule, host: &Host) -> Result<(), RouteRuleMissReason> {
    if !rule.ip_is_private {
        return Ok(());
    }

    match host {
        Host::Ip(_) if is_private_or_unique_local(host) => Ok(()),
        Host::Ip(_) => Err(RouteRuleMissReason::IpNotPrivate),
        Host::Domain(_) => Err(RouteRuleMissReason::DestinationNotIp),
    }
}

fn matches_ip_is_loopback(
    rule: &CompiledRouteRule,
    host: &Host,
) -> Result<(), RouteRuleMissReason> {
    if !rule.ip_is_loopback {
        return Ok(());
    }

    match host {
        Host::Ip(_) if is_loopback(host) => Ok(()),
        Host::Ip(_) => Err(RouteRuleMissReason::IpNotLoopback),
        Host::Domain(_) => Err(RouteRuleMissReason::DestinationNotIp),
    }
}

fn matches_ip_is_link_local(
    rule: &CompiledRouteRule,
    host: &Host,
) -> Result<(), RouteRuleMissReason> {
    if !rule.ip_is_link_local {
        return Ok(());
    }

    match host {
        Host::Ip(_) if is_link_local(host) => Ok(()),
        Host::Ip(_) => Err(RouteRuleMissReason::IpNotLinkLocal),
        Host::Domain(_) => Err(RouteRuleMissReason::DestinationNotIp),
    }
}

fn matches_port(rule: &CompiledRouteRule, port: u16) -> Result<(), RouteRuleMissReason> {
    if rule.port.is_empty() || rule.port.contains(&port) {
        Ok(())
    } else {
        Err(RouteRuleMissReason::PortMismatch)
    }
}

fn matches_inbound(
    rule: &CompiledRouteRule,
    inbound_tag: Option<&str>,
) -> Result<(), RouteRuleMissReason> {
    if rule.inbound.is_empty() {
        return Ok(());
    }

    match inbound_tag {
        Some(tag) if rule.inbound.iter().any(|candidate| candidate == tag) => Ok(()),
        _ => Err(RouteRuleMissReason::InboundMismatch),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use veex_core::types::Destination;

    use super::{evaluate_current_state, evaluate_final_decision};
    use crate::{
        context::RouteInput,
        router::Router,
        RouteAction,
        RouteFinalAction,
        RouteReason,
        RouteRule,
        RouteStep,
    };

    #[test]
    fn selects_default_final_for_normal_destinations() {
        let router = Router::with_default_outbound("proxy");
        let destination = Destination::from_domain("example.com", 443);

        let decision = evaluate_final_decision(
            &router,
            RouteInput::new(&destination, Some("test"), Some("example.com")),
        );
        assert_eq!(decision.outbound_tag(), Some("proxy"));
        assert_eq!(decision.reason, RouteReason::Final);
    }

    #[test]
    fn private_destinations_do_not_bypass_without_explicit_rule() {
        let router = Router::with_default_outbound("proxy");
        let destination = Destination::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 53);

        let decision =
            evaluate_final_decision(&router, RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag(), Some("proxy"));
        assert_eq!(decision.reason, RouteReason::Final);
    }

    #[test]
    fn matches_domain_rule_exactly() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            domain: vec!["example.com".into()],
            ..RouteRule::new("proxy")
        });
        let destination = Destination::from_domain("Example.COM", 443);

        let decision = evaluate_final_decision(
            &router,
            RouteInput::new(&destination, Some("test"), Some("Example.COM")),
        );
        assert_eq!(decision.outbound_tag(), Some("proxy"));
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn matches_domain_suffix_for_apex_and_subdomain() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            domain_suffix: vec!["google.com".into()],
            ..RouteRule::new("proxy")
        });

        let apex = Destination::from_domain("google.com", 443);
        let subdomain = Destination::from_domain("www.google.com", 443);

        let apex_decision = evaluate_final_decision(
            &router,
            RouteInput::new(&apex, Some("test"), Some("google.com")),
        );
        let subdomain_decision = evaluate_final_decision(
            &router,
            RouteInput::new(&subdomain, Some("test"), Some("www.google.com")),
        );

        assert_eq!(apex_decision.outbound_tag(), Some("proxy"));
        assert_eq!(apex_decision.reason, RouteReason::Rule);
        assert_eq!(subdomain_decision.outbound_tag(), Some("proxy"));
        assert_eq!(subdomain_decision.reason, RouteReason::Rule);
    }

    #[test]
    fn matches_ip_cidr_rule_for_ip_destinations() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            ip_cidr: vec!["198.51.100.0/24".parse().unwrap()],
            ..RouteRule::new("proxy")
        });
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let decision =
            evaluate_final_decision(&router, RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag(), Some("proxy"));
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn matches_private_loopback_and_link_local_rules_as_regular_rules() {
        let router = Router::with_default_outbound("proxy").with_rules([
            RouteRule {
                ip_is_loopback: true,
                ..RouteRule::new("loopback-direct")
            },
            RouteRule {
                ip_is_private: true,
                ..RouteRule::new("private-direct")
            },
            RouteRule {
                ip_is_link_local: true,
                ..RouteRule::new("link-local-direct")
            },
        ]);

        let loopback = Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let private = Destination::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8080);
        let link_local = Destination::from_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 10, 20)), 8080);

        assert_eq!(
            evaluate_final_decision(&router, RouteInput::new(&loopback, Some("test"), None))
                .outbound_tag(),
            Some("loopback-direct")
        );
        assert_eq!(
            evaluate_final_decision(&router, RouteInput::new(&private, Some("test"), None))
                .outbound_tag(),
            Some("private-direct")
        );
        assert_eq!(
            evaluate_final_decision(&router, RouteInput::new(&link_local, Some("test"), None))
                .outbound_tag(),
            Some("link-local-direct")
        );
    }

    #[test]
    fn matches_port_and_inbound_rules() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                port: vec![53],
                ..RouteRule::new("dns")
            },
            RouteRule {
                inbound: vec!["socks-in".into()],
                ..RouteRule::new("socks-out")
            },
        ]);
        let port_destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 53);
        let inbound_destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 80);

        let port_match = evaluate_final_decision(
            &router,
            RouteInput::new(&port_destination, Some("redirect-in"), None),
        );
        let inbound_match = evaluate_final_decision(
            &router,
            RouteInput::new(&inbound_destination, Some("socks-in"), None),
        );

        assert_eq!(port_match.outbound_tag(), Some("dns"));
        assert_eq!(port_match.reason, RouteReason::Rule);
        assert_eq!(inbound_match.outbound_tag(), Some("socks-out"));
        assert_eq!(inbound_match.reason, RouteReason::Rule);
    }

    #[test]
    fn requires_all_matchers_in_a_rule_to_match() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            domain_suffix: vec!["google.com".into()],
            port: vec![443],
            ..RouteRule::new("proxy")
        });
        let matching = Destination::from_domain("www.google.com", 443);
        let mismatched_port = Destination::from_domain("www.google.com", 80);

        let matching_decision = evaluate_final_decision(
            &router,
            RouteInput::new(&matching, Some("test"), Some("www.google.com")),
        );
        let mismatched_decision = evaluate_final_decision(
            &router,
            RouteInput::new(&mismatched_port, Some("test"), Some("www.google.com")),
        );

        assert_eq!(matching_decision.outbound_tag(), Some("proxy"));
        assert_eq!(matching_decision.reason, RouteReason::Rule);
        assert_eq!(mismatched_decision.outbound_tag(), Some("final"));
        assert_eq!(mismatched_decision.reason, RouteReason::Final);
    }

    #[test]
    fn final_rule_stops_pipeline_immediately() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                port: vec![443],
                ..RouteRule::new("first")
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("second")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let decision =
            evaluate_final_decision(&router, RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag(), Some("first"));
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn can_return_hijack_dns_as_a_final_action() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            inbound: vec!["dns-in".into()],
            action: RouteAction::Final(RouteFinalAction::HijackDns),
            ..RouteRule::new("unused")
        });
        let destination = Destination::from_ip("127.0.0.1".parse().unwrap(), 53);

        let decision =
            evaluate_final_decision(&router, RouteInput::new(&destination, Some("dns-in"), None));

        assert!(matches!(decision.final_action, RouteFinalAction::HijackDns));
        assert_eq!(decision.reason, RouteReason::Rule);
        assert_eq!(decision.outbound_tag(), None);
    }

    #[test]
    fn domain_rules_do_not_match_when_domain_is_absent() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                domain: vec!["example.com".into()],
                ..RouteRule::new("proxy")
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("fallback-rule")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let decision =
            evaluate_final_decision(&router, RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag(), Some("fallback-rule"));
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn can_be_rerun_after_domain_becomes_available() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            domain_suffix: vec!["google.com".into()],
            ..RouteRule::new("proxy")
        });
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let first =
            evaluate_final_decision(&router, RouteInput::new(&destination, Some("test"), None));
        let second = evaluate_final_decision(
            &router,
            RouteInput::new(&destination, Some("test"), Some("www.google.com")),
        );

        assert_eq!(first.outbound_tag(), Some("final"));
        assert_eq!(first.reason, RouteReason::Final);
        assert_eq!(second.outbound_tag(), Some("proxy"));
        assert_eq!(second.reason, RouteReason::Rule);
    }

    #[test]
    fn step_api_exposes_upgrade_without_executing_it() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                inbound: vec!["tproxy-in".into()],
                ..RouteRule::sniff(std::time::Duration::from_millis(300))
            },
            RouteRule {
                domain_suffix: vec!["google.com".into()],
                ..RouteRule::new("proxy")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let step = evaluate_current_state(
            &router,
            RouteInput::new(&destination, Some("tproxy-in"), None),
            0,
        );

        match step {
            RouteStep::Upgrade {
                trace, next_index, ..
            } => {
                assert_eq!(trace.rule_index, 0);
                assert_eq!(trace.action_kind, "sniff");
                assert_eq!(trace.matcher_summary, "inbound");
                assert_eq!(next_index, 1);
            }
            other => panic!("expected upgrade step, got {other:?}"),
        }
    }
}
