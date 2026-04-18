use veex_core::session::SessionContext;

use crate::rule::{RouteDecision, RouteUpgradeAction};

pub struct RouteResult<I> {
    pub ctx: SessionContext,
    pub decision: RouteDecision,
    pub input: I,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteRuleMissReason {
    DomainAbsent,
    DomainMismatch,
    DomainSuffixMismatch,
    DestinationNotIp,
    IpCidrMismatch,
    IpNotPrivate,
    IpNotLoopback,
    IpNotLinkLocal,
    PortMismatch,
    InboundMismatch,
}

impl RouteRuleMissReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DomainAbsent => "domain_absent",
            Self::DomainMismatch => "domain_mismatch",
            Self::DomainSuffixMismatch => "domain_suffix_mismatch",
            Self::DestinationNotIp => "destination_not_ip",
            Self::IpCidrMismatch => "ip_cidr_mismatch",
            Self::IpNotPrivate => "ip_not_private",
            Self::IpNotLoopback => "ip_not_loopback",
            Self::IpNotLinkLocal => "ip_not_link_local",
            Self::PortMismatch => "port_mismatch",
            Self::InboundMismatch => "inbound_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteRuleTrace<'a> {
    pub rule_index: usize,
    pub action_kind: &'static str,
    pub matcher_summary: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RouteStep<'a> {
    Miss {
        trace: RouteRuleTrace<'a>,
        reason: RouteRuleMissReason,
        next_index: usize,
    },
    Upgrade {
        trace: RouteRuleTrace<'a>,
        action: &'a RouteUpgradeAction,
        next_index: usize,
    },
    Final {
        trace: RouteRuleTrace<'a>,
        decision: RouteDecision,
    },
    DefaultFinal {
        decision: RouteDecision,
    },
}
