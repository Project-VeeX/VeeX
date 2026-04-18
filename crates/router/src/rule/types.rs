use std::time::Duration;

use ipnet::IpNet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteReason {
    Rule,
    Final,
}

impl RouteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Final => "final",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDecision {
    pub final_action: RouteFinalAction,
    pub reason: RouteReason,
}

impl RouteDecision {
    pub fn route(outbound_tag: impl Into<String>, reason: RouteReason) -> Self {
        Self {
            final_action: RouteFinalAction::Route(RouteTarget::new(outbound_tag)),
            reason,
        }
    }

    pub fn route_target(&self) -> Option<&RouteTarget> {
        match &self.final_action {
            RouteFinalAction::Route(target) => Some(target),
            RouteFinalAction::HijackDns => None,
        }
    }

    pub fn outbound_tag(&self) -> Option<&str> {
        self.route_target()
            .map(|target| target.outbound_tag.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteAction {
    Upgrade(RouteUpgradeAction),
    Final(RouteFinalAction),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteUpgradeAction {
    Sniff(SniffAction),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SniffAction {
    pub timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteFinalAction {
    Route(RouteTarget),
    HijackDns,
}

impl RouteFinalAction {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Route(_) => "route",
            Self::HijackDns => "hijack-dns",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteTarget {
    pub outbound_tag: String,
}

impl RouteTarget {
    pub fn new(outbound_tag: impl Into<String>) -> Self {
        Self {
            outbound_tag: outbound_tag.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRule {
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub ip_cidr: Vec<IpNet>,
    pub ip_is_private: bool,
    pub ip_is_loopback: bool,
    pub ip_is_link_local: bool,
    pub port: Vec<u16>,
    pub inbound: Vec<String>,
    pub action: RouteAction,
}

impl RouteRule {
    pub fn new(outbound_tag: impl Into<String>) -> Self {
        Self {
            domain: Vec::new(),
            domain_suffix: Vec::new(),
            ip_cidr: Vec::new(),
            ip_is_private: false,
            ip_is_loopback: false,
            ip_is_link_local: false,
            port: Vec::new(),
            inbound: Vec::new(),
            action: RouteAction::Final(RouteFinalAction::Route(RouteTarget::new(outbound_tag))),
        }
    }

    pub fn sniff(timeout: Duration) -> Self {
        Self {
            domain: Vec::new(),
            domain_suffix: Vec::new(),
            ip_cidr: Vec::new(),
            ip_is_private: false,
            ip_is_loopback: false,
            ip_is_link_local: false,
            port: Vec::new(),
            inbound: Vec::new(),
            action: RouteAction::Upgrade(RouteUpgradeAction::Sniff(SniffAction { timeout })),
        }
    }
}

impl RouteAction {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Upgrade(RouteUpgradeAction::Sniff(_)) => "sniff",
            Self::Final(action) => action.kind(),
        }
    }
}
