pub(crate) mod compile;
pub(crate) mod matchers;
mod types;

pub(crate) use compile::CompiledRouteRule;
pub(crate) use matchers::{
    is_link_local, is_loopback, is_private_or_unique_local, matches_domain_suffix,
    normalize_domain_str,
};
pub use types::{
    RouteAction, RouteDecision, RouteFinalAction, RouteReason, RouteRule, RouteTarget,
    RouteUpgradeAction, SniffAction,
};
