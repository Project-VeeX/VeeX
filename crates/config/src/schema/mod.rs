mod dns;
mod inbound;
mod outbound;
mod route;
mod shared;

pub use dns::{DnsConfig, DnsRuleConfig, DnsServerConfig, DnsServerTypeConfig};
pub use inbound::{
    DirectInboundConfig, InboundConfig, InboundType, RedirectInboundConfig, SocksInboundConfig,
    TProxyInboundConfig,
};
pub use outbound::{DirectOutboundConfig, OutboundConfig, OutboundType, TrojanOutboundConfig};
pub use route::{
    RouteActionConfig, RouteConfig, RouteFinalActionConfig, RouteRuleConfig, RouteTargetConfig,
    RouteUpgradeActionConfig, SniffActionConfig,
};
pub use shared::{
    DialFields, DomainResolverConfig, ListenFields, LogConfig, ProxyConfig, TlsFields,
};
