//! Minimal sing-box compatible configuration subset used by VeeX.

mod defaults;
mod error;
mod input;
mod parse;
mod preflight;
mod schema;
mod validate;

pub use defaults::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_DIRECT_OUTBOUND_TAG, DEFAULT_SNIFF_TIMEOUT,
    DEFAULT_TLS_HANDSHAKE_TIMEOUT,
};
pub use error::{ConfigError, ExitCodeHint};
pub use parse::{
    ParseDiagnostics, ParseIgnored, ParseWarning, load_from_path, load_from_path_unvalidated,
    load_from_path_with_diagnostics, parse_config, parse_config_unvalidated,
    parse_config_with_diagnostics,
};
pub use schema::{
    DialFields, DirectInboundConfig, DirectOutboundConfig, DnsConfig, DnsRuleConfig,
    DnsServerConfig, DnsServerTypeConfig, DomainResolverConfig, InboundConfig, InboundType,
    ListenFields, LogConfig, OutboundConfig, OutboundType, ProxyConfig, RedirectInboundConfig,
    RouteActionConfig, RouteConfig, RouteFinalActionConfig, RouteRuleConfig, RouteTargetConfig,
    RouteUpgradeActionConfig, SniffActionConfig, SocksInboundConfig, TProxyInboundConfig,
    TlsFields, TrojanOutboundConfig,
};
pub use validate::validate_config;
