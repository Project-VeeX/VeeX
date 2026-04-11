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
    load_from_path, load_from_path_unvalidated, load_from_path_with_diagnostics, parse_config,
    parse_config_unvalidated, parse_config_with_diagnostics, ParseDiagnostics, ParseIgnored,
    ParseWarning,
};
pub use preflight::JsonValue;
pub use schema::{
    DirectInboundConfig, DirectOutboundConfig, InboundConfig, InboundType, LogConfig,
    OutboundConfig, OutboundType, ProxyConfig, RedirectInboundConfig, RouteActionConfig,
    RouteConfig, RouteFinalActionConfig, RouteRuleConfig, RouteTargetConfig,
    RouteUpgradeActionConfig, SniffActionConfig, SocksInboundConfig, TProxyInboundConfig,
    TrojanOutboundConfig, TrojanTlsConfig,
};
pub use validate::validate_config;
