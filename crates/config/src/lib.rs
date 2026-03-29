//! Minimal sing-box compatible configuration subset used by VeeX.

mod defaults;
mod json;
mod parse;
mod schema;
mod validate;

pub use defaults::DEFAULT_DIRECT_OUTBOUND_TAG;
pub use json::JsonValue;
pub use parse::{load_from_path, parse_config, ConfigError, ExitCodeHint};
pub use schema::{
    DirectOutboundConfig, InboundConfig, InboundType, LogConfig, OutboundConfig, OutboundType,
    ProxyConfig, RedirectInboundConfig, RouteConfig, SocksInboundConfig, TrojanOutboundConfig,
    TrojanTlsConfig,
};
