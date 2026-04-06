//! Minimal sing-box compatible configuration subset used by VeeX.

mod defaults;
mod error;
mod json;
mod parse;
mod schema;
mod validate;

pub use defaults::DEFAULT_DIRECT_OUTBOUND_TAG;
pub use error::{ConfigError, ExitCodeHint};
pub use json::JsonValue;
pub use parse::{
    load_from_path, load_from_path_unvalidated, parse_config, parse_config_unvalidated,
};
pub use schema::{
    DirectOutboundConfig, InboundConfig, InboundType, LogConfig, OutboundConfig, OutboundType,
    ProxyConfig, RedirectInboundConfig, RouteConfig, SocksInboundConfig, TProxyInboundConfig,
    TrojanOutboundConfig, TrojanTlsConfig,
};
pub use validate::validate_config;
