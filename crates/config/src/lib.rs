//! Minimal sing-box compatible configuration subset used by VeeX.

mod defaults;
mod json;
mod schema;
mod validate;

pub use defaults::DEFAULT_DIRECT_OUTBOUND_TAG;
pub use json::JsonValue;
pub use schema::{
    DirectOutboundConfig, InboundConfig, InboundType, LogConfig, OutboundConfig, OutboundType,
    ProxyConfig, RedirectInboundConfig, RouteConfig, SocksInboundConfig, TrojanOutboundConfig,
    TrojanTlsConfig,
};
pub use validate::{load_from_path, parse_config, ConfigError, ExitCodeHint};
