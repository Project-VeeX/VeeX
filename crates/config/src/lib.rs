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
pub use parse::{load_from_path, parse_config};
pub use schema::{
    DirectOutboundConfig, InboundConfig, InboundType, LogConfig, OutboundConfig, OutboundType,
    ProxyConfig, RedirectInboundConfig, RouteConfig, SocksInboundConfig, TProxyInboundConfig,
    TrojanOutboundConfig, TrojanTlsConfig,
};
