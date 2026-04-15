//! Trojan outbound implementation for Phase1.

mod client;
mod dialer;
mod error;

pub use client::TrojanOutbound;
pub use dialer::{
    build_dialer, build_dialer_with_connector, system_host_resolver, system_tcp_connector,
};
pub use veex_protocol::trojan::encode::{build_trojan_request, encode_key_hex, TrojanCommand};
