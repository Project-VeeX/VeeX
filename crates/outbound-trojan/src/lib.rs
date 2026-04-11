//! Trojan outbound implementation for Phase1.

mod client;
mod dialer;
mod encode;
mod error;

pub use client::TrojanOutbound;
pub use dialer::{build_dialer, build_dialer_with_connector, system_tcp_connector};
pub use encode::{build_trojan_request, password_hash_hex, TrojanCommand};
