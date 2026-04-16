//! Aggregated outbound component crate.

pub mod direct;
pub mod trojan;

pub use direct::DirectOutbound;
pub use trojan::TrojanOutbound;
