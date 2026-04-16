//! Aggregated inbound component crate.

pub mod direct;
pub mod socks;
pub mod transparent;

pub use direct::{DirectInbound, DirectUdpInbound};
pub use socks::SocksInbound;
pub use transparent::{RedirectInbound, TProxyInbound};
