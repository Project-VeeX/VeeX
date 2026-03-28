//! Linux redirect inbound support built on top of `SO_ORIGINAL_DST`.

pub mod error;
pub mod original_dst;
pub mod server;

pub use error::RedirectError;
pub use original_dst::{resolve_original_dst, IP6T_SO_ORIGINAL_DST, SO_ORIGINAL_DST};
pub use server::RedirectInbound;
