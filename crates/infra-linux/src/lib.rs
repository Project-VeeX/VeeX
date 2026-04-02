//! Linux-specific infrastructure helpers shared by transparent inbounds.

mod transparent;

pub use transparent::{
    create_transparent_listener, get_original_dst, get_tproxy_dst, TransparentError,
    IP6T_SO_ORIGINAL_DST, SO_ORIGINAL_DST,
};
