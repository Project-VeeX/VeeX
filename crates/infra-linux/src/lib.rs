//! Linux-specific infrastructure helpers shared by transparent inbounds.

mod socket;
mod transparent;

pub use transparent::{
    create_dual_stack_listener, create_transparent_listener, get_original_dst, get_tproxy_dst,
    is_v4_mapped, TransparentError, IP6T_SO_ORIGINAL_DST, SO_ORIGINAL_DST,
};
