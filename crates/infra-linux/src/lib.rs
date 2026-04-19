//! Linux-specific infrastructure helpers shared by transparent inbounds.

mod resolv_conf;
mod socket;
mod transparent;

pub use resolv_conf::load_system_dns_servers;
pub use socket::create_dual_stack_udp_socket;
pub use transparent::{
    IP6T_SO_ORIGINAL_DST, SO_ORIGINAL_DST, TransparentError, create_dual_stack_listener,
    create_transparent_listener, get_original_dst, get_tproxy_dst, is_v4_mapped,
};
