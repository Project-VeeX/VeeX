//! Direct outbound implementation kept outside `veex-core` so platform-specific
//! egress behavior can evolve without polluting core runtime abstractions.

mod client;
mod dialer;
mod error;

pub use client::DirectOutbound;
pub use dialer::{
    build_dialer, build_dialer_with_connector, build_packet_dialer,
    build_packet_dialer_with_connector, system_host_resolver,
};
