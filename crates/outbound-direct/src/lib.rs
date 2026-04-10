//! Direct outbound implementation kept outside `veex-core` so platform-specific
//! egress behavior can evolve without polluting core runtime abstractions.

mod client;
mod dialer;
mod error;

pub use client::DirectOutbound;
