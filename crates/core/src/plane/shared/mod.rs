//! Shared execution-plane contracts.

pub mod context;
pub mod outbound;
pub mod registry;

pub use context::{RouteReason, SessionContext, SessionMeta, SessionRoute, SessionState};
pub use outbound::DispatchOutbound;
pub use registry::OutboundRegistry;
