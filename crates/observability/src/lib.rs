//! Minimal logging bootstrap shared by runtime entrypoints.

pub mod logging;
pub mod session;

pub use logging::{init_logging, log_line, LogLevel, LoggingOptions};
pub use session::{emit_session_summary, format_session_summary, SessionSummary};
