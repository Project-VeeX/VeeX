//! Minimal logging bootstrap shared by runtime entrypoints.

pub mod logging;
pub mod session;

pub use logging::{LogLevel, LoggingOptions, log_line};
pub use session::{
    ErrorKind, SessionSummary, emit_session_finish, emit_session_summary, format_session_summary,
};
