#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum LogLevel {
    #[default]
    Error,
    Warn,
    Info,
    Debug,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LoggingOptions {
    pub level: LogLevel,
    pub disabled: bool,
}

pub fn log_line(level: LogLevel, message: &str) {
    match level {
        LogLevel::Error => tracing::error!(message = %message),
        LogLevel::Warn => tracing::warn!(message = %message),
        LogLevel::Info => tracing::info!(message = %message),
        LogLevel::Debug => tracing::debug!(message = %message),
    }
}
