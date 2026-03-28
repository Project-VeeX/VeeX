use std::sync::OnceLock;

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

#[derive(Clone, Copy, Debug)]
struct LoggingState {
    level: LogLevel,
    disabled: bool,
}

static LOGGING_STATE: OnceLock<LoggingState> = OnceLock::new();

pub fn init_logging(options: &LoggingOptions) -> std::io::Result<()> {
    let _ = LOGGING_STATE.set(LoggingState {
        level: options.level,
        disabled: options.disabled,
    });
    Ok(())
}

pub fn log_line(level: LogLevel, message: &str) {
    let state = LOGGING_STATE.get().copied().unwrap_or(LoggingState {
        level: LogLevel::Error,
        disabled: false,
    });

    if state.disabled || level > state.level {
        return;
    }

    match level {
        LogLevel::Error | LogLevel::Warn => eprintln!("{message}"),
        LogLevel::Info | LogLevel::Debug => println!("{message}"),
    }
}
