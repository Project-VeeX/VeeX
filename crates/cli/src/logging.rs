use std::{io, sync::OnceLock};

use time::{UtcOffset, macros::format_description};
use tracing_subscriber::{filter::LevelFilter, fmt::time::OffsetTime};
use veex_observability::{LogLevel, LoggingOptions};

static TRACING_INIT: OnceLock<Result<(), String>> = OnceLock::new();

const LOG_TIMESTAMP_FORMAT: &[time::format_description::BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]");

pub fn init_tracing(options: &LoggingOptions) -> io::Result<()> {
    let result = TRACING_INIT.get_or_init(|| {
        let max_level = if options.disabled {
            LevelFilter::OFF
        } else {
            level_filter(options.level)
        };

        if options.timestamp {
            let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_target(false)
                .with_timer(OffsetTime::new(offset, LOG_TIMESTAMP_FORMAT))
                .with_max_level(max_level)
                .try_init()
                .map_err(|err| format!("failed to install tracing subscriber: {err}"))
        } else {
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_target(false)
                .without_time()
                .with_max_level(max_level)
                .try_init()
                .map_err(|err| format!("failed to install tracing subscriber: {err}"))
        }
    });

    result
        .as_ref()
        .map(|_| ())
        .map_err(|message| io::Error::other(message.clone()))
}

fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
    }
}
