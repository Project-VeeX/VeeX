use std::{env, process::ExitCode};

use tracing::info;
use veex_cli::{
    command::{parse_args, Command},
    logging::init_tracing,
    runtime::run_with_shutdown,
};
use veex_config::{load_from_path_with_diagnostics, ConfigError, ParseDiagnostics};
use veex_core::logging::sanitize_field;
use veex_observability::{LogLevel, LoggingOptions};

const EXIT_OK: u8 = 0;
const EXIT_CONFIG_ERROR: u8 = 2;
const EXIT_STARTUP_ERROR: u8 = 3;
const EXIT_RUNTIME_ERROR: u8 = 4;

fn main() -> ExitCode {
    match try_main() {
        Ok(code) => ExitCode::from(code),
        Err((code, message)) => {
            eprintln!("{message}");
            ExitCode::from(code)
        }
    }
}

fn try_main() -> Result<u8, (u8, String)> {
    let command = parse_args(env::args()).map_err(|err| (EXIT_CONFIG_ERROR, err.to_string()))?;

    match command {
        Command::Check {
            config_path,
            verbose,
        } => {
            let loaded = load_config(&config_path)?;
            if verbose {
                emit_config_warnings(&loaded.diagnostics);
            }
            println!(
                "config check passed: {} inbound(s), {} outbound(s), final={}",
                loaded.config.inbounds.len(),
                loaded.config.outbounds.len(),
                loaded.config.route.final_outbound
            );
            Ok(EXIT_OK)
        }
        Command::Run {
            config_path,
            verbose,
        } => run_command(&config_path, verbose),
        Command::Version => {
            println!(
                "veex {}\nbuild_time={}\ngit_commit={}",
                env!("CARGO_PKG_VERSION"),
                option_env!("VEEX_BUILD_TIME").unwrap_or("unknown"),
                option_env!("VEEX_GIT_COMMIT").unwrap_or("unknown")
            );
            Ok(EXIT_OK)
        }
    }
}

fn run_command(config_path: &str, verbose: bool) -> Result<u8, (u8, String)> {
    let loaded = load_config(config_path)?;
    if verbose {
        emit_config_warnings(&loaded.diagnostics);
    }
    let config = loaded.config;
    let logging = LoggingOptions {
        level: parse_log_level(&config.log.level)
            .map_err(|message| (EXIT_CONFIG_ERROR, message))?,
        disabled: config.log.disabled,
        timestamp: config.log.timestamp,
    };

    init_tracing(&logging)
        .map_err(|err| (EXIT_STARTUP_ERROR, format!("logging init failed: {err}")))?;

    info!(
        event = "process_start",
        inbounds = config.inbounds.len(),
        outbounds = config.outbounds.len(),
        final_outbound = %sanitize_field(config.route.final_outbound.as_str()),
        "process start"
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            (
                EXIT_STARTUP_ERROR,
                format!("failed to build runtime: {err}"),
            )
        })?;

    runtime
        .block_on(async {
            run_with_shutdown(&config, async { wait_for_shutdown_signal().await }).await
        })
        .map_err(|err| (EXIT_RUNTIME_ERROR, err.to_string()))?;

    info!(event = "process_stop", "process stop");
    Ok(EXIT_OK)
}

struct LoadedConfig {
    config: veex_config::ProxyConfig,
    diagnostics: ParseDiagnostics,
}

fn load_config(path: &str) -> Result<LoadedConfig, (u8, String)> {
    let (config, diagnostics) = load_from_path_with_diagnostics(path).map_err(map_config_error)?;
    Ok(LoadedConfig {
        config,
        diagnostics,
    })
}

fn map_config_error(err: ConfigError) -> (u8, String) {
    (err.exit_code_hint() as u8, err.to_string())
}

fn emit_config_warnings(diagnostics: &ParseDiagnostics) {
    for warning in &diagnostics.warnings {
        eprintln!("config warning at {}: {}", warning.path, warning.message);
    }
}

fn parse_log_level(value: &str) -> Result<LogLevel, String> {
    match value {
        "error" => Ok(LogLevel::Error),
        "warn" | "warning" => Ok(LogLevel::Warn),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        other => Err(format!("unsupported log level '{other}'")),
    }
}

async fn wait_for_shutdown_signal() -> Result<(), String> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut terminate = signal(SignalKind::terminate())
            .map_err(|err| format!("failed to install SIGTERM handler: {err}"))?;

        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|err| format!("failed to wait for SIGINT: {err}"))?;
                Ok(())
            }
            _ = terminate.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|err| format!("failed to wait for shutdown signal: {err}"))?;
        Ok(())
    }
}
