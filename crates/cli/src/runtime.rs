use std::{future::Future, sync::Arc};

use thiserror::Error;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use veex_config::ProxyConfig;
use veex_core::{sanitize_field, ProxyError};

use crate::bootstrap::{build_runtime_state, BootstrapError, RuntimeState};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime bootstrap failed: {0}")]
    Bootstrap(#[from] BootstrapError),
    #[error("shutdown wait failed: {message}")]
    ShutdownWait { message: String },
    #[error("runtime inbound task `{inbound}` failed: {source}")]
    Task {
        inbound: String,
        #[source]
        source: ProxyError,
    },
    #[error("runtime task join failed: {source}")]
    TaskJoin {
        #[source]
        source: tokio::task::JoinError,
    },
}

impl RuntimeError {
    fn shutdown_wait(message: impl Into<String>) -> Self {
        Self::ShutdownWait {
            message: message.into(),
        }
    }

    fn task(inbound: impl Into<String>, source: ProxyError) -> Self {
        Self::Task {
            inbound: inbound.into(),
            source,
        }
    }

    fn task_join(source: tokio::task::JoinError) -> Self {
        Self::TaskJoin { source }
    }
}

pub async fn run_with_shutdown<F>(config: &ProxyConfig, shutdown: F) -> Result<(), RuntimeError>
where
    F: Future<Output = std::result::Result<(), String>>,
{
    let state = build_runtime_state(config)?;
    let RuntimeState {
        dispatcher,
        inbounds,
        shutdown: shutdown_trigger,
    } = state;
    let mut tasks = JoinSet::new();

    info!(
        event = "runtime_start",
        inbounds = config.inbounds.len(),
        outbounds = config.outbounds.len(),
        final_outbound = %sanitize_field(config.route.final_outbound.as_str()),
        "runtime start"
    );

    for inbound in inbounds {
        let inbound_tag = inbound.tag().to_string();
        let dispatcher = Arc::clone(&dispatcher);
        let inbound_field = sanitize_field(&inbound_tag).into_owned();
        info!(
            event = "service_start",
            inbound = %inbound_field,
            "starting inbound service"
        );
        tasks.spawn(async move {
            let result = inbound.serve(dispatcher).await;
            (inbound_tag, result)
        });
    }

    tokio::pin!(shutdown);
    let mut shutdown_requested = false;

    loop {
        if shutdown_requested && tasks.is_empty() {
            info!(event = "shutdown_complete", "shutdown complete");
            return Ok(());
        }

        tokio::select! {
            result = &mut shutdown, if !shutdown_requested => {
                result.map_err(RuntimeError::shutdown_wait)?;
                info!(event = "shutdown_begin", remaining_tasks = tasks.len(), "shutdown begin");
                shutdown_trigger.trigger();
                shutdown_requested = true;
            }
            maybe_task = tasks.join_next(), if !tasks.is_empty() => {
                match maybe_task {
                    Some(Ok((_inbound, Ok(())))) => continue,
                    Some(Ok((inbound, Err(err)))) => {
                        let inbound_field = sanitize_field(&inbound).into_owned();
                        warn!(
                            event = "inbound_service_failed",
                            inbound = %inbound_field,
                            error_kind = ?err.kind(),
                            error = %err,
                            "inbound service failed"
                        );
                        return Err(RuntimeError::task(inbound, err));
                    }
                    Some(Err(err)) => {
                        error!(
                            event = "task_join_failed",
                            error = %err,
                            "runtime task join failed"
                        );
                        return Err(RuntimeError::task_join(err));
                    }
                    None => {
                        if shutdown_requested {
                            info!(event = "shutdown_complete", "shutdown complete");
                        }
                        return Ok(());
                    }
                }
            }
        }
    }
}
