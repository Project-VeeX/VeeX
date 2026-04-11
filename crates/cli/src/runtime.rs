use std::future::Future;

use thiserror::Error;
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
    #[error("runtime outbound task `{outbound}` failed: {source}")]
    OutboundTask {
        outbound: String,
        #[source]
        source: ProxyError,
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

    fn outbound_task(outbound: impl Into<String>, source: ProxyError) -> Self {
        Self::OutboundTask {
            outbound: outbound.into(),
            source,
        }
    }
}

pub async fn run_with_shutdown<F>(config: &ProxyConfig, shutdown: F) -> Result<(), RuntimeError>
where
    F: Future<Output = std::result::Result<(), String>>,
{
    let state = build_runtime_state(config)?;
    let RuntimeState {
        inbounds,
        outbounds,
    } = state;

    info!(
        event = "runtime_start",
        inbounds = config.inbounds.len(),
        outbounds = config.outbounds.len(),
        final_outbound = %sanitize_field(config.route.final_outbound.as_str()),
        "runtime start"
    );

    start_outbounds(&outbounds).await?;
    start_inbounds(&inbounds).await?;

    tokio::pin!(shutdown);
    shutdown.await.map_err(RuntimeError::shutdown_wait)?;

    info!(
        event = "shutdown_begin",
        remaining_inbounds = inbounds.len(),
        remaining_outbounds = outbounds.len(),
        "shutdown begin"
    );

    close_inbounds(&inbounds).await?;
    close_outbounds(&outbounds).await?;

    info!(event = "shutdown_complete", "shutdown complete");
    Ok(())
}

async fn start_inbounds(
    inbounds: &[std::sync::Arc<dyn veex_core::Inbound>],
) -> Result<(), RuntimeError> {
    for inbound in inbounds {
        let inbound_tag = inbound.meta().tag.clone();
        let inbound_field = sanitize_field(&inbound_tag).into_owned();
        info!(
            event = "service_start",
            inbound = %inbound_field,
            "starting inbound service"
        );
        if let Err(err) = inbound.start().await {
            warn!(
                event = "inbound_service_failed",
                inbound = %inbound_field,
                error_kind = ?err.kind(),
                error = %err,
                "inbound service failed"
            );
            return Err(RuntimeError::task(inbound_tag, err));
        }
    }

    Ok(())
}

async fn start_outbounds(
    outbounds: &[std::sync::Arc<dyn veex_core::Outbound>],
) -> Result<(), RuntimeError> {
    for outbound in outbounds {
        let outbound_tag = outbound.meta().tag.clone();
        let outbound_field = sanitize_field(&outbound_tag).into_owned();
        info!(
            event = "service_start",
            outbound = %outbound_field,
            "starting outbound service"
        );
        if let Err(err) = outbound.start().await {
            warn!(
                event = "outbound_service_failed",
                outbound = %outbound_field,
                error_kind = ?err.kind(),
                error = %err,
                "outbound service failed"
            );
            return Err(RuntimeError::outbound_task(outbound_tag, err));
        }
    }

    Ok(())
}

async fn close_inbounds(
    inbounds: &[std::sync::Arc<dyn veex_core::Inbound>],
) -> Result<(), RuntimeError> {
    for inbound in inbounds {
        let inbound_tag = inbound.meta().tag.clone();
        let inbound_field = sanitize_field(&inbound_tag).into_owned();
        if let Err(err) = inbound.close().await {
            warn!(
                event = "inbound_service_failed",
                inbound = %inbound_field,
                error_kind = ?err.kind(),
                error = %err,
                "inbound service failed during close"
            );
            return Err(RuntimeError::task(inbound_tag, err));
        }
    }

    Ok(())
}

async fn close_outbounds(
    outbounds: &[std::sync::Arc<dyn veex_core::Outbound>],
) -> Result<(), RuntimeError> {
    for outbound in outbounds {
        let outbound_tag = outbound.meta().tag.clone();
        let outbound_field = sanitize_field(&outbound_tag).into_owned();
        if let Err(err) = outbound.close().await {
            error!(
                event = "outbound_service_failed",
                outbound = %outbound_field,
                error_kind = ?err.kind(),
                error = %err,
                "outbound service failed during close"
            );
            return Err(RuntimeError::outbound_task(outbound_tag, err));
        }
    }

    Ok(())
}
