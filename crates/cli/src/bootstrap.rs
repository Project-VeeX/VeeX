use std::sync::Arc;

use thiserror::Error;
use veex_config::{ProxyConfig, DEFAULT_DIRECT_OUTBOUND_TAG};
use veex_core::{Inbound, InboundSink, OutboundRegistry, ProxyError, SimpleDispatcher};

use crate::factory::{build_inbounds, build_outbounds, build_router, RuntimeServices};

pub struct RuntimeState {
    pub inbounds: Vec<Arc<dyn Inbound>>,
    pub outbounds: Arc<OutboundRegistry>,
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("at least one inbound is required to run veex")]
    MissingInbound,
    #[error("failed to build inbound runtime state: {0}")]
    InboundBuild(#[source] ProxyError),
    #[error("failed to build outbound runtime state: {0}")]
    OutboundBuild(#[source] ProxyError),
    #[error("runtime references missing final outbound `{0}`")]
    MissingFinalOutbound(String),
    #[error("runtime requires direct outbound `{0}`")]
    MissingDirectOutbound(String),
}

pub fn build_runtime_state(config: &ProxyConfig) -> Result<RuntimeState, BootstrapError> {
    if config.inbounds.is_empty() {
        return Err(BootstrapError::MissingInbound);
    }

    let services = RuntimeServices::default();
    let outbounds = build_outbounds(config, &services).map_err(BootstrapError::OutboundBuild)?;
    ensure_required_outbounds_built(config, outbounds.as_ref())?;
    let sink: Arc<dyn InboundSink> = Arc::new(SimpleDispatcher::new(
        build_router(config),
        Arc::clone(&outbounds),
    ));
    let inbounds = build_inbounds(config, sink).map_err(BootstrapError::InboundBuild)?;

    Ok(RuntimeState {
        inbounds,
        outbounds,
    })
}

fn ensure_required_outbounds_built(
    config: &ProxyConfig,
    outbounds: &OutboundRegistry,
) -> Result<(), BootstrapError> {
    if !outbounds.contains(&config.route.final_outbound) {
        return Err(BootstrapError::MissingFinalOutbound(
            config.route.final_outbound.clone(),
        ));
    }

    if !outbounds.contains(DEFAULT_DIRECT_OUTBOUND_TAG) {
        return Err(BootstrapError::MissingDirectOutbound(
            DEFAULT_DIRECT_OUTBOUND_TAG.to_string(),
        ));
    }

    Ok(())
}
