use std::{collections::HashMap, sync::Arc};

use thiserror::Error;
use veex_config::{ProxyConfig, DEFAULT_DIRECT_OUTBOUND_TAG};
use veex_core::{Dispatcher, Inbound, Outbound, ProxyError, RuntimeOutbound, SimpleDispatcher};

use crate::factory::{build_inbounds, build_outbounds, build_router, RuntimeServices};

pub struct RuntimeState {
    pub inbounds: Vec<Arc<dyn Inbound>>,
    pub outbounds: Vec<Arc<dyn Outbound>>,
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
    let built_outbounds =
        build_outbounds(config, &services).map_err(BootstrapError::OutboundBuild)?;
    ensure_required_outbounds_built(config, &built_outbounds.routing)?;
    let dispatcher: Arc<dyn Dispatcher> = Arc::new(SimpleDispatcher::new(
        build_router(config),
        built_outbounds.routing,
    ));
    let inbounds = build_inbounds(config, dispatcher).map_err(BootstrapError::InboundBuild)?;

    Ok(RuntimeState {
        inbounds,
        outbounds: built_outbounds.registry,
    })
}

fn ensure_required_outbounds_built(
    config: &ProxyConfig,
    outbounds: &HashMap<String, RuntimeOutbound>,
) -> Result<(), BootstrapError> {
    if !outbounds.contains_key(&config.route.final_outbound) {
        return Err(BootstrapError::MissingFinalOutbound(
            config.route.final_outbound.clone(),
        ));
    }

    if !outbounds.contains_key(DEFAULT_DIRECT_OUTBOUND_TAG) {
        return Err(BootstrapError::MissingDirectOutbound(
            DEFAULT_DIRECT_OUTBOUND_TAG.to_string(),
        ));
    }

    Ok(())
}
