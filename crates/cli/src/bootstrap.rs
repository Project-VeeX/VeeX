use std::{collections::HashMap, sync::Arc};

use thiserror::Error;
use veex_config::{ProxyConfig, DEFAULT_DIRECT_OUTBOUND_TAG};
use veex_core::{
    shutdown_channel, Dispatcher, Inbound, Outbound, ProxyError, ShutdownTrigger,
    SimpleDispatcher,
};

use crate::factory::{build_inbounds, build_outbounds, build_router};

pub struct RuntimeState {
    pub dispatcher: Arc<dyn Dispatcher>,
    pub inbounds: Vec<Arc<dyn Inbound>>,
    pub shutdown: ShutdownTrigger,
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

    let (shutdown, shutdown_signal) = shutdown_channel();
    let outbounds = build_outbounds(config).map_err(BootstrapError::OutboundBuild)?;
    validate_runtime_outbounds(config, &outbounds)?;
    let dispatcher: Arc<dyn Dispatcher> =
        Arc::new(SimpleDispatcher::new(build_router(config), outbounds));
    let inbounds = build_inbounds(config, shutdown_signal).map_err(BootstrapError::InboundBuild)?;

    Ok(RuntimeState {
        dispatcher,
        inbounds,
        shutdown,
    })
}

fn validate_runtime_outbounds(
    config: &ProxyConfig,
    outbounds: &HashMap<String, Arc<dyn Outbound>>,
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
