use std::{collections::HashMap, sync::Arc};

use veex_config::{ProxyConfig, DEFAULT_DIRECT_OUTBOUND_TAG};
use veex_core::{
    shutdown_channel, Dispatcher, Inbound, Outbound, ShutdownTrigger, SimpleDispatcher,
};

use crate::factory::{build_inbounds, build_outbounds, build_router};

pub struct RuntimeState {
    pub dispatcher: Arc<dyn Dispatcher>,
    pub inbounds: Vec<Arc<dyn Inbound>>,
    pub shutdown: ShutdownTrigger,
}

pub fn build_runtime_state(config: &ProxyConfig) -> Result<RuntimeState, String> {
    if config.inbounds.is_empty() {
        return Err("at least one inbound is required to run veex".into());
    }

    let (shutdown, shutdown_signal) = shutdown_channel();
    let outbounds = build_outbounds(config)?;
    validate_runtime_outbounds(config, &outbounds)?;
    let dispatcher: Arc<dyn Dispatcher> =
        Arc::new(SimpleDispatcher::new(build_router(config), outbounds));
    let inbounds = build_inbounds(config, shutdown_signal)?;

    Ok(RuntimeState {
        dispatcher,
        inbounds,
        shutdown,
    })
}

fn validate_runtime_outbounds(
    config: &ProxyConfig,
    outbounds: &HashMap<String, Arc<dyn Outbound>>,
) -> Result<(), String> {
    if !outbounds.contains_key(&config.route.final_outbound) {
        return Err(format!(
            "runtime references missing final outbound '{}'",
            config.route.final_outbound
        ));
    }

    if !outbounds.contains_key(DEFAULT_DIRECT_OUTBOUND_TAG) {
        return Err(format!(
            "runtime requires direct outbound '{}'",
            DEFAULT_DIRECT_OUTBOUND_TAG
        ));
    }

    Ok(())
}
