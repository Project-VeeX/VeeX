use std::sync::Arc;

use thiserror::Error;
use veex_config::ProxyConfig;
use veex_core::{portal::Inbound, ProxyError};
use veex_execution::{
    PacketDispatch, PacketDispatcher, RoutedPacketDispatch, RoutedStreamDispatch, StreamDispatch,
    StreamDispatcher,
};

use crate::factory::{
    build_dns_services, build_inbounds, build_outbounds, build_router, RuntimeOutbounds,
    RuntimeServices,
};

pub struct RuntimeState {
    pub inbounds: Vec<Arc<dyn Inbound>>,
    pub outbounds: Arc<RuntimeOutbounds>,
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
}

pub fn build_runtime_state(config: &ProxyConfig) -> Result<RuntimeState, BootstrapError> {
    if config.inbounds.is_empty() {
        return Err(BootstrapError::MissingInbound);
    }

    let services = RuntimeServices::default();
    let outbounds = build_outbounds(config, &services).map_err(BootstrapError::OutboundBuild)?;
    ensure_required_outbounds_built(config, outbounds.as_ref())?;
    let router = build_router(config);
    let dns_services = build_dns_services(config, Arc::clone(outbounds.catalog()))
        .map_err(BootstrapError::OutboundBuild)?;
    if let Some(services_handle) = dns_services.as_ref() {
        services
            .install_domain_resolver(Arc::clone(&services_handle.resolver))
            .map_err(BootstrapError::OutboundBuild)?;
    }
    let dns_executor = dns_services.map(|services| services.executor);
    let stream_executor = Arc::new(StreamDispatcher::with_dns_executor(
        Arc::clone(outbounds.catalog()),
        dns_executor.clone(),
    ));
    let packet_executor = Arc::new(PacketDispatcher::with_dns_executor(
        Arc::clone(outbounds.catalog()),
        dns_executor,
    ));
    let stream_sink: Arc<dyn StreamDispatch> =
        Arc::new(RoutedStreamDispatch::new(router.clone(), stream_executor));
    let packet_sink: Arc<dyn PacketDispatch> =
        Arc::new(RoutedPacketDispatch::new(router, packet_executor));
    let inbounds =
        build_inbounds(config, stream_sink, packet_sink).map_err(BootstrapError::InboundBuild)?;

    Ok(RuntimeState {
        inbounds,
        outbounds,
    })
}

fn ensure_required_outbounds_built(
    config: &ProxyConfig,
    outbounds: &RuntimeOutbounds,
) -> Result<(), BootstrapError> {
    if !outbounds.contains(&config.route.final_outbound) {
        return Err(BootstrapError::MissingFinalOutbound(
            config.route.final_outbound.clone(),
        ));
    }

    Ok(())
}
