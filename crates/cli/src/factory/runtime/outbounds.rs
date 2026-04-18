use std::{collections::HashMap, sync::Arc};

use veex_config::DEFAULT_DIRECT_OUTBOUND_TAG;
use veex_core::{
    logging::Logger,
    portal::{Dial, Outbound, OutboundMeta},
    ProxyError,
};
use veex_execution::{ExecutionOutbound, OutboundCatalog};
use veex_portal_outbound::direct::{
    build_dialer as build_direct_dialer, build_packet_dialer as build_direct_packet_dialer,
    DirectOutbound,
};

use crate::factory::runtime::RuntimeServices;

pub(crate) const IMPLICIT_DIRECT_OUTBOUND_TAG: &str = "implicit-direct";

type ExecutionHandle = Arc<dyn ExecutionOutbound>;
type LifecycleHandle = Arc<dyn Outbound>;
type ImplicitDirect = (ExecutionHandle, Option<LifecycleHandle>);

pub(crate) struct RuntimeOutbounds {
    catalog: Arc<OutboundCatalog>,
    lifecycle: Vec<LifecycleHandle>,
}

impl RuntimeOutbounds {
    pub(crate) fn new(catalog: Arc<OutboundCatalog>, lifecycle: Vec<LifecycleHandle>) -> Self {
        Self { catalog, lifecycle }
    }

    pub(crate) fn catalog(&self) -> &Arc<OutboundCatalog> {
        &self.catalog
    }

    pub(crate) fn contains(&self, tag: &str) -> bool {
        self.catalog.contains(tag)
    }

    pub(crate) fn lifecycle(&self) -> impl Iterator<Item = &LifecycleHandle> + '_ {
        self.lifecycle.iter()
    }

    pub(crate) fn len(&self) -> usize {
        self.lifecycle.len()
    }
}

pub(crate) struct BuiltRuntimeOutbound {
    pub(crate) execution: ExecutionHandle,
    lifecycle: LifecycleHandle,
}

impl BuiltRuntimeOutbound {
    pub(crate) fn new<T>(instance: Arc<T>) -> Self
    where
        T: ExecutionOutbound + Outbound + 'static,
    {
        let execution: ExecutionHandle = instance.clone();
        let lifecycle: LifecycleHandle = instance;
        Self {
            execution,
            lifecycle,
        }
    }
}

pub(crate) struct RuntimeOutboundsBuilder {
    catalog_entries: HashMap<String, ExecutionHandle>,
    lifecycle: Vec<LifecycleHandle>,
    configured_default_direct: Option<ExecutionHandle>,
}

impl RuntimeOutboundsBuilder {
    pub(crate) fn new() -> Self {
        Self {
            catalog_entries: HashMap::new(),
            lifecycle: Vec::new(),
            configured_default_direct: None,
        }
    }

    pub(crate) fn set_default_direct(&mut self, outbound: ExecutionHandle) {
        self.configured_default_direct = Some(outbound);
    }

    pub(crate) fn register(&mut self, outbound: BuiltRuntimeOutbound) -> Result<(), ProxyError> {
        let tag = outbound.execution.tag().to_string();
        if self
            .catalog_entries
            .insert(tag.clone(), Arc::clone(&outbound.execution))
            .is_some()
        {
            return Err(ProxyError::config(format!(
                "duplicate outbound tag in registry: {tag}"
            )));
        }

        self.lifecycle.push(outbound.lifecycle);
        Ok(())
    }

    pub(crate) fn finalize(
        mut self,
        services: &RuntimeServices,
    ) -> Result<Arc<RuntimeOutbounds>, ProxyError> {
        let (default_outbound, default_lifecycle) = match self.configured_default_direct.take() {
            Some(outbound) => (outbound, None),
            None => build_implicit_direct_outbound(services)?,
        };

        if let Some(default_lifecycle) = default_lifecycle {
            self.lifecycle.push(default_lifecycle);
        }

        Ok(Arc::new(RuntimeOutbounds::new(
            Arc::new(OutboundCatalog::new(self.catalog_entries, default_outbound)),
            self.lifecycle,
        )))
    }
}

fn build_implicit_direct_outbound(
    services: &RuntimeServices,
) -> Result<ImplicitDirect, ProxyError> {
    let dialer = build_direct_dialer(Dial::default(), Arc::clone(&services.host_resolver))?;
    let packet_dialer =
        build_direct_packet_dialer(Dial::default(), Arc::clone(&services.host_resolver))?;
    let instance = Arc::new(DirectOutbound::new(
        OutboundMeta::new(IMPLICIT_DIRECT_OUTBOUND_TAG, "direct"),
        Logger::new(IMPLICIT_DIRECT_OUTBOUND_TAG, "direct"),
        dialer,
        packet_dialer,
    )?);
    Ok((
        instance.clone() as ExecutionHandle,
        Some(instance as LifecycleHandle),
    ))
}

pub(crate) fn is_default_direct_tag(tag: &str) -> bool {
    tag == DEFAULT_DIRECT_OUTBOUND_TAG
}
