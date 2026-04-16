use std::{collections::HashMap, sync::Arc};

use veex_core::ProxyError;

use super::traits::ExecutionOutbound;

/// Builder for a finalized outbound registry.
#[derive(Default)]
pub struct OutboundRegistryBuilder {
    outbounds: Vec<Arc<dyn ExecutionOutbound>>,
    index_by_tag: HashMap<String, usize>,
}

impl OutboundRegistryBuilder {
    pub fn register(&mut self, outbound: Arc<dyn ExecutionOutbound>) -> veex_core::Result<()> {
        let tag = outbound.meta().tag.clone();
        if self.index_by_tag.contains_key(&tag) {
            return Err(ProxyError::config(format!(
                "duplicate outbound tag in registry: {tag}"
            )));
        }

        let index = self.outbounds.len();
        self.outbounds.push(outbound);
        self.index_by_tag.insert(tag, index);
        Ok(())
    }

    pub fn finalize(self, default_outbound: Arc<dyn ExecutionOutbound>) -> OutboundRegistry {
        OutboundRegistry {
            outbounds: self.outbounds,
            index_by_tag: self.index_by_tag,
            default_outbound,
        }
    }
}

/// Registry of dispatch-capable outbounds indexed by tag.
pub struct OutboundRegistry {
    outbounds: Vec<Arc<dyn ExecutionOutbound>>,
    index_by_tag: HashMap<String, usize>,
    default_outbound: Arc<dyn ExecutionOutbound>,
}

impl OutboundRegistry {
    pub fn get(&self, tag: &str) -> Option<Arc<dyn ExecutionOutbound>> {
        self.index_by_tag
            .get(tag)
            .and_then(|index| self.outbounds.get(*index))
            .map(Arc::clone)
    }

    pub fn default_outbound(&self) -> Arc<dyn ExecutionOutbound> {
        Arc::clone(&self.default_outbound)
    }

    pub fn require(&self, tag: &str) -> veex_core::Result<Arc<dyn ExecutionOutbound>> {
        self.get(tag)
            .ok_or_else(|| ProxyError::config(format!("missing outbound tag: {tag}")))
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.index_by_tag.contains_key(tag)
    }

    pub fn len(&self) -> usize {
        self.outbounds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.outbounds.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Arc<dyn ExecutionOutbound>> + '_ {
        self.outbounds.iter()
    }

    pub fn lifecycle_iter(&self) -> impl Iterator<Item = &Arc<dyn ExecutionOutbound>> + '_ {
        let default_outbound = (!self
            .outbounds
            .iter()
            .any(|outbound| Arc::ptr_eq(outbound, &self.default_outbound)))
        .then_some(&self.default_outbound);

        self.outbounds.iter().chain(default_outbound)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use veex_core::{
        io::BoxedAsyncStream,
        logging::Logger,
        portal::{meta::OutboundMeta, traits::BoxFuture, Outbound},
        session::SessionContext,
        ProxyError,
    };

    use crate::ExecutionOutbound;

    use super::OutboundRegistryBuilder;

    struct TestOutbound {
        meta: OutboundMeta,
        logger: Logger,
    }

    impl TestOutbound {
        fn new(tag: &str) -> Self {
            Self {
                meta: OutboundMeta::new(tag, "direct"),
                logger: Logger::new(tag, "direct"),
            }
        }
    }

    impl Outbound for TestOutbound {
        fn meta(&self) -> &OutboundMeta {
            &self.meta
        }

        fn logger(&self) -> &Logger {
            &self.logger
        }

        fn close(&self) -> BoxFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    impl ExecutionOutbound for TestOutbound {
        fn open_stream(&self, _ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("unused")) })
        }
    }

    #[test]
    fn registry_resolves_missing_detour_to_default_outbound() {
        let default_outbound: Arc<dyn ExecutionOutbound> = Arc::new(TestOutbound::new("direct"));
        let registry = OutboundRegistryBuilder::default().finalize(Arc::clone(&default_outbound));

        let resolved = registry.default_outbound();

        assert!(Arc::ptr_eq(&resolved, &default_outbound));
    }

    #[test]
    fn registry_resolves_explicit_detour_without_using_default() {
        let explicit_outbound: Arc<dyn ExecutionOutbound> = Arc::new(TestOutbound::new("proxy"));
        let mut registry = OutboundRegistryBuilder::default();
        registry
            .register(Arc::clone(&explicit_outbound))
            .expect("explicit outbound should register");
        let registry = registry.finalize(Arc::new(TestOutbound::new("direct")));

        let resolved = registry
            .require("proxy")
            .expect("explicit detour should resolve");

        assert!(Arc::ptr_eq(&resolved, &explicit_outbound));
    }

    #[test]
    fn registry_rejects_missing_explicit_detour() {
        let registry =
            OutboundRegistryBuilder::default().finalize(Arc::new(TestOutbound::new("direct")));

        let err = match registry.require("missing") {
            Ok(_) => panic!("missing explicit detour should remain an error"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("missing outbound tag: missing"));
    }

    #[test]
    fn lifecycle_iter_does_not_duplicate_registered_default_outbound() {
        let default_outbound: Arc<dyn ExecutionOutbound> = Arc::new(TestOutbound::new("direct"));
        let mut registry = OutboundRegistryBuilder::default();
        registry
            .register(Arc::clone(&default_outbound))
            .expect("default outbound should register");
        let registry = registry.finalize(default_outbound);

        assert_eq!(registry.lifecycle_iter().count(), 1);
    }
}
