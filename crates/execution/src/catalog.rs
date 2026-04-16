use std::{collections::HashMap, sync::Arc};

use veex_core::ProxyError;

use crate::ExecutionOutbound;

/// Read-only catalog of dispatch-capable outbounds indexed by tag.
pub struct OutboundCatalog {
    outbounds: HashMap<String, Arc<dyn ExecutionOutbound>>,
    default_outbound: Arc<dyn ExecutionOutbound>,
}

impl OutboundCatalog {
    pub fn new(
        outbounds: HashMap<String, Arc<dyn ExecutionOutbound>>,
        default_outbound: Arc<dyn ExecutionOutbound>,
    ) -> Self {
        Self {
            outbounds,
            default_outbound,
        }
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn ExecutionOutbound>> {
        self.outbounds.get(tag).map(Arc::clone)
    }

    pub fn default_outbound(&self) -> Arc<dyn ExecutionOutbound> {
        Arc::clone(&self.default_outbound)
    }

    pub fn require(&self, tag: &str) -> veex_core::Result<Arc<dyn ExecutionOutbound>> {
        self.get(tag)
            .ok_or_else(|| ProxyError::config(format!("missing outbound tag: {tag}")))
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.outbounds.contains_key(tag)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use veex_core::{io::BoxedAsyncStream, session::SessionContext, ProxyError};

    use crate::{ExecutionFuture, ExecutionOutbound};

    use super::OutboundCatalog;

    struct TestOutbound {
        tag: String,
    }

    impl TestOutbound {
        fn new(tag: &str) -> Self {
            Self {
                tag: tag.to_string(),
            }
        }
    }

    impl ExecutionOutbound for TestOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }

        fn open_stream(&self, _ctx: &SessionContext) -> ExecutionFuture<'_, BoxedAsyncStream> {
            Box::pin(async { Err(ProxyError::protocol("unused")) })
        }
    }

    #[test]
    fn catalog_resolves_missing_detour_to_default_outbound() {
        let default_outbound: Arc<dyn ExecutionOutbound> = Arc::new(TestOutbound::new("direct"));
        let catalog = OutboundCatalog::new(HashMap::new(), Arc::clone(&default_outbound));

        let resolved = catalog.default_outbound();

        assert!(Arc::ptr_eq(&resolved, &default_outbound));
    }

    #[test]
    fn catalog_resolves_explicit_detour_without_using_default() {
        let explicit_outbound: Arc<dyn ExecutionOutbound> = Arc::new(TestOutbound::new("proxy"));
        let mut outbounds = HashMap::new();
        outbounds.insert("proxy".to_string(), Arc::clone(&explicit_outbound));
        let catalog = OutboundCatalog::new(outbounds, Arc::new(TestOutbound::new("direct")));

        let resolved = catalog
            .require("proxy")
            .expect("explicit detour should resolve");

        assert!(Arc::ptr_eq(&resolved, &explicit_outbound));
    }

    #[test]
    fn catalog_rejects_missing_explicit_detour() {
        let catalog = OutboundCatalog::new(HashMap::new(), Arc::new(TestOutbound::new("direct")));

        let err = match catalog.require("missing") {
            Ok(_) => panic!("missing explicit detour should remain an error"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("missing outbound tag: missing"));
    }
}
