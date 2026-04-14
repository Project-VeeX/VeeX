use std::{collections::HashMap, sync::Arc};

use crate::{error::ProxyError, plane::outbound::PlaneOutbound};

/// Registry of dispatch-capable outbounds indexed by tag.
#[derive(Default)]
pub struct OutboundRegistry {
    outbounds: Vec<Arc<dyn PlaneOutbound>>,
    index_by_tag: HashMap<String, usize>,
}

impl OutboundRegistry {
    pub fn register(&mut self, outbound: Arc<dyn PlaneOutbound>) -> crate::Result<()> {
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

    pub fn get(&self, tag: &str) -> Option<Arc<dyn PlaneOutbound>> {
        self.index_by_tag
            .get(tag)
            .and_then(|index| self.outbounds.get(*index))
            .map(Arc::clone)
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

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Arc<dyn PlaneOutbound>> + '_ {
        self.outbounds.iter()
    }
}
