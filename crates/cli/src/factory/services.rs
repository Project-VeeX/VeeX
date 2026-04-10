use std::sync::Arc;

use veex_transport::{resolve_host, HostResolver};

#[derive(Clone)]
pub(crate) struct RuntimeServices {
    pub(crate) host_resolver: Arc<HostResolver>,
}

impl Default for RuntimeServices {
    fn default() -> Self {
        Self {
            host_resolver: Arc::new(|host, port| {
                Box::pin(async move { resolve_host(&host, port).await })
            }),
        }
    }
}
