use std::sync::{Arc, OnceLock};

use veex_core::{DomainResolverHandle, ProxyError};
use veex_transport::{resolve_host, HostResolveRequest, HostResolver};

#[derive(Clone)]
pub(crate) struct RuntimeServices {
    pub(crate) host_resolver: Arc<HostResolver>,
    domain_resolver: Arc<RuntimeDomainResolver>,
}

impl RuntimeServices {
    pub(crate) fn install_domain_resolver(
        &self,
        resolver: Arc<dyn DomainResolverHandle>,
    ) -> Result<(), ProxyError> {
        self.domain_resolver.install(resolver)
    }
}

impl Default for RuntimeServices {
    fn default() -> Self {
        let domain_resolver = Arc::new(RuntimeDomainResolver::default());
        let host_resolver = {
            let domain_resolver = Arc::clone(&domain_resolver);
            Arc::new(move |request: HostResolveRequest| {
                let domain_resolver = Arc::clone(&domain_resolver);
                Box::pin(async move { domain_resolver.resolve(request).await })
                    as std::pin::Pin<
                        Box<
                            dyn std::future::Future<
                                    Output = veex_core::Result<Vec<std::net::SocketAddr>>,
                                > + Send
                                + 'static,
                        >,
                    >
            }) as Arc<HostResolver>
        };

        Self {
            host_resolver,
            domain_resolver,
        }
    }
}

#[derive(Default)]
struct RuntimeDomainResolver {
    installed: OnceLock<Arc<dyn DomainResolverHandle>>,
}

impl RuntimeDomainResolver {
    fn install(&self, resolver: Arc<dyn DomainResolverHandle>) -> Result<(), ProxyError> {
        self.installed
            .set(resolver)
            .map_err(|_| ProxyError::protocol("domain resolver is already installed"))
    }

    async fn resolve(
        &self,
        request: HostResolveRequest,
    ) -> veex_core::Result<Vec<std::net::SocketAddr>> {
        match self.installed.get() {
            Some(resolver) => {
                resolver
                    .resolve_host(request.host, request.port, request.context)
                    .await
            }
            None => resolve_host(&request.host, request.port).await,
        }
    }
}
