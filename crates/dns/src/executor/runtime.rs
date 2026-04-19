use std::{sync::Arc, time::Duration};

use veex_execution::OutboundCatalog;

use crate::{
    router::DnsServerRoute,
    traits::DnsUpstream,
    types::{DnsServer, DnsServerTransport},
    upstream::build_upstream,
};

use super::DnsExecutor;

pub(super) struct DnsServerRuntime {
    pub(super) server: DnsServer,
    pub(super) upstream: Arc<dyn DnsUpstream>,
}

impl DnsServerRuntime {
    pub(super) fn new(
        server: DnsServer,
        outbounds: &Arc<OutboundCatalog>,
        query_timeout: Duration,
    ) -> veex_core::Result<Self> {
        let dialer = match &server.transport {
            DnsServerTransport::Unsupported(_) => None,
            _ => Some(crate::dialer::DnsDialer::new(
                server.tag.clone(),
                server.dial.clone(),
                outbounds,
            )?),
        };
        let upstream = build_upstream(&server, dialer.clone(), query_timeout)?;
        Ok(Self { server, upstream })
    }
}

impl DnsExecutor {
    pub(super) fn server_routes(&self) -> Vec<DnsServerRoute<'_>> {
        self.servers
            .values()
            .map(|server| DnsServerRoute {
                tag: server.server.tag.as_str(),
                detour: server.server.outbound_tag(),
            })
            .collect()
    }

    pub(super) fn lookup_server(&self, server_tag: &str) -> veex_core::Result<&DnsServerRuntime> {
        self.servers.get(server_tag).ok_or_else(|| {
            veex_core::ProxyError::config(format!("missing dns server tag: {server_tag}"))
        })
    }

    pub(super) fn lookup_candidate_servers(
        &self,
        candidate_server_tags: &[String],
    ) -> veex_core::Result<Vec<&DnsServerRuntime>> {
        candidate_server_tags
            .iter()
            .map(|tag| self.lookup_server(tag))
            .collect()
    }
}
