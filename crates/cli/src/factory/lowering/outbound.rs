use veex_config::OutboundConfig;
use veex_core::{
    portal::{Dial, OutboundMeta},
    types::Destination,
};
use veex_transport::TlsClientOptions;

use crate::factory::lowering::shared::{lower_tls_options, parse_host};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredDirectOutbound {
    pub(crate) meta: OutboundMeta,
    pub(crate) dial: Dial,
}

#[derive(Clone, Debug)]
pub(crate) struct LoweredTrojanOutbound {
    pub(crate) meta: OutboundMeta,
    pub(crate) dial: Dial,
    pub(crate) upstream_addr: Destination,
    pub(crate) key: String,
    pub(crate) tls: TlsClientOptions,
}

#[derive(Clone, Debug)]
pub(crate) enum LoweredOutbound {
    Direct(LoweredDirectOutbound),
    Trojan(LoweredTrojanOutbound),
}

pub(crate) fn lower_outbound(outbound: &OutboundConfig) -> LoweredOutbound {
    match outbound {
        OutboundConfig::Direct(config) => LoweredOutbound::Direct(LoweredDirectOutbound {
            meta: OutboundMeta::new(config.tag.clone(), "direct"),
            dial: Dial {
                detour: None,
                connect_timeout: Some(config.connect_timeout),
                routing_mark: config.routing_mark,
                domain_resolver: config
                    .domain_resolver
                    .as_ref()
                    .map(|resolver| resolver.server.clone()),
            },
        }),
        OutboundConfig::Trojan(config) => LoweredOutbound::Trojan(LoweredTrojanOutbound {
            meta: OutboundMeta::new(config.tag.clone(), "trojan"),
            dial: Dial {
                detour: None,
                connect_timeout: Some(config.connect_timeout),
                routing_mark: None,
                domain_resolver: config
                    .domain_resolver
                    .as_ref()
                    .map(|resolver| resolver.server.clone()),
            },
            upstream_addr: Destination::new(parse_host(&config.server), config.server_port),
            key: config.password.clone(),
            tls: lower_tls_options(&config.tls),
        }),
    }
}
