use veex_config::OutboundConfig;
use veex_core::{
    portal::{Dial, OutboundMeta},
    types::Destination,
};
use veex_transport::OutboundTls;

use crate::factory::lowering::shared::{lower_dial_fields, lower_tls_fields, parse_host};

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
    pub(crate) tls: OutboundTls,
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
            dial: lower_dial_fields(&config.dial),
        }),
        OutboundConfig::Trojan(config) => LoweredOutbound::Trojan(LoweredTrojanOutbound {
            meta: OutboundMeta::new(config.tag.clone(), "trojan"),
            dial: lower_dial_fields(&config.dial),
            upstream_addr: Destination::new(parse_host(&config.server), config.server_port),
            key: config.password.clone(),
            tls: lower_tls_fields(&config.tls),
        }),
    }
}
