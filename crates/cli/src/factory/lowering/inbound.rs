use veex_config::InboundConfig;
use veex_core::{
    portal::{InboundMeta, Listen},
    types::{Host, Network},
};

use crate::factory::lowering::shared::{lower_listen_fields, parse_host};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredSocksInbound {
    pub(crate) meta: InboundMeta,
    pub(crate) listen: Listen,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LoweredDirectNetwork {
    Tcp,
    Udp,
    Both,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredDirectInbound {
    pub(crate) meta: InboundMeta,
    pub(crate) listen: Listen,
    pub(crate) network: LoweredDirectNetwork,
    pub(crate) override_host: Option<Host>,
    pub(crate) override_port: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredRedirectInbound {
    pub(crate) meta: InboundMeta,
    pub(crate) listen: Listen,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoweredTProxyInbound {
    pub(crate) meta: InboundMeta,
    pub(crate) listen: Listen,
    pub(crate) network: Network,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LoweredInbound {
    Direct(LoweredDirectInbound),
    Socks(LoweredSocksInbound),
    Redirect(LoweredRedirectInbound),
    TProxy(LoweredTProxyInbound),
}

pub(crate) fn lower_inbound(inbound: &InboundConfig) -> LoweredInbound {
    match inbound {
        InboundConfig::Direct(config) => LoweredInbound::Direct(LoweredDirectInbound {
            meta: InboundMeta::new(config.tag.clone(), "direct"),
            listen: lower_listen_fields(&config.listen),
            network: normalize_direct_network(config.network.as_deref()),
            override_host: config.override_address.as_deref().map(parse_host),
            override_port: config.override_port,
        }),
        InboundConfig::Socks(config) => LoweredInbound::Socks(LoweredSocksInbound {
            meta: InboundMeta::new(config.tag.clone(), "socks"),
            listen: lower_listen_fields(&config.listen),
        }),
        InboundConfig::Redirect(config) => LoweredInbound::Redirect(LoweredRedirectInbound {
            meta: InboundMeta::new(config.tag.clone(), "redirect"),
            listen: lower_listen_fields(&config.listen),
        }),
        InboundConfig::TProxy(config) => LoweredInbound::TProxy(LoweredTProxyInbound {
            meta: InboundMeta::new(config.tag.clone(), "tproxy"),
            listen: lower_listen_fields(&config.listen),
            network: normalize_tproxy_network(config.network.as_deref()),
        }),
    }
}

fn normalize_tproxy_network(_network: Option<&str>) -> Network {
    Network::Tcp
}

fn normalize_direct_network(network: Option<&str>) -> LoweredDirectNetwork {
    match network {
        Some("tcp") => LoweredDirectNetwork::Tcp,
        Some("udp") => LoweredDirectNetwork::Udp,
        None => LoweredDirectNetwork::Both,
        Some(_) => unreachable!("config validation should reject unsupported direct networks"),
    }
}
