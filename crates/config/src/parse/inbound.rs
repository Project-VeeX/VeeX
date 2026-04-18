use crate::{
    input::{InputInbound, InputInboundType},
    schema::{
        DirectInboundConfig, InboundConfig, RedirectInboundConfig, SocksInboundConfig,
        TProxyInboundConfig,
    },
};

pub(crate) fn input_inbound_into_config(input_config: InputInbound) -> InboundConfig {
    match input_config.kind {
        InputInboundType::Direct => InboundConfig::Direct(DirectInboundConfig {
            tag: input_config.tag,
            listen: input_config.listen,
            listen_port: input_config.listen_port,
            network: input_config.network,
            override_address: input_config.override_address,
            override_port: input_config.override_port,
        }),
        InputInboundType::Socks => InboundConfig::Socks(SocksInboundConfig {
            tag: input_config.tag,
            listen: input_config.listen,
            listen_port: input_config.listen_port,
        }),
        InputInboundType::Redirect => InboundConfig::Redirect(RedirectInboundConfig {
            tag: input_config.tag,
            listen: input_config.listen,
            listen_port: input_config.listen_port,
        }),
        InputInboundType::Tproxy => InboundConfig::TProxy(TProxyInboundConfig {
            tag: input_config.tag,
            listen: input_config.listen,
            listen_port: input_config.listen_port,
            network: input_config.network,
        }),
    }
}
