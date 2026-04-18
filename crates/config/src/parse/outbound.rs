use crate::{
    defaults::DEFAULT_CONNECT_TIMEOUT,
    error::ConfigError,
    input::{InputOutbound, InputOutboundType},
    schema::{DirectOutboundConfig, OutboundConfig, TrojanOutboundConfig},
};

use super::shared::{
    input_trojan_tls_into_config, input_trojan_tls_or_default, optional_domain_resolver,
    required_nested_port, required_nested_string,
};

pub(crate) fn input_outbound_into_config(
    input_config: InputOutbound,
    index: usize,
) -> Result<OutboundConfig, ConfigError> {
    match input_config.kind {
        InputOutboundType::Direct => Ok(OutboundConfig::Direct(DirectOutboundConfig {
            tag: input_config.tag,
            connect_timeout: input_config
                .connect_timeout
                .unwrap_or(DEFAULT_CONNECT_TIMEOUT),
            routing_mark: input_config.routing_mark,
            domain_resolver: optional_domain_resolver(
                input_config.domain_resolver,
                format!("$.outbounds[{index}].domain_resolver"),
            )?,
        })),
        InputOutboundType::Trojan => Ok(OutboundConfig::Trojan(TrojanOutboundConfig {
            tag: input_config.tag,
            server: required_nested_string(
                input_config.server,
                format!("$.outbounds[{index}].server"),
            )?,
            server_port: required_nested_port(
                input_config.server_port,
                format!("$.outbounds[{index}].server_port"),
            )?,
            password: required_nested_string(
                input_config.password,
                format!("$.outbounds[{index}].password"),
            )?,
            connect_timeout: input_config
                .connect_timeout
                .unwrap_or(DEFAULT_CONNECT_TIMEOUT),
            domain_resolver: optional_domain_resolver(
                input_config.domain_resolver,
                format!("$.outbounds[{index}].domain_resolver"),
            )?,
            tls: input_trojan_tls_into_config(input_trojan_tls_or_default(
                input_config.tls,
                format!("$.outbounds[{index}].tls"),
            )?),
        })),
    }
}
