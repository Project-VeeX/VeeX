use std::{collections::HashMap, sync::Arc};

use veex_config::{OutboundConfig, ProxyConfig, TrojanTlsConfig};
use veex_core::{Outbound, ProxyError};
use veex_outbound_direct::DirectOutbound;
use veex_outbound_trojan::TrojanOutbound;
use veex_transport::{connect_host_with_resolver, TlsClientOptions};

use crate::factory::RuntimeServices;

pub fn build_outbounds(
    config: &ProxyConfig,
    services: &RuntimeServices,
) -> Result<HashMap<String, Arc<dyn Outbound>>, ProxyError> {
    let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();

    for outbound in &config.outbounds {
        match outbound {
            OutboundConfig::Direct(direct) => {
                let instance: Arc<dyn Outbound> = Arc::new(DirectOutbound::new_with_resolver(
                    direct.tag.clone(),
                    direct.routing_mark,
                    direct.connect_timeout,
                    Arc::clone(&services.host_resolver),
                )?);
                outbounds.insert(direct.tag.clone(), instance);
            }
            OutboundConfig::Trojan(trojan) => {
                let host_resolver = Arc::clone(&services.host_resolver);
                let instance = TrojanOutbound::new_with_connector(
                    trojan.tag.clone(),
                    trojan.server.clone(),
                    trojan.server_port,
                    trojan.password.clone(),
                    trojan.connect_timeout,
                    tls_options_from_config(&trojan.tls),
                    move |host, port, options| {
                        let host_resolver = Arc::clone(&host_resolver);
                        Box::pin(async move {
                            connect_host_with_resolver(&host, port, host_resolver.as_ref(), options)
                                .await
                        })
                    },
                );
                instance.validate()?;
                let instance: Arc<dyn Outbound> = Arc::new(instance);
                outbounds.insert(trojan.tag.clone(), instance);
            }
        }
    }

    Ok(outbounds)
}

fn tls_options_from_config(config: &TrojanTlsConfig) -> TlsClientOptions {
    TlsClientOptions {
        enabled: config.enabled,
        server_name: config.server_name.clone(),
        disable_sni: config.disable_sni,
        insecure: config.insecure,
        certificate_path: config.certificate_path.clone(),
        ca_path: config.ca_path.clone(),
        handshake_timeout: config.handshake_timeout,
    }
}
