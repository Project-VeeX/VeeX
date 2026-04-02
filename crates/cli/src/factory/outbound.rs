use std::{collections::HashMap, sync::Arc};

use veex_config::{OutboundConfig, ProxyConfig, TrojanTlsConfig};
use veex_core::Outbound;
use veex_outbound_direct::DirectOutbound;
use veex_outbound_trojan::TrojanOutbound;
use veex_transport::TlsClientOptions;

pub fn build_outbounds(config: &ProxyConfig) -> Result<HashMap<String, Arc<dyn Outbound>>, String> {
    let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();

    for outbound in &config.outbounds {
        match outbound {
            OutboundConfig::Direct(direct) => {
                let instance: Arc<dyn Outbound> = Arc::new(DirectOutbound::new(direct.tag.clone()));
                outbounds.insert(direct.tag.clone(), instance);
            }
            OutboundConfig::Trojan(trojan) => {
                let instance: Arc<dyn Outbound> = Arc::new(TrojanOutbound::new(
                    trojan.tag.clone(),
                    trojan.server.clone(),
                    trojan.server_port,
                    trojan.password.clone(),
                    tls_options_from_config(&trojan.tls),
                ));
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
    }
}
