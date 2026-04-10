use std::{collections::HashMap, sync::Arc};

use veex_config::ProxyConfig;
use veex_core::{Outbound, ProxyError};
use veex_outbound_direct::DirectOutbound;
use veex_outbound_trojan::TrojanOutbound;
use veex_transport::connect_host_with_resolver;

use crate::factory::{lower_outbound, LoweredOutbound, RuntimeServices};

pub fn build_outbounds(
    config: &ProxyConfig,
    services: &RuntimeServices,
) -> Result<HashMap<String, Arc<dyn Outbound>>, ProxyError> {
    let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();

    for outbound in config.outbounds.iter().map(lower_outbound) {
        match outbound {
            LoweredOutbound::Direct(direct) => {
                let instance: Arc<dyn Outbound> = Arc::new(DirectOutbound::new_with_resolver(
                    direct.tag.clone(),
                    direct.routing_mark,
                    direct.connect_timeout,
                    Arc::clone(&services.host_resolver),
                )?);
                outbounds.insert(direct.tag, instance);
            }
            LoweredOutbound::Trojan(trojan) => {
                let host_resolver = Arc::clone(&services.host_resolver);
                let instance = TrojanOutbound::new_with_connector(
                    trojan.tag.clone(),
                    trojan.server,
                    trojan.server_port,
                    trojan.password,
                    trojan.connect_timeout,
                    trojan.tls,
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
                outbounds.insert(trojan.tag, instance);
            }
        }
    }

    Ok(outbounds)
}
