use std::sync::Arc;

use veex_core::{logging::Logger, portal::Inbound, ProxyError};
use veex_execution::StreamDispatch;
use veex_portal_inbound::{socks::create_socks_listener, SocksInbound};

use crate::factory::lowering::LoweredSocksInbound;

pub(super) fn build_socks_inbound(
    socks: LoweredSocksInbound,
    stream_sink: Arc<dyn StreamDispatch>,
) -> Result<Arc<dyn Inbound>, ProxyError> {
    let logger = Logger::new(socks.meta.tag.clone(), socks.meta.r#type.clone());
    let listener = create_socks_listener(socks.listen);
    let instance = SocksInbound::new(socks.meta, logger, stream_sink, listener)?;
    Ok(instance as Arc<dyn Inbound>)
}
