use std::sync::Arc;

use veex_core::{logging::Logger, portal::Inbound, ProxyError};
use veex_execution::StreamDispatch;
use veex_portal_inbound::transparent::{
    create_redirect_stream_listener, create_tproxy_stream_listener,
};
use veex_portal_inbound::{RedirectInbound, TProxyInbound};

use crate::factory::lowering::{LoweredRedirectInbound, LoweredTProxyInbound};

pub(super) fn build_redirect_inbound(
    redirect: LoweredRedirectInbound,
    stream_sink: Arc<dyn StreamDispatch>,
) -> Result<Arc<dyn Inbound>, ProxyError> {
    let logger = Logger::new(redirect.meta.tag.clone(), redirect.meta.r#type.clone());
    let listener = create_redirect_stream_listener(redirect.listen);
    let instance = RedirectInbound::new(redirect.meta, logger, stream_sink, listener)?;
    Ok(instance as Arc<dyn Inbound>)
}

pub(super) fn build_tproxy_inbound(
    tproxy: LoweredTProxyInbound,
    stream_sink: Arc<dyn StreamDispatch>,
) -> Result<Arc<dyn Inbound>, ProxyError> {
    let logger = Logger::new(tproxy.meta.tag.clone(), tproxy.meta.r#type.clone());
    let listener = create_tproxy_stream_listener(tproxy.listen);
    let instance = TProxyInbound::new(tproxy.meta, logger, stream_sink, listener, tproxy.network)?;
    Ok(instance as Arc<dyn Inbound>)
}
