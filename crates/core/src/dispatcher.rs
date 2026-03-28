use std::{collections::HashMap, sync::Arc};

use veex_observability::{emit_session_summary, SessionSummary};

use crate::{
    error::ProxyError,
    relay::relay_bidirectional,
    router::Router,
    traits::{BoxFuture, Dispatcher, Outbound},
    types::{BoxedAsyncStream, SessionContext},
};

pub struct SimpleDispatcher {
    router: Router,
    outbounds: HashMap<String, Arc<dyn Outbound>>,
}

impl SimpleDispatcher {
    pub fn new(router: Router, outbounds: HashMap<String, Arc<dyn Outbound>>) -> Self {
        Self { router, outbounds }
    }
}

impl Dispatcher for SimpleDispatcher {
    fn dispatch(&self, inbound_stream: BoxedAsyncStream, ctx: SessionContext) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let decision = self.router.select(&ctx);
            let outbound_tag = decision.outbound_tag.clone();
            let outbound = self.outbounds.get(&decision.outbound_tag).ok_or_else(|| {
                ProxyError::Config(format!("missing outbound tag: {}", decision.outbound_tag))
            })?;

            let result: crate::Result<_> = async {
                let outbound_stream = outbound.connect(&ctx).await?;
                let stats = relay_bidirectional(inbound_stream, outbound_stream).await?;
                Ok(stats)
            }
            .await;

            let summary = match &result {
                Ok(stats) => SessionSummary::succeeded(
                    ctx.meta.id,
                    ctx.meta.inbound_tag.as_str(),
                    outbound_tag.as_str(),
                    ctx.meta.peer.to_string(),
                    ctx.meta.destination.to_string(),
                    stats.bytes_up,
                    stats.bytes_down,
                    ctx.meta.start.elapsed(),
                ),
                Err(err) => SessionSummary::succeeded(
                    ctx.meta.id,
                    ctx.meta.inbound_tag.as_str(),
                    outbound_tag.as_str(),
                    ctx.meta.peer.to_string(),
                    ctx.meta.destination.to_string(),
                    0,
                    0,
                    ctx.meta.start.elapsed(),
                )
                .failed(format!("{:?}", err.kind()).to_ascii_lowercase()),
            };

            emit_session_summary(&summary);
            result.map(|_| ())
        })
    }
}
