use std::{future::Future, pin::Pin, sync::Arc};

use crate::{
    error::Result,
    types::{BoxedAsyncStream, SessionContext},
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;

    fn connect(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream>;
}

pub trait Inbound: Send + Sync {
    fn tag(&self) -> &str;

    fn serve(self: Arc<Self>, dispatcher: Arc<dyn Dispatcher>) -> BoxFuture<'static, ()>;
}

pub trait Dispatcher: Send + Sync {
    fn dispatch(&self, inbound_stream: BoxedAsyncStream, ctx: SessionContext) -> BoxFuture<'_, ()>;
}
