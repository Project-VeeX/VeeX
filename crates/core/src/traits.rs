use std::{future::Future, pin::Pin, sync::Arc};

use crate::{
    error::Result,
    types::{BoxedAsyncStream, SessionContext},
};

/// A boxed future that is Send-safe, returned by trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Outbound connection handler.
///
/// Implementors handle establishing connections to remote destinations.
/// All implementations must be Send + Sync as they may be accessed concurrently
/// from multiple tasks.
pub trait Outbound: Send + Sync {
    /// Returns the tag identifying this outbound, used in route decisions.
    fn tag(&self) -> &str;

    /// Establishes a connection to the destination described by `ctx`.
    ///
    /// Returns a boxed async stream representing the established connection.
    fn connect(&self, ctx: &SessionContext) -> BoxFuture<'_, BoxedAsyncStream>;
}

/// Inbound connection listener.
///
/// Implementors accept incoming connections and dispatch them to the dispatcher.
/// The `serve` method consumes `self` via `Arc<Self>` because it starts an
/// accept loop that runs until shutdown — an inbound instance cannot be reused
/// after `serve` is called.
///
/// All implementations must be Send + Sync.
pub trait Inbound: Send + Sync {
    /// Returns the tag identifying this inbound.
    fn tag(&self) -> &str;

    /// Starts the accept loop, consuming the inbound instance.
    ///
    /// The returned future resolves when the inbound shuts down.
    /// Consumes `self` via `Arc<Self>` — this instance cannot call `serve`
    /// again after the returned future is spawned.
    fn serve(self: Arc<Self>, dispatcher: Arc<dyn Dispatcher>) -> BoxFuture<'static, ()>;
}

/// Session dispatcher.
///
/// Implementors route inbound sessions to appropriate outbounds based on
/// routing decisions. All implementations must be Send + Sync.
pub trait Dispatcher: Send + Sync {
    /// Dispatches an inbound session to the appropriate outbound.
    ///
    /// The `inbound_stream` is the established client connection, and `ctx`
    /// contains session metadata including destination and routing information.
    fn dispatch(&self, inbound_stream: BoxedAsyncStream, ctx: SessionContext) -> BoxFuture<'_, ()>;
}
