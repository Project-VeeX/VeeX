use tokio::io::{AsyncRead, AsyncWrite};

/// A stream that supports both async read and async write operations.
/// All implementations must be Send-safe for use across task boundaries.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A type-erased boxed async stream.
pub type BoxedAsyncStream = Box<dyn AsyncStream>;
