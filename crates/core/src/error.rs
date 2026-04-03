use std::{fmt, io};

use thiserror::Error;

pub use veex_observability::ErrorKind;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("dial error: {0}")]
    Dial(String),
    #[error("resolve error: {0}")]
    Resolve(String),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("relay error: {0}")]
    Relay(String),
    #[error("timeout error: {0}")]
    Timeout(String),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("shutdown requested")]
    Shutdown,
}

impl ProxyError {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn config_ctx(context: impl fmt::Display, source: impl fmt::Display) -> Self {
        Self::Config(with_context(context, source))
    }

    pub fn dial(message: impl Into<String>) -> Self {
        Self::Dial(message.into())
    }

    pub fn dial_ctx(context: impl fmt::Display, source: impl fmt::Display) -> Self {
        Self::Dial(with_context(context, source))
    }

    pub fn resolve(message: impl Into<String>) -> Self {
        Self::Resolve(message.into())
    }

    pub fn resolve_ctx(context: impl fmt::Display, source: impl fmt::Display) -> Self {
        Self::Resolve(with_context(context, source))
    }

    pub fn tls(message: impl Into<String>) -> Self {
        Self::Tls(message.into())
    }

    pub fn tls_ctx(context: impl fmt::Display, source: impl fmt::Display) -> Self {
        Self::Tls(with_context(context, source))
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    pub fn protocol_ctx(context: impl fmt::Display, source: impl fmt::Display) -> Self {
        Self::Protocol(with_context(context, source))
    }

    pub fn relay(message: impl Into<String>) -> Self {
        Self::Relay(message.into())
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::Timeout(message.into())
    }

    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Config(_) => ErrorKind::Config,
            Self::Dial(_) => ErrorKind::Dial,
            Self::Resolve(_) => ErrorKind::Resolve,
            Self::Tls(_) => ErrorKind::Tls,
            Self::Protocol(_) => ErrorKind::Protocol,
            Self::Relay(_) => ErrorKind::Relay,
            Self::Timeout(_) => ErrorKind::Timeout,
            Self::Io(_) => ErrorKind::Io,
            Self::Shutdown => ErrorKind::Shutdown,
        }
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;

fn with_context(context: impl fmt::Display, source: impl fmt::Display) -> String {
    format!("{context}: {source}")
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io};

    use super::{ErrorKind, ProxyError};

    #[test]
    fn error_kind_mapping_remains_stable() {
        let cases = [
            (ProxyError::config("bad config"), ErrorKind::Config),
            (ProxyError::dial("dial failed"), ErrorKind::Dial),
            (ProxyError::resolve("resolve failed"), ErrorKind::Resolve),
            (ProxyError::tls("tls failed"), ErrorKind::Tls),
            (ProxyError::protocol("protocol failed"), ErrorKind::Protocol),
            (ProxyError::relay("relay failed"), ErrorKind::Relay),
            (ProxyError::timeout("timeout failed"), ErrorKind::Timeout),
            (ProxyError::from(io::Error::other("disk")), ErrorKind::Io),
            (ProxyError::Shutdown, ErrorKind::Shutdown),
        ];

        for (error, expected) in cases {
            assert_eq!(error.kind(), expected);
        }
    }

    #[test]
    fn contextual_helpers_keep_high_frequency_error_messages_stable() {
        let err = ProxyError::dial_ctx("tcp connect failed", "connection refused");
        assert_eq!(err.kind(), ErrorKind::Dial);
        assert!(err.to_string().contains("tcp connect failed"));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn io_error_keeps_source_chain() {
        let err = ProxyError::from(io::Error::other("broken pipe"));
        let source = err.source().expect("i/o error should expose source");
        assert!(source.to_string().contains("broken pipe"));
    }
}
