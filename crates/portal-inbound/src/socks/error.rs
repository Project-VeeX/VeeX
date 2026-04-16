use std::io;

use thiserror::Error;
use veex_core::ProxyError;

#[derive(Debug, Error)]
pub enum SocksError {
    #[error("i/o error: {0}")]
    Io(io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("no supported authentication method")]
    UnsupportedAuthMethods,
    #[error("unsupported command: 0x{0:02x}")]
    UnsupportedCommand(u8),
    #[error("unsupported address type: 0x{0:02x}")]
    UnsupportedAddressType(u8),
}

impl SocksError {
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }
}

impl From<io::Error> for SocksError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<SocksError> for ProxyError {
    fn from(value: SocksError) -> Self {
        match value {
            SocksError::Io(err) => ProxyError::Io(err),
            other => ProxyError::protocol(other.to_string()),
        }
    }
}
