use std::{error::Error, fmt, io};

use veex_core::ProxyError;
use veex_infra_linux::TransparentError;

#[derive(Debug)]
pub enum TProxyError {
    UnsupportedPlatform,
    Transparent(TransparentError),
    Io(io::Error),
}

impl fmt::Display for TProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => f.write_str("tproxy inbound is only supported on linux"),
            Self::Transparent(err) => write!(f, "tproxy transparent socket error: {err}"),
            Self::Io(err) => write!(f, "tproxy inbound i/o error: {err}"),
        }
    }
}

impl Error for TProxyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transparent(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::UnsupportedPlatform => None,
        }
    }
}

impl From<io::Error> for TProxyError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<TransparentError> for TProxyError {
    fn from(value: TransparentError) -> Self {
        match value {
            TransparentError::UnsupportedPlatform => Self::UnsupportedPlatform,
            TransparentError::Io(err) => Self::Io(err),
            other => Self::Transparent(other),
        }
    }
}

impl From<TProxyError> for ProxyError {
    fn from(value: TProxyError) -> Self {
        match value {
            TProxyError::Io(err) => Self::Io(err),
            other => Self::Protocol(other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, TProxyError>;
