use std::{error::Error, fmt, io};

use veex_core::ProxyError;

#[derive(Debug)]
pub enum DirectError {
    Io(io::Error),
}

impl fmt::Display for DirectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "direct inbound i/o error: {err}"),
        }
    }
}

impl Error for DirectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
        }
    }
}

impl From<io::Error> for DirectError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<DirectError> for ProxyError {
    fn from(value: DirectError) -> Self {
        match value {
            DirectError::Io(err) => Self::Io(err),
        }
    }
}

pub type Result<T> = std::result::Result<T, DirectError>;
