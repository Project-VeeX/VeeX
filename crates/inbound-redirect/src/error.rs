use std::{error::Error, fmt, io};

use veex_core::ProxyError;

#[derive(Debug)]
pub enum RedirectError {
    UnsupportedPlatform,
    GetSockOpt {
        level: i32,
        option: i32,
        source: io::Error,
    },
    UnexpectedSockAddrLen {
        expected: usize,
        actual: usize,
    },
    UnsupportedAddressFamily(i32),
    Io(io::Error),
}

impl fmt::Display for RedirectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => f.write_str("redirect inbound is only supported on linux"),
            Self::GetSockOpt {
                level,
                option,
                source,
            } => write!(
                f,
                "getsockopt(level={level}, option={option}) failed: {source}"
            ),
            Self::UnexpectedSockAddrLen { expected, actual } => write!(
                f,
                "getsockopt returned sockaddr length {actual}, expected at least {expected}"
            ),
            Self::UnsupportedAddressFamily(family) => {
                write!(
                    f,
                    "unsupported sockaddr family returned by getsockopt: {family}"
                )
            }
            Self::Io(err) => write!(f, "redirect inbound i/o error: {err}"),
        }
    }
}

impl Error for RedirectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::GetSockOpt { source, .. } => Some(source),
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for RedirectError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<RedirectError> for ProxyError {
    fn from(value: RedirectError) -> Self {
        match value {
            RedirectError::Io(err) => Self::Io(err),
            other => Self::Protocol(other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, RedirectError>;
