use std::{error::Error, fmt, io};

pub use veex_observability::ErrorKind;

#[derive(Debug)]
pub enum ProxyError {
    Config(String),
    Dial(String),
    Resolve(String),
    Tls(String),
    Protocol(String),
    Relay(String),
    Timeout(String),
    Io(io::Error),
    Shutdown,
}

impl ProxyError {
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

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Dial(msg) => write!(f, "dial error: {msg}"),
            Self::Resolve(msg) => write!(f, "resolve error: {msg}"),
            Self::Tls(msg) => write!(f, "tls error: {msg}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::Relay(msg) => write!(f, "relay error: {msg}"),
            Self::Timeout(msg) => write!(f, "timeout error: {msg}"),
            Self::Io(err) => write!(f, "i/o error: {err}"),
            Self::Shutdown => f.write_str("shutdown requested"),
        }
    }
}

impl Error for ProxyError {}

impl From<io::Error> for ProxyError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;
