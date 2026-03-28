use std::{error::Error, fmt, io};

use veex_core::ProxyError;

#[derive(Debug)]
pub enum SocksError {
    Io(io::Error),
    Protocol(String),
    UnsupportedAuthMethods,
    UnsupportedCommand(u8),
    UnsupportedAddressType(u8),
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "i/o error: {err}"),
            Self::Protocol(message) => write!(f, "protocol error: {message}"),
            Self::UnsupportedAuthMethods => f.write_str("no supported authentication method"),
            Self::UnsupportedCommand(cmd) => write!(f, "unsupported command: 0x{cmd:02x}"),
            Self::UnsupportedAddressType(atyp) => {
                write!(f, "unsupported address type: 0x{atyp:02x}")
            }
        }
    }
}

impl Error for SocksError {}

impl From<io::Error> for SocksError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<SocksError> for ProxyError {
    fn from(value: SocksError) -> Self {
        match value {
            SocksError::Io(err) => ProxyError::Io(err),
            SocksError::Protocol(message) => ProxyError::Protocol(message),
            SocksError::UnsupportedAuthMethods => {
                ProxyError::Protocol("no supported authentication method".into())
            }
            SocksError::UnsupportedCommand(cmd) => {
                ProxyError::Protocol(format!("unsupported SOCKS command: 0x{cmd:02x}"))
            }
            SocksError::UnsupportedAddressType(atyp) => {
                ProxyError::Protocol(format!("unsupported SOCKS address type: 0x{atyp:02x}"))
            }
        }
    }
}

