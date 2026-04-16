use tokio::net::TcpStream;
use veex_core::types::Destination;
use veex_infra_linux::{get_original_dst, get_tproxy_dst};

use super::{redirect::RedirectError, tproxy::TProxyError};

pub(crate) trait RedirectDestinationProvider: Send + Sync {
    fn destination_from_stream(
        &self,
        stream: &TcpStream,
    ) -> std::result::Result<Destination, RedirectError>;
}

pub(crate) trait TProxyDestinationProvider: Send + Sync {
    fn destination_from_stream(
        &self,
        stream: &TcpStream,
    ) -> std::result::Result<Destination, TProxyError>;
}

#[derive(Debug, Default)]
pub(crate) struct SocketRedirectDestinationProvider;

impl RedirectDestinationProvider for SocketRedirectDestinationProvider {
    fn destination_from_stream(
        &self,
        stream: &TcpStream,
    ) -> std::result::Result<Destination, RedirectError> {
        let destination = get_original_dst(stream)?;
        Ok(Destination::from_ip(destination.ip(), destination.port()))
    }
}

#[derive(Debug, Default)]
pub(crate) struct SocketTProxyDestinationProvider;

impl TProxyDestinationProvider for SocketTProxyDestinationProvider {
    fn destination_from_stream(
        &self,
        stream: &TcpStream,
    ) -> std::result::Result<Destination, TProxyError> {
        let destination = get_tproxy_dst(stream)?;
        Ok(Destination::from_ip(destination.ip(), destination.port()))
    }
}
