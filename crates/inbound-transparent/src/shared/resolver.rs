use tokio::net::TcpStream;
use veex_core::Destination;
use veex_infra_linux::{get_original_dst, get_tproxy_dst};

use crate::{RedirectError, TProxyError};

pub(crate) trait RedirectDestinationResolver: Send + Sync {
    fn resolve_redirect(
        &self,
        stream: &TcpStream,
    ) -> std::result::Result<Destination, RedirectError>;
}

pub(crate) trait TProxyDestinationResolver: Send + Sync {
    fn resolve_tproxy(&self, stream: &TcpStream) -> std::result::Result<Destination, TProxyError>;
}

#[derive(Debug, Default)]
pub(crate) struct SocketRedirectDestinationResolver;

impl RedirectDestinationResolver for SocketRedirectDestinationResolver {
    fn resolve_redirect(
        &self,
        stream: &TcpStream,
    ) -> std::result::Result<Destination, RedirectError> {
        let destination = get_original_dst(stream)?;
        Ok(Destination::from_ip(destination.ip(), destination.port()))
    }
}

#[derive(Debug, Default)]
pub(crate) struct SocketTProxyDestinationResolver;

impl TProxyDestinationResolver for SocketTProxyDestinationResolver {
    fn resolve_tproxy(&self, stream: &TcpStream) -> std::result::Result<Destination, TProxyError> {
        let destination = get_tproxy_dst(stream)?;
        Ok(Destination::from_ip(destination.ip(), destination.port()))
    }
}
