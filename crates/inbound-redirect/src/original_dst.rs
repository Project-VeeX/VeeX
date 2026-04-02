use tokio::net::TcpStream;
use veex_core::Destination;
use veex_infra_linux::get_original_dst as get_original_dst_socket;

pub use veex_infra_linux::{IP6T_SO_ORIGINAL_DST, SO_ORIGINAL_DST};

use crate::error::Result;

pub fn resolve_original_dst(stream: &TcpStream) -> Result<Destination> {
    let destination = get_original_dst_socket(stream)?;
    Ok(Destination::from_ip(destination.ip(), destination.port()))
}
