use tokio::io::copy_bidirectional;

use crate::{error::{ProxyError, Result}, types::BoxedAsyncStream};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayStats {
    pub bytes_up: u64,
    pub bytes_down: u64,
}

pub async fn relay_bidirectional(
    mut inbound_stream: BoxedAsyncStream,
    mut outbound_stream: BoxedAsyncStream,
) -> Result<RelayStats> {
    let (bytes_up, bytes_down) = copy_bidirectional(&mut inbound_stream, &mut outbound_stream)
        .await
        .map_err(|err| ProxyError::Relay(err.to_string()))?;

    Ok(RelayStats {
        bytes_up,
        bytes_down,
    })
}

