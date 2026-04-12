use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    packet::PacketFrame,
    traits::BoxFuture,
    types::{Destination, Network},
    ProxyError, Result,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRequest {
    pub raw_message: Vec<u8>,
    pub protocol: Network,
    pub inbound_tag: String,
    pub peer: SocketAddr,
    pub destination: Destination,
}

impl DnsRequest {
    pub fn new(
        raw_message: Vec<u8>,
        protocol: Network,
        inbound_tag: impl Into<String>,
        peer: SocketAddr,
        destination: Destination,
    ) -> Self {
        Self {
            raw_message,
            protocol,
            inbound_tag: inbound_tag.into(),
            peer,
            destination,
        }
    }

    pub fn from_packet(packet: PacketFrame) -> Self {
        Self::new(
            packet.payload,
            packet.metadata.network,
            packet.metadata.inbound_tag,
            packet.metadata.peer,
            packet.metadata.destination,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResponse {
    pub raw_message: Vec<u8>,
}

impl DnsResponse {
    pub fn new(raw_message: Vec<u8>) -> Self {
        Self { raw_message }
    }
}

/// Runtime hook used by the packet dispatcher for `hijack-dns` final actions.
///
/// The DNS subsystem owns query parsing, dns.rules/dns.final server selection,
/// and short-lived upstream query execution. The packet dispatcher remains
/// responsible for client-facing write-back.
pub trait DnsExecutorHandle: Send + Sync {
    fn execute_query(&self, request: DnsRequest) -> BoxFuture<'_, DnsResponse>;
}

pub async fn read_dns_tcp_message<R>(reader: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut length_buf = [0u8; 2];
    let bytes_read = reader.read(&mut length_buf[..1]).await?;
    if bytes_read == 0 {
        return Ok(None);
    }

    reader.read_exact(&mut length_buf[1..]).await?;
    let length = u16::from_be_bytes(length_buf);
    if length == 0 {
        return Err(ProxyError::protocol(
            "dns over tcp frame length must be greater than zero",
        ));
    }

    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

pub async fn write_dns_tcp_message<W>(writer: &mut W, message: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let length = u16::try_from(message.len()).map_err(|_| {
        ProxyError::protocol(format!(
            "dns over tcp message exceeds 65535 bytes: {}",
            message.len()
        ))
    })?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(message).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{io::duplex, time::timeout};

    use super::{read_dns_tcp_message, write_dns_tcp_message};

    #[tokio::test]
    async fn tcp_dns_frame_round_trip_preserves_payload() {
        let (mut client, mut server) = duplex(64);
        let payload = b"\x12\x34payload".to_vec();

        let writer = tokio::spawn(async move {
            write_dns_tcp_message(&mut client, &payload)
                .await
                .expect("dns tcp frame should write");
        });
        let read = read_dns_tcp_message(&mut server)
            .await
            .expect("dns tcp frame should read")
            .expect("frame should exist");
        writer.await.expect("writer task should join");

        assert_eq!(read, b"\x12\x34payload");
    }

    #[tokio::test]
    async fn tcp_dns_frame_reports_none_on_clean_eof() {
        let (client, mut server) = duplex(64);
        drop(client);

        let read = timeout(Duration::from_secs(1), read_dns_tcp_message(&mut server))
            .await
            .expect("clean eof should not hang")
            .expect("clean eof should be accepted");

        assert!(read.is_none());
    }
}
