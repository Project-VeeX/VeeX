use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    execution::packet::io::PacketFrame,
    portal::traits::BoxFuture,
    types::{Destination, Host, Network},
    ProxyError, Result,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRequest {
    pub raw_message: Vec<u8>,
    pub protocol: Network,
    pub inbound_tag: String,
    pub peer: SocketAddr,
    pub destination: Destination,
    pub session_id: Option<u64>,
    pub resolve_context: Option<ResolveContext>,
    /// DNS control-plane metadata.
    ///
    /// This field MUST NOT be propagated to outbound payload.
    /// It is only used internally by DNS resolution logic.
    pub resolution_domain: Option<String>,
    pub buffered_payload: Vec<u8>,
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
            session_id: None,
            resolve_context: None,
            resolution_domain: None,
            buffered_payload: Vec::new(),
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

    pub fn with_session_id(mut self, session_id: u64) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_resolve_context(mut self, context: ResolveContext) -> Self {
        self.resolve_context = Some(context);
        self
    }

    pub fn with_resolution_domain(mut self, domain: impl Into<String>) -> Self {
        self.resolution_domain = Some(domain.into());
        self
    }

    pub fn with_buffered_payload(mut self, buffered_payload: Vec<u8>) -> Self {
        self.buffered_payload = buffered_payload;
        self
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvePurpose {
    ClientQuery,
    OutboundDial,
    DnsUpstreamDial,
}

impl ResolvePurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientQuery => "client_query",
            Self::OutboundDial => "outbound_dial",
            Self::DnsUpstreamDial => "dns_upstream_dial",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveContext {
    pub purpose: ResolvePurpose,
    pub caller_outbound_tag: Option<String>,
    pub caller_dns_server_tag: Option<String>,
    pub explicit_server_tag: Option<String>,
    pub recursion_depth: u8,
}

impl ResolveContext {
    pub fn client_query() -> Self {
        Self {
            purpose: ResolvePurpose::ClientQuery,
            caller_outbound_tag: None,
            caller_dns_server_tag: None,
            explicit_server_tag: None,
            recursion_depth: 0,
        }
    }

    pub fn outbound_dial(
        caller_outbound_tag: impl Into<String>,
        explicit_server_tag: Option<String>,
    ) -> Self {
        Self {
            purpose: ResolvePurpose::OutboundDial,
            caller_outbound_tag: Some(caller_outbound_tag.into()),
            caller_dns_server_tag: None,
            explicit_server_tag,
            recursion_depth: 0,
        }
    }

    pub fn with_depth(mut self, recursion_depth: u8) -> Self {
        self.recursion_depth = recursion_depth;
        self
    }

    pub fn from_outbound_policy(
        existing: Option<&ResolveContext>,
        caller_outbound_tag: impl Into<String>,
        explicit_server_tag: Option<String>,
    ) -> Self {
        let caller_outbound_tag = caller_outbound_tag.into();

        match existing {
            Some(existing) => {
                let mut context = existing.clone();
                if context.caller_outbound_tag.is_none() {
                    context.caller_outbound_tag = Some(caller_outbound_tag);
                }
                if context.explicit_server_tag.is_none() {
                    context.explicit_server_tag = explicit_server_tag;
                }
                context
            }
            None => Self::outbound_dial(caller_outbound_tag, explicit_server_tag),
        }
    }

    pub fn for_dns_upstream_dial(
        &self,
        caller_outbound_tag: impl Into<String>,
        caller_dns_server_tag: impl Into<String>,
        explicit_server_tag: Option<String>,
    ) -> Self {
        Self {
            purpose: ResolvePurpose::DnsUpstreamDial,
            caller_outbound_tag: Some(caller_outbound_tag.into()),
            caller_dns_server_tag: Some(caller_dns_server_tag.into()),
            explicit_server_tag,
            recursion_depth: self.recursion_depth.saturating_add(1),
        }
    }
}

pub trait DomainResolverHandle: Send + Sync {
    fn resolve_host(
        &self,
        host: Host,
        port: u16,
        context: ResolveContext,
    ) -> BoxFuture<'_, Vec<SocketAddr>>;
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

    use super::{read_dns_tcp_message, write_dns_tcp_message, ResolveContext};

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

    #[test]
    fn outbound_policy_preserves_existing_explicit_resolver() {
        let parent = ResolveContext::outbound_dial("dns-detour", Some("bootstrap".into()));

        let context = ResolveContext::from_outbound_policy(
            Some(&parent),
            "proxy",
            Some("outbound-default".into()),
        );

        assert_eq!(context.caller_outbound_tag.as_deref(), Some("dns-detour"));
        assert_eq!(context.explicit_server_tag.as_deref(), Some("bootstrap"));
    }
}
