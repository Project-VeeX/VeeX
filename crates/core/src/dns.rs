use crate::{packet::PacketFrame, traits::BoxFuture};

/// Runtime hook used by the packet dispatcher for `hijack-dns` final actions.
///
/// The DNS subsystem owns query parsing, dns.rules/dns.final server selection,
/// and short-lived upstream query execution. The packet dispatcher remains
/// responsible for client-facing write-back.
pub trait DnsExecutorHandle: Send + Sync {
    fn execute_query(&self, packet: PacketFrame) -> BoxFuture<'_, Vec<u8>>;
}
