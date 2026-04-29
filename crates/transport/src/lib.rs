//! Transport building blocks shared by outbound implementations.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectTraceContext {
    pub session_id: u64,
    pub outbound: String,
    pub routing_mark: Option<u32>,
}

impl ConnectTraceContext {
    pub fn new(session_id: u64, outbound: impl Into<String>, routing_mark: Option<u32>) -> Self {
        Self {
            session_id,
            outbound: outbound.into(),
            routing_mark,
        }
    }
}

pub mod tcp;
pub mod tls;
pub mod verifier;

pub use tcp::{
    HostResolveRequest, HostResolver, TcpAttemptConnector, TcpConnectOptions, connect_host,
    connect_host_with_resolver, connect_resolved_addresses, resolve_host,
};
pub use tls::{OutboundTls, TlsError, connect_tls, connect_tls_stream, server_name_for_tls};
pub use verifier::{CertificateVerifierOptions, VerifierError};
