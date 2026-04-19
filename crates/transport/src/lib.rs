//! Transport building blocks shared by outbound implementations.

pub mod tcp;
pub mod tls;
pub mod verifier;

pub use tcp::{
    ConnectTraceContext, HostResolveRequest, HostResolver, TcpAttemptConnector, TcpConnectOptions,
    connect_host, connect_host_with_resolver, connect_resolved_addresses, resolve_host,
};
pub use tls::{TlsClientOptions, TlsError, connect_tls, connect_tls_stream, server_name_for_tls};
pub use verifier::{CertificateVerifierOptions, VerifierError};
