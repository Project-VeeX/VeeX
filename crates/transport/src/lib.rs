//! Transport building blocks shared by outbound implementations.

pub mod tcp;
pub mod tls;
pub mod verifier;

pub use tcp::{
    connect_host, connect_host_with_resolver, connect_resolved_addresses, resolve_host,
    ConnectTraceContext, HostResolveRequest, HostResolver, TcpAttemptConnector, TcpConnectOptions,
};
pub use tls::{connect_tls, connect_tls_stream, server_name_for_tls, TlsClientOptions, TlsError};
pub use verifier::{CertificateVerifierOptions, VerifierError};
