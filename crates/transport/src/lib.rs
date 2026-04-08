//! Transport building blocks shared by outbound implementations.

pub mod tcp;
#[cfg(test)]
mod test_support;
pub mod tls;
pub mod verifier;

pub use tcp::{connect_host, connect_resolved_addresses, ConnectTraceContext, TcpConnectOptions};
pub use tls::{connect_tls, server_name_for_tls, TlsClientOptions, TlsError};
pub use verifier::{CertificateVerifierOptions, VerifierError};
