//! Transport building blocks shared by outbound implementations.

pub mod tcp;
pub mod tls;
pub mod verifier;

pub use tcp::{connect_host, ConnectTraceContext, TcpConnectOptions};
pub use tls::{connect_tls, server_name_for_tls, TlsClientOptions, TlsError};
pub use verifier::{CertificateVerifierOptions, VerifierError};
