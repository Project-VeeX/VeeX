use std::{
    fs,
    io::{self, BufReader, Cursor},
    path::Path,
    sync::Arc,
};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("failed to access certificate file {path}: {source}")]
    Access {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("certificate path is not a file: {path}")]
    NotAFile { path: String },
    #[error("failed to read certificate file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse certificate file {path} as PEM/DER: {message}")]
    Parse { path: String, message: String },
    #[error("certificate file does not contain any certificates: {path}")]
    Empty { path: String },
    #[error("failed to load system root certificates: {message}")]
    LoadSystemRoots { message: String },
    #[error("failed to add system root certificate: {message}")]
    AddSystemRoot { message: String },
    #[error("failed to add certificate to root store: {message}")]
    AddToRootStore { message: String },
    #[error("failed to build webpki verifier: {message}")]
    BuildWebPki { message: String },
    #[error("failed to configure TLS protocol versions: {message}")]
    ConfigureProtocolVersions { message: String },
}

pub type Result<T> = std::result::Result<T, VerifierError>;

#[derive(Clone, Debug, Default)]
pub struct CertificateVerifierOptions {
    pub insecure: bool,
    pub certificate_path: Option<String>,
    pub ca_path: Option<String>,
}

pub fn validate_certificate_paths(options: &CertificateVerifierOptions) -> Result<()> {
    if let Some(path) = options.certificate_path.as_deref() {
        ensure_file_exists(path)?;
    }

    if let Some(path) = options.ca_path.as_deref() {
        ensure_file_exists(path)?;
    }

    Ok(())
}

pub fn build_client_config(options: &CertificateVerifierOptions) -> Result<ClientConfig> {
    validate_certificate_paths(options)?;

    let mut root_store = load_root_store()?;
    let pinned_certificate = match options.certificate_path.as_deref() {
        Some(path) => {
            let certificates = read_certificates(path)?;
            if certificates.is_empty() {
                return Err(VerifierError::Empty {
                    path: path.to_string(),
                });
            }
            add_certificates_to_root_store(&mut root_store, &certificates)?;
            Some(certificates[0].clone())
        }
        None => None,
    };

    if let Some(path) = options.ca_path.as_deref() {
        let certificates = read_certificates(path)?;
        add_certificates_to_root_store(&mut root_store, &certificates)?;
    }

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier: Arc<dyn ServerCertVerifier> = if options.insecure {
        Arc::new(NoCertificateVerification::new(
            provider.signature_verification_algorithms,
        ))
    } else if let Some(pinned_certificate) = pinned_certificate {
        let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store.clone()))
            .build()
            .map_err(|err| VerifierError::BuildWebPki {
                message: err.to_string(),
            })?;
        Arc::new(PinnedCertificateVerifier::new(
            inner,
            pinned_certificate,
            provider.signature_verification_algorithms,
        ))
    } else {
        rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|err| VerifierError::BuildWebPki {
                message: err.to_string(),
            })?
    };

    let config = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|err| VerifierError::ConfigureProtocolVersions {
            message: err.to_string(),
        })?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok(config)
}

fn load_root_store() -> Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();

    if native.certs.is_empty() && !native.errors.is_empty() {
        let details = native
            .errors
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(VerifierError::LoadSystemRoots { message: details });
    }

    for certificate in native.certs {
        root_store
            .add(certificate)
            .map_err(|err| VerifierError::AddSystemRoot {
                message: err.to_string(),
            })?;
    }

    Ok(root_store)
}

fn add_certificates_to_root_store(
    root_store: &mut RootCertStore,
    certificates: &[CertificateDer<'static>],
) -> Result<()> {
    for certificate in certificates {
        root_store
            .add(certificate.clone())
            .map_err(|err| VerifierError::AddToRootStore {
                message: err.to_string(),
            })?;
    }
    Ok(())
}

fn read_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let content = fs::read(path).map_err(|err| VerifierError::Read {
        path: path.to_string(),
        source: err,
    })?;
    read_certificates_from_slice(&content).map_err(|err| VerifierError::Parse {
        path: path.to_string(),
        message: err.to_string(),
    })
}

pub(crate) fn read_certificates_from_slice(
    content: &[u8],
) -> std::result::Result<Vec<CertificateDer<'static>>, RustlsError> {
    let mut reader = BufReader::new(Cursor::new(content));
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| RustlsError::General(format!("failed to read certificate PEM: {err}")))?;
    if !certificates.is_empty() {
        return Ok(certificates);
    }

    Ok(vec![CertificateDer::from(content.to_vec())])
}

fn ensure_file_exists(path: &str) -> Result<()> {
    let metadata = fs::metadata(Path::new(path)).map_err(|err| VerifierError::Access {
        path: path.to_string(),
        source: err,
    })?;
    if !metadata.is_file() {
        return Err(VerifierError::NotAFile {
            path: path.to_string(),
        });
    }
    Ok(())
}

#[derive(Debug)]
struct NoCertificateVerification {
    supported_algorithms: WebPkiSupportedAlgorithms,
}

impl NoCertificateVerification {
    fn new(supported_algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self {
            supported_algorithms,
        }
    }
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct PinnedCertificateVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    pinned_certificate: CertificateDer<'static>,
    supported_algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedCertificateVerifier {
    fn new(
        inner: Arc<dyn ServerCertVerifier>,
        pinned_certificate: CertificateDer<'static>,
        supported_algorithms: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            inner,
            pinned_certificate,
            supported_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        if end_entity.as_ref() != self.pinned_certificate.as_ref() {
            return Err(RustlsError::General(
                "server certificate did not match certificate_path".into(),
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algorithms.supported_schemes()
    }
}
