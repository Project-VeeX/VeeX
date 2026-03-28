use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use veex_core::{BoxedAsyncStream, Host, ProxyError, Result};

use crate::verifier::{
    build_client_config, validate_certificate_paths, CertificateVerifierOptions,
};

#[derive(Clone, Debug, Default)]
pub struct TlsClientOptions {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub disable_sni: bool,
    pub insecure: bool,
    pub certificate_path: Option<String>,
    pub ca_path: Option<String>,
}

impl TlsClientOptions {
    pub fn validate(&self) -> Result<()> {
        if self.disable_sni && !self.insecure && self.server_name.is_none() {
            return Err(ProxyError::Config(
                "disable_sni=true requires an explicit server_name or insecure=true".into(),
            ));
        }

        validate_certificate_paths(&CertificateVerifierOptions {
            insecure: self.insecure,
            certificate_path: self.certificate_path.clone(),
            ca_path: self.ca_path.clone(),
        })?;

        Ok(())
    }
}

pub fn server_name_for_tls(host: &Host, options: &TlsClientOptions) -> Result<String> {
    if let Some(server_name) = &options.server_name {
        return Ok(server_name.clone());
    }

    match host {
        Host::Domain(domain) => Ok(domain.clone()),
        Host::Ip(ip) => {
            if options.insecure {
                Ok(ip.to_string())
            } else {
                Err(ProxyError::Config(
                    "tls server_name is required when using an IP address with certificate verification".into(),
                ))
            }
        }
    }
}

pub async fn connect_tls(
    stream: TcpStream,
    host: &Host,
    options: &TlsClientOptions,
) -> Result<BoxedAsyncStream> {
    if !options.enabled {
        return Ok(Box::new(stream));
    }

    options.validate()?;
    let server_name = server_name_for_tls(host, options)?;
    let mut config = build_client_config(&CertificateVerifierOptions {
        insecure: options.insecure,
        certificate_path: options.certificate_path.clone(),
        ca_path: options.ca_path.clone(),
    })?;
    config.enable_sni = !options.disable_sni;

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(server_name)
        .map_err(|err| ProxyError::Config(format!("invalid tls server_name: {err}")))?;

    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|err| ProxyError::Tls(format!("tls handshake failed: {err}")))?;

    Ok(Box::new(stream))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::IpAddr,
        path::PathBuf,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rcgen::generate_simple_self_signed;
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::TlsAcceptor;
    use veex_core::Host;

    use super::{connect_tls, server_name_for_tls, TlsClientOptions};

    #[test]
    fn derives_server_name_from_domain() {
        let name = server_name_for_tls(
            &Host::Domain("example.com".into()),
            &TlsClientOptions::default(),
        )
        .expect("domain host should derive server name");

        assert_eq!(name, "example.com");
    }

    #[test]
    fn rejects_ip_without_explicit_server_name_when_verifying() {
        let err = server_name_for_tls(
            &Host::Ip(IpAddr::from([127, 0, 0, 1])),
            &TlsClientOptions::default(),
        )
        .expect_err("ip host without insecure mode should fail");

        assert!(err.to_string().contains("server_name"));
    }

    #[tokio::test]
    async fn connects_with_insecure_tls() {
        let server = spawn_tls_server("localhost").await;
        let stream = tokio::net::TcpStream::connect(server.addr)
            .await
            .expect("tcp connect should succeed");

        let mut stream = connect_tls(
            stream,
            &Host::Domain("localhost".into()),
            &TlsClientOptions {
                enabled: true,
                insecure: true,
                ..TlsClientOptions::default()
            },
        )
        .await
        .expect("insecure tls should connect");

        stream
            .write_all(b"ping")
            .await
            .expect("client write should succeed");

        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .await
            .expect("client read should succeed");
        assert_eq!(&response, b"pong");
    }

    #[tokio::test]
    async fn connects_with_ca_path() {
        let server = spawn_tls_server("localhost").await;
        let stream = tokio::net::TcpStream::connect(server.addr)
            .await
            .expect("tcp connect should succeed");

        let mut stream = connect_tls(
            stream,
            &Host::Domain("localhost".into()),
            &TlsClientOptions {
                enabled: true,
                ca_path: Some(server.certificate_path.to_string_lossy().into_owned()),
                ..TlsClientOptions::default()
            },
        )
        .await
        .expect("ca_path should trust the self-signed certificate");

        stream
            .write_all(b"ping")
            .await
            .expect("client write should succeed");

        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .await
            .expect("client read should succeed");
        assert_eq!(&response, b"pong");
    }

    #[tokio::test]
    async fn connects_with_certificate_path_pin() {
        let server = spawn_tls_server("localhost").await;
        let stream = tokio::net::TcpStream::connect(server.addr)
            .await
            .expect("tcp connect should succeed");

        let mut stream = connect_tls(
            stream,
            &Host::Domain("localhost".into()),
            &TlsClientOptions {
                enabled: true,
                certificate_path: Some(server.certificate_path.to_string_lossy().into_owned()),
                ..TlsClientOptions::default()
            },
        )
        .await
        .expect("certificate_path should pin the server certificate");

        stream
            .write_all(b"ping")
            .await
            .expect("client write should succeed");

        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .await
            .expect("client read should succeed");
        assert_eq!(&response, b"pong");
    }

    struct TestTlsServer {
        addr: std::net::SocketAddr,
        certificate_path: PathBuf,
    }

    impl Drop for TestTlsServer {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.certificate_path);
        }
    }

    async fn spawn_tls_server(server_name: &str) -> TestTlsServer {
        let certified = generate_simple_self_signed(vec![server_name.to_string()])
            .expect("certificate generation should succeed");
        let certificate = certified.cert.der().clone();
        let key = certified.key_pair.serialize_der();
        let certificate_path = write_temp_certificate(certificate.as_ref());

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate.as_ref().to_vec())],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)),
            )
            .expect("server config should build");

        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener bind should succeed");
        let addr = listener.local_addr().expect("listener addr should exist");
        let acceptor = TlsAcceptor::from(Arc::new(config));

        tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("listener accept should succeed");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("tls accept should succeed");

            let mut request = [0u8; 4];
            stream
                .read_exact(&mut request)
                .await
                .expect("server read should succeed");
            assert_eq!(&request, b"ping");

            stream
                .write_all(b"pong")
                .await
                .expect("server write should succeed");
        });

        TestTlsServer {
            addr,
            certificate_path,
        }
    }

    fn write_temp_certificate(certificate_der: &[u8]) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("veex-transport-test-{nanos}.pem"));
        let pem = pem_encode_certificate(certificate_der);
        fs::write(&path, pem).expect("temporary certificate should be written");
        path
    }

    fn pem_encode_certificate(certificate_der: &[u8]) -> String {
        let mut encoded = String::new();
        encoded.push_str("-----BEGIN CERTIFICATE-----\n");

        for chunk in base64_encode(certificate_der).as_bytes().chunks(64) {
            encoded.push_str(std::str::from_utf8(chunk).expect("base64 must be valid utf-8"));
            encoded.push('\n');
        }

        encoded.push_str("-----END CERTIFICATE-----\n");
        encoded
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
        let mut index = 0;
        while index < bytes.len() {
            let b0 = bytes[index];
            let b1 = bytes.get(index + 1).copied();
            let b2 = bytes.get(index + 2).copied();

            output.push(TABLE[(b0 >> 2) as usize] as char);
            output.push(TABLE[(((b0 & 0x03) << 4) | (b1.unwrap_or(0) >> 4)) as usize] as char);

            match (b1, b2) {
                (Some(b1), Some(b2)) => {
                    output.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
                    output.push(TABLE[(b2 & 0x3f) as usize] as char);
                }
                (Some(b1), None) => {
                    output.push(TABLE[((b1 & 0x0f) << 2) as usize] as char);
                    output.push('=');
                }
                (None, _) => {
                    output.push('=');
                    output.push('=');
                }
            }

            index += 3;
        }

        output
    }
}
