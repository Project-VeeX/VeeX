use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rcgen::generate_simple_self_signed;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{io::AsyncReadExt, net::TcpListener};
use tokio_rustls::TlsAcceptor;
use veex_core::{
    logging::Logger,
    portal::{Dial, OutboundMeta, ProxyOutbound},
    session::{SessionContext, SessionMeta},
    types::{Destination, Host, Network},
};
use veex_portal_outbound::trojan::{
    TrojanOutbound, build_dialer, build_trojan_request, system_host_resolver,
};
use veex_transport::OutboundTls;

#[tokio::test]
async fn trojan_outbound_connects_and_writes_request() {
    let server = spawn_tls_server("localhost").await;
    let outbound = TrojanOutbound::new(
        OutboundMeta::new("proxy", "trojan"),
        Logger::new("proxy", "trojan"),
        build_dialer(
            Dial {
                connect_timeout: Some(std::time::Duration::from_secs(1)),
                ..Dial::default()
            },
            system_host_resolver(),
        ),
        Destination::new(
            Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            server.addr.port(),
        ),
        "secret",
        OutboundTls {
            enabled: true,
            insecure: true,
            server_name: Some("localhost".into()),
            ..OutboundTls::default()
        },
    )
    .expect("trojan outbound should build");

    let destination = Destination::new(Host::Domain("example.com".into()), 443);
    let buffered_payload = b"GET / HTTP/1.1\r\n\r\n".to_vec();
    let expected = build_trojan_request("secret", &destination, &buffered_payload)
        .expect("request builder should succeed");
    let ctx = SessionContext::new(
        SessionMeta {
            id: 1,
            network: Network::Tcp,
            inbound_tag: "socks-in".into(),
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000),
            destination,
            start: Instant::now(),
        },
        buffered_payload,
    );

    let stream = outbound
        .connect_proxy_stream(&ctx)
        .await
        .expect("trojan outbound should connect");

    let certificate_path = server.certificate_path.clone();
    drop(stream);
    let received = server
        .handle
        .await
        .expect("server task should finish successfully");
    let _ = fs::remove_file(certificate_path);
    assert_eq!(received, expected);
}

struct TestTlsServer {
    addr: SocketAddr,
    certificate_path: PathBuf,
    handle: tokio::task::JoinHandle<Vec<u8>>,
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

    let handle = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("listener accept should succeed");
        let mut stream = acceptor
            .accept(stream)
            .await
            .expect("tls accept should succeed");

        let mut received = vec![0u8; expected_trojan_request_len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("server read should succeed");
        received
    });

    TestTlsServer {
        addr,
        certificate_path,
        handle,
    }
}

fn expected_trojan_request_len() -> usize {
    build_trojan_request(
        "secret",
        &Destination::new(Host::Domain("example.com".into()), 443),
        b"GET / HTTP/1.1\r\n\r\n",
    )
    .expect("request builder should succeed")
    .len()
}

fn write_temp_certificate(certificate_der: &[u8]) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("veex-outbound-test-{nanos}.pem"));
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
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
