use std::{collections::HashMap, future::Future, sync::Arc};

use tokio::task::JoinSet;
use veex_config::{
    DEFAULT_DIRECT_OUTBOUND_TAG, InboundConfig, OutboundConfig, ProxyConfig, TrojanTlsConfig,
};
use veex_core::{DirectOutbound, Dispatcher, Inbound, Outbound, Router, SimpleDispatcher};
use veex_inbound_socks::SocksInbound;
use veex_outbound_trojan::TrojanOutbound;
use veex_transport::TlsClientOptions;

struct RuntimeState {
    dispatcher: Arc<dyn Dispatcher>,
    inbounds: Vec<Arc<dyn Inbound>>,
}

pub async fn run_with_shutdown<F>(config: &ProxyConfig, shutdown: F) -> Result<(), String>
where
    F: Future<Output = Result<(), String>>,
{
    let state = build_runtime_state(config)?;
    let mut tasks = JoinSet::new();

    for inbound in state.inbounds {
        tasks.spawn(inbound.serve(Arc::clone(&state.dispatcher)));
    }

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = &mut shutdown => {
                result?;
                return Ok(());
            }
            maybe_task = tasks.join_next() => {
                match maybe_task {
                    Some(Ok(Ok(()))) => continue,
                    Some(Ok(Err(err))) => return Err(format!("runtime task failed: {err}")),
                    Some(Err(err)) => return Err(format!("runtime task panicked: {err}")),
                    None => return Ok(()),
                }
            }
        }
    }
}

fn build_runtime_state(config: &ProxyConfig) -> Result<RuntimeState, String> {
    if config.inbounds.is_empty() {
        return Err("at least one inbound is required to run veex".into());
    }

    let outbounds = build_outbounds(config)?;
    let router = build_router(config);
    let dispatcher: Arc<dyn Dispatcher> = Arc::new(SimpleDispatcher::new(router, outbounds));
    let inbounds = build_inbounds(config)?;

    Ok(RuntimeState {
        dispatcher,
        inbounds,
    })
}

fn build_outbounds(
    config: &ProxyConfig,
) -> Result<HashMap<String, Arc<dyn Outbound>>, String> {
    let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();

    for outbound in &config.outbounds {
        match outbound {
            OutboundConfig::Direct(direct) => {
                let instance: Arc<dyn Outbound> = Arc::new(DirectOutbound::new(direct.tag.clone()));
                outbounds.insert(direct.tag.clone(), instance);
            }
            OutboundConfig::Trojan(trojan) => {
                let instance: Arc<dyn Outbound> = Arc::new(TrojanOutbound::new(
                    trojan.tag.clone(),
                    trojan.server.clone(),
                    trojan.server_port,
                    trojan.password.clone(),
                    tls_options_from_config(&trojan.tls),
                ));
                outbounds.insert(trojan.tag.clone(), instance);
            }
        }
    }

    Ok(outbounds)
}

fn build_router(config: &ProxyConfig) -> Router {
    let mut router = Router::new(
        config.route.final_outbound.clone(),
        DEFAULT_DIRECT_OUTBOUND_TAG,
    );

    for outbound in &config.outbounds {
        if let OutboundConfig::Trojan(trojan) = outbound {
            router = router.with_bypass_host(trojan.server.clone());
        }
    }

    router
}

fn build_inbounds(config: &ProxyConfig) -> Result<Vec<Arc<dyn Inbound>>, String> {
    let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();

    for inbound in &config.inbounds {
        match inbound {
            InboundConfig::Socks(socks) => {
                let instance: Arc<dyn Inbound> = Arc::new(SocksInbound::new(
                    socks.tag.clone(),
                    socks.listen.clone(),
                    socks.listen_port,
                ));
                inbounds.push(instance);
            }
            InboundConfig::Redirect(redirect) => {
                return Err(format!(
                    "redirect inbound '{}' is not wired into the CLI runtime yet",
                    redirect.tag
                ));
            }
        }
    }

    Ok(inbounds)
}

fn tls_options_from_config(config: &TrojanTlsConfig) -> TlsClientOptions {
    TlsClientOptions {
        enabled: config.enabled,
        server_name: config.server_name.clone(),
        disable_sni: config.disable_sni,
        insecure: config.insecure,
        certificate_path: config.certificate_path.clone(),
        ca_path: config.ca_path.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{Ipv4Addr, SocketAddr},
        path::PathBuf,
        sync::Arc,
        time::Duration,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rcgen::generate_simple_self_signed;
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };
    use tokio_rustls::TlsAcceptor;
    use veex_config::{
        DirectOutboundConfig, InboundConfig, LogConfig, OutboundConfig, ProxyConfig, RouteConfig,
        SocksInboundConfig, TrojanOutboundConfig, TrojanTlsConfig,
    };
    use veex_core::{Destination, Host};
    use veex_outbound_trojan::build_trojan_request;

    use super::run_with_shutdown;

    #[tokio::test]
    async fn runtime_supports_socks_to_direct_round_trip() {
        let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("echo listener should bind");
        let echo_addr = echo_listener
            .local_addr()
            .expect("echo listener should expose local addr");
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.expect("echo accept should succeed");
            let mut buf = [0u8; 4];
            stream
                .read_exact(&mut buf)
                .await
                .expect("echo server should read payload");
            stream
                .write_all(&buf)
                .await
                .expect("echo server should write payload");
        });

        let socks_addr = reserve_local_port().await;
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
            },
            inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
                tag: "socks-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: socks_addr.port(),
            })],
            outbounds: vec![OutboundConfig::Direct(DirectOutboundConfig {
                tag: "direct".into(),
            })],
            route: RouteConfig {
                final_outbound: "direct".into(),
            },
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let runtime_task = tokio::spawn(async move {
            run_with_shutdown(&config, async move {
                shutdown_rx.await.map_err(|err| format!("shutdown channel failed: {err}"))?;
                Ok(())
            })
            .await
        });

        wait_for_listener(socks_addr).await;
        run_socks_client_round_trip(socks_addr, echo_addr)
            .await
            .expect("socks direct round-trip should succeed");

        let _ = shutdown_tx.send(());
        runtime_task
            .await
            .expect("runtime task should join")
            .expect("runtime should stop cleanly");
        echo_task.await.expect("echo task should join");
    }

    #[tokio::test]
    async fn runtime_supports_socks_to_trojan_round_trip() {
        let destination = Destination::new(Host::Ip(Ipv4Addr::new(93, 184, 216, 34).into()), 443);
        let trojan_server = spawn_trojan_server("localhost", destination.clone()).await;
        let socks_addr = reserve_local_port().await;
        let config = ProxyConfig {
            log: LogConfig {
                level: "info".into(),
                disabled: false,
            },
            inbounds: vec![InboundConfig::Socks(SocksInboundConfig {
                tag: "socks-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: socks_addr.port(),
            })],
            outbounds: vec![
                OutboundConfig::Direct(DirectOutboundConfig {
                    tag: "direct".into(),
                }),
                OutboundConfig::Trojan(TrojanOutboundConfig {
                    tag: "proxy".into(),
                    server: "127.0.0.1".into(),
                    server_port: trojan_server.addr.port(),
                    password: "secret".into(),
                    tls: TrojanTlsConfig {
                        enabled: true,
                        server_name: Some("localhost".into()),
                        disable_sni: false,
                        insecure: true,
                        certificate_path: None,
                        ca_path: None,
                    },
                }),
            ],
            route: RouteConfig {
                final_outbound: "proxy".into(),
            },
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let runtime_task = tokio::spawn(async move {
            run_with_shutdown(&config, async move {
                shutdown_rx
                    .await
                    .map_err(|err| format!("shutdown channel failed: {err}"))?;
                Ok(())
            })
            .await
        });

        wait_for_listener(socks_addr).await;
        run_socks_client_round_trip(
            socks_addr,
            SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443)),
        )
            .await
            .expect("socks trojan round-trip should succeed");

        let _ = shutdown_tx.send(());
        runtime_task
            .await
            .expect("runtime task should join")
            .expect("runtime should stop cleanly");

        let received = trojan_server
            .handle
            .await
            .expect("trojan server task should join");
        assert_eq!(received.request, build_trojan_request("secret", &destination, &[]).unwrap());
        assert_eq!(received.payload, b"ping");
        let _ = fs::remove_file(trojan_server.certificate_path);
    }

    async fn reserve_local_port() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("temporary listener should bind");
        listener.local_addr().expect("temporary addr should exist")
    }

    async fn wait_for_listener(addr: SocketAddr) {
        for _ in 0..50 {
            match TcpStream::connect(addr).await {
                Ok(_) => return,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }

        panic!("listener did not become ready on {addr}");
    }

    async fn run_socks_client_round_trip(
        socks_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> Result<(), String> {
        let mut stream = TcpStream::connect(socks_addr)
            .await
            .map_err(|err| format!("failed to connect to socks listener: {err}"))?;

        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|err| format!("failed to write greeting: {err}"))?;
        let mut method = [0u8; 2];
        stream
            .read_exact(&mut method)
            .await
            .map_err(|err| format!("failed to read method selection: {err}"))?;
        if method != [0x05, 0x00] {
            return Err(format!("unexpected method selection: {method:?}"));
        }

        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        match target_addr.ip() {
            std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
            std::net::IpAddr::V6(_) => return Err("test target must be IPv4".into()),
        }
        request.extend_from_slice(&target_addr.port().to_be_bytes());

        stream
            .write_all(&request)
            .await
            .map_err(|err| format!("failed to write socks request: {err}"))?;

        let mut reply = [0u8; 10];
        stream
            .read_exact(&mut reply)
            .await
            .map_err(|err| format!("failed to read socks reply: {err}"))?;
        if reply[1] != 0x00 {
            return Err(format!("unexpected socks reply code: 0x{:02x}", reply[1]));
        }

        stream
            .write_all(b"ping")
            .await
            .map_err(|err| format!("failed to write payload: {err}"))?;

        let mut echoed = [0u8; 4];
        stream
            .read_exact(&mut echoed)
            .await
            .map_err(|err| format!("failed to read echoed payload: {err}"))?;
        if &echoed != b"ping" {
            return Err(format!("unexpected echoed payload: {echoed:?}"));
        }

        Ok(())
    }

    struct TrojanServerResult {
        request: Vec<u8>,
        payload: Vec<u8>,
    }

    struct TestTrojanServer {
        addr: SocketAddr,
        certificate_path: PathBuf,
        handle: tokio::task::JoinHandle<TrojanServerResult>,
    }

    async fn spawn_trojan_server(server_name: &str, destination: Destination) -> TestTrojanServer {
        let certified = generate_simple_self_signed(vec![server_name.to_string()])
            .expect("certificate generation should succeed");
        let certificate = certified.cert.der().clone();
        let key = certified.key_pair.serialize_der();
        let certificate_path = write_temp_certificate(certificate.as_ref(), "veex-cli-trojan");

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate.as_ref().to_vec())],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)),
            )
            .expect("server config should build");

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("trojan listener should bind");
        let addr = listener
            .local_addr()
            .expect("trojan listener should expose local addr");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let expected_request_len = build_trojan_request("secret", &destination, &[])
            .expect("request builder should succeed")
            .len();

        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("trojan accept should succeed");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("trojan tls accept should succeed");

            let mut request = vec![0u8; expected_request_len];
            stream
                .read_exact(&mut request)
                .await
                .expect("trojan server should read request");

            let mut payload = vec![0u8; 4];
            stream
                .read_exact(&mut payload)
                .await
                .expect("trojan server should read payload");
            stream
                .write_all(&payload)
                .await
                .expect("trojan server should echo payload");

            TrojanServerResult { request, payload }
        });

        TestTrojanServer {
            addr,
            certificate_path,
            handle,
        }
    }

    fn write_temp_certificate(certificate_der: &[u8], prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{nanos}.pem"));
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
