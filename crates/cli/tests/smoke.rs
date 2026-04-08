use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[test]
fn run_starts_listener_relays_direct_and_shuts_down_on_sigint() {
    run_lifecycle_smoke_test("-INT", false, false);
}

#[test]
fn run_starts_listener_relays_direct_and_shuts_down_on_sigterm() {
    run_lifecycle_smoke_test("-TERM", false, false);
}

#[test]
fn run_prints_config_warnings_with_verbose() {
    run_lifecycle_smoke_test("-TERM", true, false);
}

#[test]
fn run_emits_timestamped_logs_when_enabled() {
    run_lifecycle_smoke_test("-TERM", false, true);
}

fn run_lifecycle_smoke_test(signal: &str, verbose: bool, timestamp: bool) {
    let echo_listener = TcpListener::bind(("127.0.0.1", 0)).expect("echo listener should bind");
    let echo_addr = echo_listener
        .local_addr()
        .expect("echo listener should expose local addr");
    let echo_thread = thread::spawn(move || {
        let (mut stream, _) = echo_listener.accept().expect("echo accept should succeed");
        let mut buf = [0u8; 4];
        stream
            .read_exact(&mut buf)
            .expect("echo server should read payload");
        stream
            .write_all(&buf)
            .expect("echo server should write payload");
    });

    let socks_addr = reserve_local_addr();
    let config_path = write_temp_file(
        "veex-smoke-run",
        &format!(
            r#"{{
  "dns": {{}},
  "log": {{ "level": "info", "disabled": false, "timestamp": {} }},
  "inbounds": [
    {{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {} }}
  ],
  "outbounds": [
    {{ "type": "direct", "tag": "direct" }}
  ],
  "route": {{ "final": "direct" }}
}}"#,
            timestamp,
            socks_addr.port()
        ),
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_veex"));
    command.arg("run");
    if verbose {
        command.arg("--verbose");
    }
    let child = command
        .args([
            "-c",
            config_path.to_str().expect("config path should be utf-8"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("veex run should spawn");

    wait_for_listener(socks_addr);
    run_socks_round_trip(socks_addr, echo_addr);

    send_signal(child.id(), signal);
    let output = child
        .wait_with_output()
        .expect("veex run should exit cleanly");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(combined.contains("process_start"));
    assert!(combined.contains("process_stop"));
    assert_output_has_event(&combined, "session_finish", &[("success", "true")]);
    if timestamp {
        assert_event_line_has_timestamp(&combined, "process_start");
    }
    if verbose {
        assert!(stderr.contains("config warning at $.dns"));
    } else {
        assert!(!stderr.contains("config warning at"));
    }

    echo_thread.join().expect("echo thread should join");
    fs::remove_file(&config_path).expect("config file should be removed");
}

#[test]
fn check_returns_config_error_for_invalid_config() {
    let config_path = write_temp_file(
        "veex-smoke-check",
        r#"{
  "inbounds": [
    { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_veex"))
        .args([
            "check",
            "-c",
            config_path.to_str().expect("config path should be utf-8"),
        ])
        .output()
        .expect("veex check should run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(stderr.contains("$.route"));

    fs::remove_file(&config_path).expect("config file should be removed");
}

#[test]
fn check_accepts_tproxy_compat_example() {
    let config_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/tproxy-compat.json");

    let output = Command::new(env!("CARGO_BIN_EXE_veex"))
        .args([
            "check",
            "-c",
            config_path.to_str().expect("config path should be utf-8"),
        ])
        .output()
        .expect("veex check should run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("config check passed"));
    assert!(stdout.contains("final=proxy"));
    assert!(!stderr.contains("config warning at"));
}

#[test]
fn check_accepts_tproxy_compat_example_and_prints_warnings_with_verbose() {
    let config_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/tproxy-compat.json");

    let output = Command::new(env!("CARGO_BIN_EXE_veex"))
        .args([
            "check",
            "--verbose",
            "-c",
            config_path.to_str().expect("config path should be utf-8"),
        ])
        .output()
        .expect("veex check should run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("config check passed"));
    assert!(stdout.contains("final=proxy"));
    assert!(stderr.contains("config warning at $.dns"));
    assert!(stderr.contains("config warning at $.outbounds[1].domain_resolver"));
    assert!(!stderr.contains("config warning at $.route.rules"));
}

fn reserve_local_addr() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("temporary listener should bind");
    listener
        .local_addr()
        .expect("temporary listener should expose local addr")
}

fn write_temp_file(prefix: &str, content: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{nanos}.json"));
    fs::write(&path, content).expect("temporary config should be written");
    path
}

fn wait_for_listener(addr: SocketAddr) {
    for _ in 0..100 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }

    panic!("listener did not become ready on {addr}");
}

fn run_socks_round_trip(socks_addr: SocketAddr, target_addr: SocketAddr) {
    let mut stream = TcpStream::connect(socks_addr).expect("socks connect should succeed");

    stream
        .write_all(&[0x05, 0x01, 0x00])
        .expect("greeting write should succeed");

    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .expect("method selection should be readable");
    assert_eq!(method, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    match target_addr.ip() {
        std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => panic!("smoke target must be IPv4"),
    }
    request.extend_from_slice(&target_addr.port().to_be_bytes());

    stream
        .write_all(&request)
        .expect("request write should succeed");

    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .expect("reply should be readable");
    assert_eq!(reply[1], 0x00, "unexpected socks reply: {reply:?}");

    stream
        .write_all(b"ping")
        .expect("payload write should succeed");
    let mut echoed = [0u8; 4];
    stream
        .read_exact(&mut echoed)
        .expect("echoed payload should be readable");
    assert_eq!(&echoed, b"ping");
    let _ = stream.shutdown(Shutdown::Both);
}

fn send_signal(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .expect("kill should run");
    assert!(status.success(), "kill {signal} {pid} failed");
}

fn assert_output_has_event(output: &str, event_name: &str, expected_fields: &[(&str, &str)]) {
    let matched = output.lines().any(|line| {
        let fields = parse_output_fields(line);
        fields.get("event").map(String::as_str) == Some(event_name)
            && expected_fields
                .iter()
                .all(|(key, expected)| fields.get(*key).map(String::as_str) == Some(*expected))
    });

    assert!(
        matched,
        "expected event `{event_name}` with fields {:?} in output:\n{output}",
        expected_fields
    );
}

fn assert_event_line_has_timestamp(output: &str, event_name: &str) {
    let line = output
        .lines()
        .find(|line| parse_output_fields(line).get("event").map(String::as_str) == Some(event_name))
        .unwrap_or_else(|| panic!("expected event `{event_name}` in output:\n{output}"));
    let prefix = line
        .split_whitespace()
        .next()
        .expect("timestamped log line should not be empty");
    let fractional = prefix
        .rsplit_once('.')
        .map(|(_, tail)| tail)
        .expect("timestamp should contain millisecond precision");

    assert!(
        prefix.contains('T')
            && fractional.len() == 3
            && prefix.matches(':').count() == 2,
        "expected local millisecond timestamp prefix without offset for `{event_name}`, got line:\n{line}"
    );
    assert!(
        line.starts_with(&format!("{prefix}  INFO ")),
        "expected default aligned level formatting for `{event_name}`, got line:\n{line}"
    );
}

fn parse_output_fields(line: &str) -> std::collections::BTreeMap<String, String> {
    line.split_whitespace()
        .filter_map(|token| token.split_once('='))
        .map(|(key, value)| (key.to_string(), value.trim_matches('"').to_string()))
        .collect()
}
