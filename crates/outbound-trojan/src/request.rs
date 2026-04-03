use sha2::{Digest, Sha224};
use veex_core::{Destination, Host, ProxyError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrojanCommand {
    Connect = 0x01,
}

pub fn password_hash_hex(password: &str) -> String {
    let digest = sha224(password.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(nibble_to_hex(byte >> 4));
        output.push(nibble_to_hex(byte & 0x0f));
    }
    output
}

pub fn build_trojan_request(
    password: &str,
    destination: &Destination,
    buffered_payload: &[u8],
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(password_hash_hex(password).as_bytes());
    output.extend_from_slice(b"\r\n");
    output.push(TrojanCommand::Connect as u8);
    encode_destination(destination, &mut output)?;
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(buffered_payload);
    Ok(output)
}

fn encode_destination(destination: &Destination, output: &mut Vec<u8>) -> Result<()> {
    match &destination.host {
        Host::Ip(std::net::IpAddr::V4(ip)) => {
            output.push(0x01);
            output.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.len() > u8::MAX as usize {
                return Err(ProxyError::Protocol(format!(
                    "domain is too long for trojan request: {} bytes",
                    bytes.len()
                )));
            }
            output.push(0x03);
            output.push(bytes.len() as u8);
            output.extend_from_slice(bytes);
        }
        Host::Ip(std::net::IpAddr::V6(ip)) => {
            output.push(0x04);
            output.extend_from_slice(&ip.octets());
        }
    }

    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

fn sha224(input: &[u8]) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut output = [0u8; 28];
    output.copy_from_slice(&digest);
    output
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("nibble must be within 0..=15"),
    }
}
