use sha2::{Digest, Sha224};
use veex_core::{
    types::{Destination, Host},
    ProxyError, Result,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrojanCommand {
    Connect = 0x01,
}

pub fn encode_key_hex(key: &str) -> String {
    let digest = sha224(key.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(nibble_to_hex(byte >> 4));
        output.push(nibble_to_hex(byte & 0x0f));
    }
    output
}

pub fn build_trojan_request(
    key: &str,
    destination: &Destination,
    buffered_payload: &[u8],
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(encode_key_hex(key).as_bytes());
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use veex_core::types::Destination;

    use super::{build_trojan_request, encode_key_hex};

    #[test]
    fn encoded_key_has_expected_length() {
        let hash = encode_key_hex("secret");
        assert_eq!(hash.len(), 56);
        assert!(hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }

    #[test]
    fn encoded_key_matches_sha224_test_vectors() {
        assert_eq!(
            encode_key_hex(""),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            encode_key_hex("abc"),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[test]
    fn encodes_ipv4_destination() {
        let request = build_trojan_request(
            "secret",
            &Destination::from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
            &[],
        )
        .expect("request should encode");

        assert_eq!(&request[56..58], b"\r\n");
        assert_eq!(request[58], 0x01);
        assert_eq!(request[59], 0x01);
        assert_eq!(&request[60..64], &[1, 2, 3, 4]);
        assert_eq!(&request[64..66], &443u16.to_be_bytes());
        assert_eq!(&request[66..68], b"\r\n");
    }

    #[test]
    fn encodes_domain_and_payload() {
        let request = build_trojan_request(
            "secret",
            &Destination::from_domain("example.com", 80),
            b"GET / HTTP/1.1\r\n",
        )
        .expect("request should encode");

        assert_eq!(request[58], 0x01);
        assert_eq!(request[59], 0x03);
        assert_eq!(request[60], 11);
        assert_eq!(&request[61..72], b"example.com");
        assert_eq!(&request[72..74], &80u16.to_be_bytes());
        assert_eq!(&request[74..76], b"\r\n");
        assert_eq!(&request[76..], b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn encodes_ipv6_destination() {
        let request = build_trojan_request(
            "secret",
            &Destination::from_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 1080),
            &[],
        )
        .expect("request should encode");

        assert_eq!(request[59], 0x04);
        assert_eq!(&request[60..76], &Ipv6Addr::LOCALHOST.octets());
    }
}
