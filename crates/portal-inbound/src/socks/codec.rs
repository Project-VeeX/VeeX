use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use veex_core::types::{Destination, Host};

use super::error::SocksError;

pub const SOCKS_VERSION: u8 = 0x05;
pub const NO_AUTHENTICATION: u8 = 0x00;
pub const NO_ACCEPTABLE_METHODS: u8 = 0xff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Connect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressType {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    NetworkUnreachable = 0x03,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Greeting {
    pub methods: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub command: Command,
    pub destination: Destination,
}

pub fn decode_greeting(bytes: &[u8]) -> Result<Greeting, SocksError> {
    if bytes.len() < 2 {
        return Err(SocksError::protocol("greeting is too short"));
    }

    if bytes[0] != SOCKS_VERSION {
        return Err(SocksError::protocol(format!(
            "unsupported SOCKS version: 0x{:02x}",
            bytes[0]
        )));
    }

    let method_len = bytes[1] as usize;
    if bytes.len() != method_len + 2 {
        return Err(SocksError::protocol("greeting method list length mismatch"));
    }

    Ok(Greeting {
        methods: bytes[2..].to_vec(),
    })
}

pub fn decode_request(bytes: &[u8]) -> Result<Request, SocksError> {
    if bytes.len() < 4 {
        return Err(SocksError::protocol("request is too short"));
    }

    if bytes[0] != SOCKS_VERSION {
        return Err(SocksError::protocol(format!(
            "unsupported SOCKS version: 0x{:02x}",
            bytes[0]
        )));
    }

    if bytes[2] != 0x00 {
        return Err(SocksError::protocol("request reserved field must be 0x00"));
    }

    let command = match bytes[1] {
        0x01 => Command::Connect,
        other => return Err(SocksError::UnsupportedCommand(other)),
    };

    let atyp = bytes[3];
    let (host, port_index) = match atyp {
        x if x == AddressType::V4 as u8 => {
            if bytes.len() != 10 {
                return Err(SocksError::protocol("ipv4 request length mismatch"));
            }
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            (Host::Ip(IpAddr::V4(ip)), 8)
        }
        x if x == AddressType::Domain as u8 => {
            if bytes.len() < 7 {
                return Err(SocksError::protocol("domain request is too short"));
            }
            let domain_len = bytes[4] as usize;
            if domain_len == 0 {
                return Err(SocksError::protocol("domain must not be empty"));
            }
            let expected = 4 + 1 + domain_len + 2;
            if bytes.len() != expected {
                return Err(SocksError::protocol("domain request length mismatch"));
            }
            let domain = std::str::from_utf8(&bytes[5..5 + domain_len])
                .map_err(|_| SocksError::protocol("domain is not valid UTF-8"))?;
            (Host::Domain(domain.to_string()), 5 + domain_len)
        }
        x if x == AddressType::V6 as u8 => {
            if bytes.len() != 22 {
                return Err(SocksError::protocol("ipv6 request length mismatch"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[4..20]);
            (Host::Ip(IpAddr::V6(Ipv6Addr::from(octets))), 20)
        }
        other => return Err(SocksError::UnsupportedAddressType(other)),
    };

    let port = u16::from_be_bytes([bytes[port_index], bytes[port_index + 1]]);

    Ok(Request {
        command,
        destination: Destination::new(host, port),
    })
}

pub fn encode_method_selection(method: u8) -> [u8; 2] {
    [SOCKS_VERSION, method]
}

pub fn encode_reply(code: ReplyCode, bound_addr: Option<SocketAddr>) -> Vec<u8> {
    let mut output = vec![SOCKS_VERSION, code as u8, 0x00];

    match bound_addr {
        Some(SocketAddr::V4(addr)) => {
            output.push(AddressType::V4 as u8);
            output.extend_from_slice(&addr.ip().octets());
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        Some(SocketAddr::V6(addr)) => {
            output.push(AddressType::V6 as u8);
            output.extend_from_slice(&addr.ip().octets());
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        None => {
            output.push(AddressType::V4 as u8);
            output.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
            output.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use veex_core::types::Host;

    use super::{
        AddressType, Command, ReplyCode, SOCKS_VERSION, decode_greeting, decode_request,
        encode_reply,
    };

    #[test]
    fn decodes_greeting() {
        let greeting = decode_greeting(&[SOCKS_VERSION, 2, 0x00, 0x02]).expect("decode");
        assert_eq!(greeting.methods, vec![0x00, 0x02]);
    }

    #[test]
    fn decodes_ipv4_request() {
        let request = decode_request(&[SOCKS_VERSION, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xbb])
            .expect("decode");
        assert_eq!(request.command, Command::Connect);
        assert_eq!(
            request.destination.host,
            Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(request.destination.port, 443);
    }

    #[test]
    fn decodes_domain_request() {
        let request = decode_request(&[
            SOCKS_VERSION,
            0x01,
            0x00,
            AddressType::Domain as u8,
            11,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            b'.',
            b'c',
            b'o',
            b'm',
            0x00,
            0x50,
        ])
        .expect("decode");

        assert_eq!(request.destination.host, Host::Domain("example.com".into()));
        assert_eq!(request.destination.port, 80);
    }

    #[test]
    fn decodes_ipv6_request() {
        let mut bytes = vec![SOCKS_VERSION, 0x01, 0x00, AddressType::V6 as u8];
        bytes.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        bytes.extend_from_slice(&1080u16.to_be_bytes());

        let request = decode_request(&bytes).expect("decode");
        assert_eq!(
            request.destination.host,
            Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(request.destination.port, 1080);
    }

    #[test]
    fn encodes_reply_with_default_bound_addr() {
        let reply = encode_reply(ReplyCode::Succeeded, None);
        assert_eq!(reply, vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn rejects_empty_domain_request() {
        let err = decode_request(&[
            SOCKS_VERSION,
            0x01,
            0x00,
            AddressType::Domain as u8,
            0,
            0x01,
            0xbb,
        ])
        .expect_err("empty domain should fail");

        assert!(err.to_string().contains("domain must not be empty"));
    }
}
