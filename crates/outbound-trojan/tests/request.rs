use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use veex_core::Destination;
use veex_outbound_trojan::{build_trojan_request, password_hash_hex};

#[test]
fn password_hash_has_expected_length() {
    let hash = password_hash_hex("secret");
    assert_eq!(hash.len(), 56);
    assert!(hash
        .chars()
        .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
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
