use veex_core::Host;
use veex_inbound_socks::{
    decode_greeting, decode_request, encode_method_selection, AddressType, ReplyCode, SocksError,
};

#[test]
fn greeting_with_no_auth_is_supported() {
    let greeting = decode_greeting(&[0x05, 0x01, 0x00]).expect("greeting should parse");
    assert_eq!(greeting.methods, vec![0x00]);
    assert_eq!(encode_method_selection(0x00), [0x05, 0x00]);
}

#[test]
fn request_with_domain_is_supported() {
    let request = decode_request(&[
        0x05,
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
        0x01,
        0xbb,
    ])
    .expect("request should parse");

    assert_eq!(request.destination.host, Host::Domain("example.com".into()));
    assert_eq!(request.destination.port, 443);
}

#[test]
fn unsupported_command_is_rejected() {
    let err = decode_request(&[0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50])
        .expect_err("udp associate is not supported");

    match err {
        SocksError::UnsupportedCommand(0x03) => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn unsupported_address_type_is_rejected() {
    let err = decode_request(&[0x05, 0x01, 0x00, 0x09, 0x00, 0x50])
        .expect_err("invalid atyp should fail");

    match err {
        SocksError::UnsupportedAddressType(0x09) => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn reply_code_values_are_stable() {
    assert_eq!(ReplyCode::Succeeded as u8, 0x00);
    assert_eq!(ReplyCode::CommandNotSupported as u8, 0x07);
}

