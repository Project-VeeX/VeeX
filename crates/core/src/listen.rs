use std::net::{AddrParseError, IpAddr, SocketAddr};

pub fn format_listen_addr(listen: &str, port: u16) -> String {
    let listen = listen.trim();

    if listen.is_empty() {
        return format!(":{port}");
    }

    if listen.starts_with('[') && listen.ends_with(']') {
        return format!("{listen}:{port}");
    }

    if matches!(listen.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
        format!("[{listen}]:{port}")
    } else {
        format!("{listen}:{port}")
    }
}

pub fn parse_listen_addr(listen: &str, port: u16) -> Result<SocketAddr, AddrParseError> {
    let listen = strip_ipv6_brackets(listen.trim());

    if let Ok(ip) = listen.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    format_listen_addr(listen, port).parse()
}

fn strip_ipv6_brackets(value: &str) -> &str {
    value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{format_listen_addr, parse_listen_addr};

    #[test]
    fn formats_ipv4_listen_addr() {
        assert_eq!(format_listen_addr("127.0.0.1", 1080), "127.0.0.1:1080");
    }

    #[test]
    fn formats_ipv6_listen_addr() {
        assert_eq!(format_listen_addr("::", 1041), "[::]:1041");
        assert_eq!(format_listen_addr("[::]", 1041), "[::]:1041");
    }

    #[test]
    fn parses_ipv4_listen_addr() {
        assert_eq!(
            parse_listen_addr("0.0.0.0", 1041).expect("ipv4 listen should parse"),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1041))
        );
    }

    #[test]
    fn parses_ipv6_listen_addr() {
        assert_eq!(
            parse_listen_addr("::", 1041).expect("ipv6 listen should parse"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041))
        );
        assert_eq!(
            parse_listen_addr("[::]", 1041).expect("bracketed ipv6 listen should parse"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041))
        );
    }
}
