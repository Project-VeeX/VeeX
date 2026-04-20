use std::net::{AddrParseError, SocketAddr};

/// Common listen fields shared by listener-backed components.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Listen {
    listen: String,
    listen_port: u16,
}

impl Listen {
    pub fn new(listen: impl Into<String>, listen_port: u16) -> Self {
        Self {
            listen: listen.into(),
            listen_port,
        }
    }

    pub fn listen(&self) -> &str {
        &self.listen
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub fn format_addr(&self) -> String {
        crate::listen::format_listen_addr(&self.listen, self.listen_port)
    }

    pub fn parse_addr(&self) -> Result<SocketAddr, AddrParseError> {
        crate::listen::parse_listen_addr(&self.listen, self.listen_port)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddr};

    use super::Listen;

    #[test]
    fn listen_formats_and_parses_ipv6() {
        let listen = Listen::new("::", 1041);

        assert_eq!(listen.format_addr(), "[::]:1041");
        assert_eq!(
            listen.parse_addr().expect("listen addr should parse"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1041))
        );
    }
}
