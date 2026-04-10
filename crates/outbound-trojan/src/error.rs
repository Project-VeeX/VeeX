use std::io;

use veex_core::{ProxyError, Result};
use veex_transport::TlsClientOptions;

pub(crate) fn validate_trojan_client(
    tag: &str,
    password: &str,
    server_port: u16,
    tls: &TlsClientOptions,
) -> Result<()> {
    if tag.trim().is_empty() {
        return Err(ProxyError::Config(
            "trojan outbound tag must not be empty".into(),
        ));
    }
    if password.is_empty() {
        return Err(ProxyError::Config(
            "trojan outbound password must not be empty".into(),
        ));
    }
    if server_port == 0 {
        return Err(ProxyError::Config(
            "trojan outbound server_port must be within 1..=65535".into(),
        ));
    }
    tls.validate()?;
    Ok(())
}

pub(crate) fn request_write_error(err: io::Error) -> ProxyError {
    ProxyError::protocol_ctx("failed to write trojan request", err)
}
