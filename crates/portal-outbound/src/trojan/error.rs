use veex_core::{ProxyError, Result, types::Destination};
use veex_transport::TlsClientOptions;

pub(crate) fn validate_trojan_client(
    tag: &str,
    upstream_addr: &Destination,
    tls: &TlsClientOptions,
) -> Result<()> {
    if tag.trim().is_empty() {
        return Err(ProxyError::Config(
            "trojan outbound tag must not be empty".into(),
        ));
    }
    if upstream_addr.port == 0 {
        return Err(ProxyError::Config(
            "trojan outbound server_port must be within 1..=65535".into(),
        ));
    }
    tls.validate()?;
    Ok(())
}
