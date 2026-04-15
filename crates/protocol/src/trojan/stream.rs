use std::{fmt, io};

use tokio::io::AsyncWriteExt;
use veex_core::{BoxedAsyncStream, ProxyError, Result};

use crate::adapter::{StreamAdapter, StreamAdapterFuture, StreamParams};

use super::encode::build_trojan_request;

#[derive(Clone)]
pub struct TrojanStreamAdapter {
    key: String,
}

impl fmt::Debug for TrojanStreamAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanStreamAdapter")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl TrojanStreamAdapter {
    pub fn new(key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        validate_trojan_key(&key)?;
        Ok(Self { key })
    }
}

impl StreamAdapter for TrojanStreamAdapter {
    fn establish<'a>(
        &'a self,
        mut stream: BoxedAsyncStream,
        params: StreamParams,
    ) -> StreamAdapterFuture<'a> {
        Box::pin(async move {
            let protocol_request =
                build_trojan_request(&self.key, &params.destination, &params.buffered_payload)?;
            stream
                .write_all(&protocol_request)
                .await
                .map_err(request_write_error)?;

            Ok(stream)
        })
    }
}

pub fn validate_trojan_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(ProxyError::Config(
            "trojan outbound password must not be empty".into(),
        ));
    }
    Ok(())
}

fn request_write_error(err: io::Error) -> ProxyError {
    ProxyError::protocol_ctx("failed to write trojan request", err)
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;
    use veex_core::Destination;

    use crate::adapter::{StreamAdapter, StreamParams};

    use crate::trojan::encode::build_trojan_request;

    use super::TrojanStreamAdapter;

    #[tokio::test]
    async fn establishes_stream_by_writing_trojan_request() {
        let adapter = TrojanStreamAdapter::new("secret").expect("adapter should build");
        let destination = Destination::from_domain("example.com", 443);
        let buffered_payload = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let expected = build_trojan_request("secret", &destination, &buffered_payload)
            .expect("request should encode");
        let (client, mut server) = tokio::io::duplex(1024);

        let stream = adapter
            .establish(
                Box::new(client),
                StreamParams::new(destination, buffered_payload),
            )
            .await
            .expect("stream should be prepared");
        drop(stream);

        let mut received = vec![0u8; expected.len()];
        server
            .read_exact(&mut received)
            .await
            .expect("server should receive trojan request");
        assert_eq!(received, expected);
    }
}
