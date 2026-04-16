use std::{error::Error, fmt};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use veex_core::Destination;

use crate::{
    codec::{
        decode_greeting, decode_request, encode_method_selection, encode_reply, Command, ReplyCode,
        NO_ACCEPTABLE_METHODS, NO_AUTHENTICATION,
    },
    error::SocksError,
};

#[derive(Debug)]
pub(crate) struct SocksStreamRequest {
    pub(crate) command: Command,
    pub(crate) destination: Destination,
    pub(crate) stream: TcpStream,
}

#[derive(Debug)]
pub(crate) struct SocksProtocolError {
    stage: &'static str,
    source: SocksError,
}

impl SocksProtocolError {
    fn new(stage: &'static str, source: SocksError) -> Self {
        Self { stage, source }
    }

    pub(crate) fn stage(&self) -> &'static str {
        self.stage
    }

    pub(crate) fn source_error(&self) -> &SocksError {
        &self.source
    }

    pub(crate) fn into_inner(self) -> SocksError {
        self.source
    }
}

impl fmt::Display for SocksProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.source)
    }
}

impl Error for SocksProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

pub(crate) async fn establish_socks_stream(
    mut stream: TcpStream,
) -> std::result::Result<SocksStreamRequest, SocksProtocolError> {
    let methods = read_greeting(&mut stream)
        .await
        .map_err(|err| SocksProtocolError::new("greeting", err))?;
    let greeting =
        decode_greeting(&methods).map_err(|err| SocksProtocolError::new("greeting", err))?;

    if !greeting.methods.contains(&NO_AUTHENTICATION) {
        stream
            .write_all(&encode_method_selection(NO_ACCEPTABLE_METHODS))
            .await
            .map_err(|err| SocksProtocolError::new("method_selection", SocksError::from(err)))?;
        return Err(SocksProtocolError::new(
            "method_selection",
            SocksError::UnsupportedAuthMethods,
        ));
    }

    stream
        .write_all(&encode_method_selection(NO_AUTHENTICATION))
        .await
        .map_err(|err| SocksProtocolError::new("method_selection", SocksError::from(err)))?;

    let request_bytes = read_request(&mut stream)
        .await
        .map_err(|err| SocksProtocolError::new("request_decode", err))?;
    let request = match decode_request(&request_bytes) {
        Ok(request) => request,
        Err(err @ SocksError::UnsupportedCommand(_)) => {
            stream
                .write_all(&encode_reply(ReplyCode::CommandNotSupported, None))
                .await
                .map_err(|write_err| {
                    SocksProtocolError::new("request_validate", SocksError::from(write_err))
                })?;
            return Err(SocksProtocolError::new("request_validate", err));
        }
        Err(err @ SocksError::UnsupportedAddressType(_)) => {
            stream
                .write_all(&encode_reply(ReplyCode::AddressTypeNotSupported, None))
                .await
                .map_err(|write_err| {
                    SocksProtocolError::new("request_validate", SocksError::from(write_err))
                })?;
            return Err(SocksProtocolError::new("request_validate", err));
        }
        Err(err) => {
            stream
                .write_all(&encode_reply(ReplyCode::GeneralFailure, None))
                .await
                .map_err(|write_err| {
                    SocksProtocolError::new("request_decode", SocksError::from(write_err))
                })?;
            return Err(SocksProtocolError::new("request_decode", err));
        }
    };

    let local_addr = stream.local_addr().ok();
    stream
        .write_all(&encode_reply(ReplyCode::Succeeded, local_addr))
        .await
        .map_err(|err| SocksProtocolError::new("request_validate", SocksError::from(err)))?;

    Ok(SocksStreamRequest {
        command: request.command,
        destination: request.destination,
        stream,
    })
}

async fn read_greeting(stream: &mut TcpStream) -> std::result::Result<Vec<u8>, SocksError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    let mut bytes = header.to_vec();

    let method_len = header[1] as usize;
    let mut methods = vec![0u8; method_len];
    stream.read_exact(&mut methods).await?;
    bytes.extend_from_slice(&methods);
    Ok(bytes)
}

async fn read_request(stream: &mut TcpStream) -> std::result::Result<Vec<u8>, SocksError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let atyp = header[3];
    let mut bytes = header.to_vec();

    match atyp {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
            bytes.extend_from_slice(&rest);
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            bytes.extend_from_slice(&len);

            let mut domain = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut domain).await?;
            bytes.extend_from_slice(&domain);
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
            bytes.extend_from_slice(&rest);
        }
        _ => {
            let mut rest = [0u8; 2];
            stream.read_exact(&mut rest).await?;
            bytes.extend_from_slice(&rest);
        }
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::establish_socks_stream;
    use crate::codec::Command;

    #[tokio::test]
    async fn establish_socks_stream_returns_standardized_result() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept should succeed");
            establish_socks_stream(stream).await
        });

        let mut client = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        client
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .expect("greeting should send");

        let mut greeting_reply = [0u8; 2];
        client
            .read_exact(&mut greeting_reply)
            .await
            .expect("greeting reply should read");
        assert_eq!(greeting_reply, [0x05, 0x00]);

        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xbb,
            ])
            .await
            .expect("request should send");

        let mut request_reply = [0u8; 10];
        client
            .read_exact(&mut request_reply)
            .await
            .expect("reply should read");
        assert_eq!(&request_reply[..2], &[0x05, 0x00]);

        let established = server
            .await
            .expect("server task should join")
            .expect("handshake should succeed");
        assert_eq!(established.command, Command::Connect);
        assert_eq!(
            established.destination,
            veex_core::Destination::from_domain("example.com", 443)
        );
    }
}
