use std::collections::BTreeMap;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use veex_core::{ProxyError, Result};

pub const DEFAULT_DOH_PATH: &str = "/dns-query";

const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;

pub async fn write_doh_http1_request<W>(
    writer: &mut W,
    host_header: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut request = format!("POST {path} HTTP/1.1\r\n");

    for (name, value) in headers {
        if is_reserved_header(name) {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }

    request.push_str(&format!("Host: {host_header}\r\n"));
    request.push_str("Accept: application/dns-message\r\n");
    request.push_str("Content-Type: application/dns-message\r\n");
    request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    request.push_str("Connection: close\r\n");
    request.push_str("\r\n");

    writer.write_all(request.as_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_doh_http1_response<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let (status_code, headers) = read_http1_headers(reader).await?;
    if !(200..300).contains(&status_code) {
        return Err(ProxyError::protocol(format!(
            "dns over https upstream returned HTTP status {status_code}"
        )));
    }

    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        return Err(ProxyError::protocol(
            "dns over https chunked responses are not supported yet",
        ));
    }

    let mut body = Vec::new();
    if let Some(content_length) = headers.get("content-length") {
        let expected = content_length.parse::<usize>().map_err(|err| {
            ProxyError::protocol(format!(
                "dns over https response content-length is invalid: {err}"
            ))
        })?;
        body.resize(expected, 0);
        reader.read_exact(&mut body).await?;
    } else {
        reader.read_to_end(&mut body).await?;
    }

    if body.is_empty() {
        return Err(ProxyError::protocol(
            "dns over https upstream returned an empty response body",
        ));
    }

    Ok(body)
}

async fn read_http1_headers<R>(reader: &mut R) -> Result<(u16, BTreeMap<String, String>)>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = Vec::new();
    loop {
        if buffer.len() >= MAX_HTTP_HEADER_BYTES {
            return Err(ProxyError::protocol(format!(
                "dns over https response headers exceed {MAX_HTTP_HEADER_BYTES} bytes"
            )));
        }

        let byte = reader.read_u8().await?;
        buffer.push(byte);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    buffer.truncate(buffer.len() - 4);
    let head = std::str::from_utf8(&buffer).map_err(|err| {
        ProxyError::protocol(format!("dns over https response is not UTF-8: {err}"))
    })?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ProxyError::protocol("dns over https response is missing a status line"))?;
    let status_code = parse_http_status_line(status_line)?;

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            ProxyError::protocol(format!(
                "dns over https response header is malformed: {line}"
            ))
        })?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    Ok((status_code, headers))
}

fn parse_http_status_line(status_line: &str) -> Result<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| ProxyError::protocol("dns over https response status line is empty"))?;
    if !version.starts_with("HTTP/") {
        return Err(ProxyError::protocol(format!(
            "dns over https response status line is invalid: {status_line}"
        )));
    }
    let status_code = parts
        .next()
        .ok_or_else(|| ProxyError::protocol("dns over https response is missing a status code"))?;
    status_code.parse::<u16>().map_err(|err| {
        ProxyError::protocol(format!(
            "dns over https response status code is invalid: {err}"
        ))
    })
}

fn is_reserved_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "accept" | "content-type" | "content-length" | "connection"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::{read_doh_http1_response, write_doh_http1_request};

    #[tokio::test]
    async fn writes_doh_http1_post_request_with_required_headers() {
        let (mut client, mut server) = duplex(256);
        let body = b"\x12\x34query".to_vec();

        let write = tokio::spawn(async move {
            write_doh_http1_request(
                &mut client,
                "dns.example.com",
                "/dns-query",
                &BTreeMap::from([(String::from("X-Test"), String::from("true"))]),
                &body,
            )
            .await
            .expect("request should write");
        });

        let mut request = Vec::new();
        server
            .read_to_end(&mut request)
            .await
            .expect("request should read");
        write.await.expect("writer task should join");

        let request = String::from_utf8_lossy(&request);
        assert!(request.contains("POST /dns-query HTTP/1.1\r\n"));
        assert!(request.contains("Host: dns.example.com\r\n"));
        assert!(request.contains("Content-Type: application/dns-message\r\n"));
        assert!(request.contains("Accept: application/dns-message\r\n"));
        assert!(request.contains("X-Test: true\r\n"));
    }

    #[tokio::test]
    async fn reads_doh_http1_response_body_from_content_length() {
        let (mut client, mut server) = duplex(256);
        let expected = b"\x12\x34response".to_vec();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            expected.len()
        );

        let write = tokio::spawn(async move {
            client
                .write_all(response.as_bytes())
                .await
                .expect("status should write");
            client
                .write_all(&expected)
                .await
                .expect("body should write");
        });

        let body = read_doh_http1_response(&mut server)
            .await
            .expect("response should parse");
        write.await.expect("writer task should join");

        assert_eq!(body, b"\x12\x34response");
    }
}
