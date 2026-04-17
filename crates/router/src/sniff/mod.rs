use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

const MAX_SNIFF_PREFIX_LEN: usize = 2048;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SniffOutcome<S> {
    pub(crate) stream: PrefixedStream<S>,
    pub(crate) domain: Option<String>,
    pub(crate) protocol: Option<SniffedProtocol>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SniffedProtocol {
    Tls,
    Http,
}

impl SniffedProtocol {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Http => "http",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SniffResult {
    Matched {
        domain: String,
        protocol: SniffedProtocol,
    },
    NotMatched,
    Timeout,
    Unsupported,
}

#[derive(Debug)]
pub(crate) struct SniffExecution<S> {
    pub(crate) outcome: SniffOutcome<S>,
    pub(crate) result: SniffResult,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrefixedStream<S> {
    prefix: Vec<u8>,
    cursor: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            cursor: 0,
            inner,
        }
    }
}

impl<S> AsyncRead for PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.cursor < self.prefix.len() {
            let remaining = &self.prefix[self.cursor..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.cursor += to_copy;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn sniff_stream<S>(stream: S, timeout: Duration) -> SniffOutcome<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    sniff_stream_internal(stream, timeout).await.outcome
}

pub(crate) async fn sniff_stream_internal<S>(mut stream: S, timeout: Duration) -> SniffExecution<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut prefix = Vec::with_capacity(MAX_SNIFF_PREFIX_LEN);
    let read_result =
        tokio::time::timeout(timeout, read_sniff_prefix(&mut stream, &mut prefix)).await;

    let mut error = None;
    let result = match read_result {
        Ok(Ok(())) => finalize_sniff_result(&prefix),
        Ok(Err(err)) => {
            error = Some(err.to_string());
            match probe_prefix(&prefix) {
                ProbeState::Matched { domain, protocol } => {
                    SniffResult::Matched { domain, protocol }
                }
                _ => SniffResult::Unsupported,
            }
        }
        Err(_) => match probe_prefix(&prefix) {
            ProbeState::Matched { domain, protocol } => SniffResult::Matched { domain, protocol },
            _ => SniffResult::Timeout,
        },
    };

    let (domain, protocol) = match &result {
        SniffResult::Matched { domain, protocol } => (Some(domain.clone()), Some(protocol.clone())),
        _ => (None, None),
    };

    SniffExecution {
        outcome: SniffOutcome {
            stream: PrefixedStream::new(prefix, stream),
            domain,
            protocol,
        },
        result,
        error,
    }
}

async fn read_sniff_prefix<S>(stream: &mut S, prefix: &mut Vec<u8>) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut buf = [0u8; 512];

    loop {
        if prefix.len() >= MAX_SNIFF_PREFIX_LEN {
            return Ok(());
        }

        match probe_prefix(prefix) {
            ProbeState::Matched { .. } | ProbeState::NotMatched => return Ok(()),
            ProbeState::NeedMoreData => {}
        }

        let remaining = MAX_SNIFF_PREFIX_LEN - prefix.len();
        let read_len = remaining.min(buf.len());
        let n = stream.read(&mut buf[..read_len]).await?;
        if n == 0 {
            return Ok(());
        }
        prefix.extend_from_slice(&buf[..n]);
    }
}

fn finalize_sniff_result(prefix: &[u8]) -> SniffResult {
    match probe_prefix(prefix) {
        ProbeState::Matched { domain, protocol } => SniffResult::Matched { domain, protocol },
        ProbeState::NotMatched => SniffResult::NotMatched,
        ProbeState::NeedMoreData => SniffResult::Unsupported,
    }
}

enum ProbeState {
    Matched {
        domain: String,
        protocol: SniffedProtocol,
    },
    NeedMoreData,
    NotMatched,
}

fn probe_prefix(prefix: &[u8]) -> ProbeState {
    match probe_tls_client_hello(prefix) {
        ProbeState::Matched { domain, protocol } => {
            return ProbeState::Matched { domain, protocol };
        }
        ProbeState::NeedMoreData => return ProbeState::NeedMoreData,
        ProbeState::NotMatched => {}
    }

    probe_http_host(prefix)
}

fn probe_tls_client_hello(prefix: &[u8]) -> ProbeState {
    if prefix.is_empty() {
        return ProbeState::NeedMoreData;
    }

    if prefix[0] != 0x16 {
        return ProbeState::NotMatched;
    }

    if prefix.len() < 5 {
        return ProbeState::NeedMoreData;
    }

    let record_len = u16::from_be_bytes([prefix[3], prefix[4]]) as usize;
    let record_end = 5 + record_len;
    if prefix.len() < record_end {
        return ProbeState::NeedMoreData;
    }

    if prefix.get(5) != Some(&0x01) {
        return ProbeState::NotMatched;
    }

    if prefix.len() < 9 {
        return ProbeState::NeedMoreData;
    }

    let handshake_len =
        ((prefix[6] as usize) << 16) | ((prefix[7] as usize) << 8) | prefix[8] as usize;
    let handshake_end = 9 + handshake_len;
    if handshake_end > record_end || prefix.len() < handshake_end {
        return ProbeState::NeedMoreData;
    }

    let mut cursor = 9;
    if !advance(&mut cursor, handshake_end, 2 + 32) {
        return ProbeState::NotMatched;
    }

    let session_id_len = match read_u8(prefix, &mut cursor, handshake_end) {
        Some(value) => value as usize,
        None => return ProbeState::NotMatched,
    };
    if !advance(&mut cursor, handshake_end, session_id_len) {
        return ProbeState::NotMatched;
    }

    let cipher_suites_len = match read_u16(prefix, &mut cursor, handshake_end) {
        Some(value) => value as usize,
        None => return ProbeState::NotMatched,
    };
    if cipher_suites_len == 0 || !advance(&mut cursor, handshake_end, cipher_suites_len) {
        return ProbeState::NotMatched;
    }

    let compression_methods_len = match read_u8(prefix, &mut cursor, handshake_end) {
        Some(value) => value as usize,
        None => return ProbeState::NotMatched,
    };
    if compression_methods_len == 0 || !advance(&mut cursor, handshake_end, compression_methods_len)
    {
        return ProbeState::NotMatched;
    }

    let extensions_len = match read_u16(prefix, &mut cursor, handshake_end) {
        Some(value) => value as usize,
        None => return ProbeState::NotMatched,
    };
    let extensions_end = cursor + extensions_len;
    if extensions_end > handshake_end {
        return ProbeState::NotMatched;
    }

    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([prefix[cursor], prefix[cursor + 1]]);
        cursor += 2;
        let ext_len = u16::from_be_bytes([prefix[cursor], prefix[cursor + 1]]) as usize;
        cursor += 2;
        if cursor + ext_len > extensions_end {
            return ProbeState::NotMatched;
        }

        if ext_type == 0x0000 {
            if let Some(domain) = parse_server_name_extension(&prefix[cursor..cursor + ext_len]) {
                return ProbeState::Matched {
                    domain,
                    protocol: SniffedProtocol::Tls,
                };
            }
            return ProbeState::NotMatched;
        }

        cursor += ext_len;
    }

    ProbeState::NotMatched
}

fn parse_server_name_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + list_len > data.len() {
        return None;
    }

    let mut cursor = 2;
    let end = 2 + list_len;
    while cursor + 3 <= end {
        let name_type = data[cursor];
        cursor += 1;
        let name_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
        cursor += 2;
        if cursor + name_len > end {
            return None;
        }

        if name_type == 0 {
            let host = std::str::from_utf8(&data[cursor..cursor + name_len]).ok()?;
            return normalize_domain(host);
        }

        cursor += name_len;
    }

    None
}

fn probe_http_host(prefix: &[u8]) -> ProbeState {
    if prefix.is_empty() {
        return ProbeState::NeedMoreData;
    }

    if !looks_like_http_prefix(prefix) {
        return ProbeState::NotMatched;
    }

    let Some(headers_end) = find_http_headers_end(prefix) else {
        return ProbeState::NeedMoreData;
    };

    let request = match std::str::from_utf8(&prefix[..headers_end]) {
        Ok(request) => request,
        Err(_) => return ProbeState::NotMatched,
    };
    let mut lines = request.lines();
    let Some(request_line) = lines.next() else {
        return ProbeState::NotMatched;
    };
    let request_line = request_line.trim_end_matches('\r');
    if !request_line.contains(" HTTP/1.") {
        return ProbeState::NotMatched;
    }

    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }

        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("host") {
            if let Some(domain) = normalize_http_host(value) {
                return ProbeState::Matched {
                    domain,
                    protocol: SniffedProtocol::Http,
                };
            }
        }
    }

    ProbeState::NotMatched
}

fn looks_like_http_prefix(prefix: &[u8]) -> bool {
    let first_line_end = prefix.iter().position(|byte| *byte == b'\n');
    let candidate = match first_line_end {
        Some(end) => &prefix[..end],
        None => prefix,
    };

    candidate
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ' || *byte == b'\r')
        && candidate
            .iter()
            .take_while(|byte| byte.is_ascii_alphabetic())
            .count()
            >= 3
}

fn find_http_headers_end(prefix: &[u8]) -> Option<usize> {
    prefix
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .or_else(|| {
            prefix
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| index + 2)
        })
}

fn normalize_http_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some(stripped) = value.strip_prefix('[') {
        let end = stripped.find(']')?;
        return normalize_domain(&stripped[..end]);
    }

    let host = value.split(':').next().unwrap_or(value);
    normalize_domain(host)
}

fn normalize_domain(value: &str) -> Option<String> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn read_u8(data: &[u8], cursor: &mut usize, end: usize) -> Option<u8> {
    if *cursor + 1 > end {
        return None;
    }
    let value = data[*cursor];
    *cursor += 1;
    Some(value)
}

fn read_u16(data: &[u8], cursor: &mut usize, end: usize) -> Option<u16> {
    if *cursor + 2 > end {
        return None;
    }
    let value = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]);
    *cursor += 2;
    Some(value)
}

fn advance(cursor: &mut usize, end: usize, len: usize) -> bool {
    if *cursor + len > end {
        return false;
    }
    *cursor += len;
    true
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use super::{
        sniff_stream, sniff_stream_internal, PrefixedStream, SniffResult, SniffedProtocol,
    };

    enum ReadStep {
        Data(Vec<u8>),
        Error(io::Error),
        Eof,
    }

    struct ScriptedStream {
        read_steps: VecDeque<ReadStep>,
        written: Vec<u8>,
    }

    impl ScriptedStream {
        fn new(read_steps: impl IntoIterator<Item = ReadStep>) -> Self {
            Self {
                read_steps: read_steps.into_iter().collect(),
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for ScriptedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.read_steps.pop_front().unwrap_or(ReadStep::Eof) {
                ReadStep::Data(data) => {
                    buf.put_slice(&data);
                    Poll::Ready(Ok(()))
                }
                ReadStep::Error(err) => {
                    Poll::Ready(Err(io::Error::new(err.kind(), err.to_string())))
                }
                ReadStep::Eof => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for ScriptedStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PendingStream;

    impl AsyncRead for PendingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct CountingStream {
        read_steps: VecDeque<ReadStep>,
        read_polls: Arc<AtomicUsize>,
    }

    impl CountingStream {
        fn new(
            read_steps: impl IntoIterator<Item = ReadStep>,
            read_polls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                read_steps: read_steps.into_iter().collect(),
                read_polls,
            }
        }
    }

    impl AsyncRead for CountingStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.read_polls.fetch_add(1, Ordering::SeqCst);
            match self.read_steps.pop_front().unwrap_or(ReadStep::Eof) {
                ReadStep::Data(data) => {
                    buf.put_slice(&data);
                    Poll::Ready(Ok(()))
                }
                ReadStep::Error(err) => {
                    Poll::Ready(Err(io::Error::new(err.kind(), err.to_string())))
                }
                ReadStep::Eof => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for CountingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn tls_sni_sniff_succeeds_and_replays_prefix() {
        let payload = tls_client_hello_with_sni("www.example.com");
        let execution = sniff_stream_internal(
            ScriptedStream::new([ReadStep::Data(payload.clone()), ReadStep::Eof]),
            Duration::from_millis(300),
        )
        .await;

        assert_eq!(
            execution.result,
            SniffResult::Matched {
                domain: "www.example.com".into(),
                protocol: SniffedProtocol::Tls,
            }
        );

        let mut stream = execution.outcome.stream;
        let mut replayed = Vec::new();
        stream
            .read_to_end(&mut replayed)
            .await
            .expect("replayed payload should read");
        assert_eq!(replayed, payload);
    }

    #[tokio::test]
    async fn http_host_sniff_succeeds_case_insensitively() {
        let request = b"GET / HTTP/1.1\r\nhOsT: Example.COM\r\nUser-Agent: test\r\n\r\n".to_vec();
        let outcome = sniff_stream(
            ScriptedStream::new([ReadStep::Data(request), ReadStep::Eof]),
            Duration::from_millis(300),
        )
        .await;

        assert_eq!(outcome.domain.as_deref(), Some("example.com"));
        assert_eq!(outcome.protocol, Some(SniffedProtocol::Http));
    }

    #[tokio::test]
    async fn sniff_reports_no_match_for_unsupported_prefix() {
        let execution = sniff_stream_internal(
            ScriptedStream::new([ReadStep::Data(b"\x01\x02\x03\x04".to_vec()), ReadStep::Eof]),
            Duration::from_millis(300),
        )
        .await;

        assert_eq!(execution.result, SniffResult::NotMatched);
        assert!(execution.outcome.domain.is_none());
        assert!(execution.outcome.protocol.is_none());
    }

    #[tokio::test]
    async fn prefixed_stream_does_not_read_inner_until_prefix_is_exhausted() {
        let read_polls = Arc::new(AtomicUsize::new(0));
        let mut stream = PrefixedStream::new(
            b"abcd".to_vec(),
            CountingStream::new(
                [ReadStep::Data(b"ef".to_vec()), ReadStep::Eof],
                Arc::clone(&read_polls),
            ),
        );

        let mut first = [0u8; 2];
        stream
            .read_exact(&mut first)
            .await
            .expect("first prefix chunk should be readable");
        assert_eq!(&first, b"ab");
        assert_eq!(read_polls.load(Ordering::SeqCst), 0);

        let mut second = [0u8; 2];
        stream
            .read_exact(&mut second)
            .await
            .expect("second prefix chunk should be readable");
        assert_eq!(&second, b"cd");
        assert_eq!(read_polls.load(Ordering::SeqCst), 0);

        let mut third = [0u8; 2];
        stream
            .read_exact(&mut third)
            .await
            .expect("inner bytes should be readable after prefix is exhausted");
        assert_eq!(&third, b"ef");
        assert_eq!(read_polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn prefixed_stream_replays_prefix_once_and_then_hits_eof() {
        let read_polls = Arc::new(AtomicUsize::new(0));
        let mut stream = PrefixedStream::new(
            b"ab".to_vec(),
            CountingStream::new([ReadStep::Eof], Arc::clone(&read_polls)),
        );

        let mut replayed = Vec::new();
        stream
            .read_to_end(&mut replayed)
            .await
            .expect("prefixed stream should read to eof");

        assert_eq!(replayed, b"ab");
        assert_eq!(read_polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tls_half_packet_reports_unsupported_without_panicking() {
        let payload = tls_client_hello_with_sni("www.example.com");
        let execution = sniff_stream_internal(
            ScriptedStream::new([ReadStep::Data(payload[..12].to_vec()), ReadStep::Eof]),
            Duration::from_millis(300),
        )
        .await;

        assert_eq!(execution.result, SniffResult::Unsupported);
        assert!(execution.outcome.domain.is_none());
    }

    #[tokio::test]
    async fn tls_incomplete_length_field_reports_unsupported() {
        let execution = sniff_stream_internal(
            ScriptedStream::new([ReadStep::Data(vec![0x16, 0x03, 0x01, 0x00]), ReadStep::Eof]),
            Duration::from_millis(300),
        )
        .await;

        assert_eq!(execution.result, SniffResult::Unsupported);
    }

    #[tokio::test]
    async fn tls_like_non_client_hello_is_not_matched() {
        let execution = sniff_stream_internal(
            ScriptedStream::new([
                ReadStep::Data(vec![0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]),
                ReadStep::Eof,
            ]),
            Duration::from_millis(300),
        )
        .await;

        assert_eq!(execution.result, SniffResult::NotMatched);
    }

    #[tokio::test]
    async fn sniff_timeout_is_best_effort() {
        let execution = sniff_stream_internal(PendingStream, Duration::from_millis(10)).await;
        assert_eq!(execution.result, SniffResult::Timeout);
        assert!(execution.outcome.domain.is_none());
    }

    #[tokio::test]
    async fn sniff_read_error_is_reported_as_unsupported_without_losing_prefix() {
        let payload = b"GET / HTTP/1.1\r\n".to_vec();
        let execution = sniff_stream_internal(
            ScriptedStream::new([
                ReadStep::Data(payload.clone()),
                ReadStep::Error(io::Error::other("boom")),
            ]),
            Duration::from_millis(300),
        )
        .await;

        assert_eq!(execution.result, SniffResult::Unsupported);
        assert!(execution
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("boom"));

        let mut stream = execution.outcome.stream;
        let mut replayed = Vec::new();
        stream
            .read_to_end(&mut replayed)
            .await
            .expect("prefixed stream should still replay bytes read before the error");
        assert_eq!(replayed, payload);
    }

    #[tokio::test]
    async fn prefixed_stream_keeps_writes_forwarded() {
        let mut stream = sniff_stream(
            ScriptedStream::new([ReadStep::Data(b"ping".to_vec()), ReadStep::Eof]),
            Duration::from_millis(300),
        )
        .await
        .stream;

        stream
            .write_all(b"pong")
            .await
            .expect("prefixed stream should forward writes");
    }

    #[tokio::test]
    async fn http_incomplete_headers_report_unsupported() {
        let execution = sniff_stream_internal(
            ScriptedStream::new([
                ReadStep::Data(b"GET / HTTP/1.1\r\nHost: example.com\r\n".to_vec()),
                ReadStep::Eof,
            ]),
            Duration::from_millis(300),
        )
        .await;

        assert_eq!(execution.result, SniffResult::Unsupported);
        assert!(execution.outcome.domain.is_none());
    }

    #[tokio::test]
    async fn http_request_without_host_is_not_matched() {
        let execution = sniff_stream_internal(
            ScriptedStream::new([
                ReadStep::Data(b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n".to_vec()),
                ReadStep::Eof,
            ]),
            Duration::from_millis(300),
        )
        .await;

        assert_eq!(execution.result, SniffResult::NotMatched);
        assert!(execution.outcome.domain.is_none());
    }

    fn tls_client_hello_with_sni(server_name: &str) -> Vec<u8> {
        let server_name_bytes = server_name.as_bytes();

        let mut server_name_ext = Vec::new();
        let list_len = 1 + 2 + server_name_bytes.len();
        server_name_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        server_name_ext.push(0);
        server_name_ext.extend_from_slice(&(server_name_bytes.len() as u16).to_be_bytes());
        server_name_ext.extend_from_slice(server_name_bytes);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(server_name_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name_ext);

        let mut client_hello = Vec::new();
        client_hello.extend_from_slice(&[0x03, 0x03]);
        client_hello.extend_from_slice(&[0u8; 32]);
        client_hello.push(0);
        client_hello.extend_from_slice(&2u16.to_be_bytes());
        client_hello.extend_from_slice(&[0x13, 0x01]);
        client_hello.push(1);
        client_hello.push(0);
        client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        client_hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let hello_len = client_hello.len() as u32;
        handshake.push(((hello_len >> 16) & 0xff) as u8);
        handshake.push(((hello_len >> 8) & 0xff) as u8);
        handshake.push((hello_len & 0xff) as u8);
        handshake.extend_from_slice(&client_hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
