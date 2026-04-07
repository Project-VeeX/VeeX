use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinError;
use tracing::debug;

use crate::{error::ProxyError, types::BoxedAsyncStream};

/// Byte transfer statistics for a relay session.
///
/// These are observed engineering metrics, not billing-grade counters.
/// Partial counts are preserved on failure to aid diagnostics:
/// a session that fails mid-stream will report non-zero bytes rather
/// than collapsing to 0/0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayStats {
    /// Bytes transferred from client to server (upstream).
    pub bytes_up: u64,
    /// Bytes transferred from server to client (downstream).
    pub bytes_down: u64,
}

/// Relay error with accompanying transfer statistics.
///
/// Returned when a relay operation fails, preserving the partial
/// byte counts at the time of failure for diagnostics.
#[derive(Debug)]
pub struct RelayErrorWithStats {
    /// Observed byte counts at the time of failure.
    pub stats: RelayStats,
    /// The underlying relay error.
    pub error: ProxyError,
    /// The direction in which the error occurred.
    pub direction: &'static str,
    /// Whether the opposite direction was already half-closed when the error occurred.
    pub has_half_close: bool,
}

pub type RelayResult = std::result::Result<RelayStats, RelayErrorWithStats>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RelayTraceContext {
    pub session_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Upstream,
    Downstream,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Downstream => "downstream",
        }
    }

    fn read_failure(self) -> &'static str {
        match self {
            Self::Upstream => "upstream_read",
            Self::Downstream => "downstream_read",
        }
    }

    fn write_failure(self) -> &'static str {
        match self {
            Self::Upstream => "upstream_write",
            Self::Downstream => "downstream_write",
        }
    }

    fn shutdown_failure(self) -> &'static str {
        match self {
            Self::Upstream => "upstream_shutdown",
            Self::Downstream => "downstream_shutdown",
        }
    }

    fn join_failure(self) -> &'static str {
        match self {
            Self::Upstream => "upstream_task",
            Self::Downstream => "downstream_task",
        }
    }
}

#[derive(Debug)]
struct OneWayRelayError {
    partial_bytes: u64,
    direction: &'static str,
    error: ProxyError,
}

type OneWayRelayResult = std::result::Result<u64, OneWayRelayError>;

pub async fn relay_bidirectional(
    inbound_stream: BoxedAsyncStream,
    outbound_stream: BoxedAsyncStream,
) -> RelayResult {
    relay_bidirectional_with_trace(inbound_stream, outbound_stream, None).await
}

pub(crate) async fn relay_bidirectional_with_trace(
    inbound_stream: BoxedAsyncStream,
    outbound_stream: BoxedAsyncStream,
    trace: Option<RelayTraceContext>,
) -> RelayResult {
    // Relay keeps transport-agnostic data-plane events local to the relay module.
    let (inbound_reader, inbound_writer) = tokio::io::split(inbound_stream);
    let (outbound_reader, outbound_writer) = tokio::io::split(outbound_stream);
    let upstream_progress = Arc::new(AtomicU64::new(0));
    let downstream_progress = Arc::new(AtomicU64::new(0));
    let half_close_seen = Arc::new(AtomicBool::new(false));

    let upstream = tokio::spawn(relay_one_way(
        inbound_reader,
        outbound_writer,
        Direction::Upstream,
        Arc::clone(&upstream_progress),
        trace,
        Arc::clone(&half_close_seen),
    ));
    let downstream = tokio::spawn(relay_one_way(
        outbound_reader,
        inbound_writer,
        Direction::Downstream,
        Arc::clone(&downstream_progress),
        trace,
        Arc::clone(&half_close_seen),
    ));

    wait_for_relay_tasks(
        upstream,
        downstream,
        &upstream_progress,
        &downstream_progress,
        &half_close_seen,
    )
    .await
}

async fn relay_one_way<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    progress: Arc<AtomicU64>,
    trace: Option<RelayTraceContext>,
    half_close_seen: Arc<AtomicBool>,
) -> OneWayRelayResult
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = [0u8; 16 * 1024];

    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|err| OneWayRelayError {
                partial_bytes: transferred,
                direction: direction.read_failure(),
                error: ProxyError::relay(format!(
                    "{} relay read failed: {}",
                    direction.as_str(),
                    err
                )),
            })?;

        if read == 0 {
            half_close_seen.store(true, Ordering::Relaxed);
            if let Some(trace) = trace {
                log_relay_half_close(trace, direction, transferred);
            }
            writer.shutdown().await.map_err(|err| OneWayRelayError {
                partial_bytes: transferred,
                direction: direction.shutdown_failure(),
                error: ProxyError::relay(format!(
                    "{} relay shutdown failed after eof: {}",
                    direction.as_str(),
                    err
                )),
            })?;
            progress.store(transferred, Ordering::Relaxed);
            return Ok(transferred);
        }

        writer
            .write_all(&buffer[..read])
            .await
            .map_err(|err| OneWayRelayError {
                partial_bytes: transferred,
                direction: direction.write_failure(),
                error: ProxyError::relay(format!(
                    "{} relay write failed: {}",
                    direction.as_str(),
                    err
                )),
            })?;

        transferred += read as u64;
        progress.store(transferred, Ordering::Relaxed);
    }
}

fn log_relay_half_close(trace: RelayTraceContext, direction: Direction, transferred: u64) {
    debug!(
        event = "relay_half_close",
        session_id = trace.session_id,
        direction = direction.as_str(),
        bytes_transferred = transferred,
        "relay half close"
    );
}

async fn wait_for_relay_tasks(
    mut upstream: tokio::task::JoinHandle<OneWayRelayResult>,
    mut downstream: tokio::task::JoinHandle<OneWayRelayResult>,
    upstream_progress: &AtomicU64,
    downstream_progress: &AtomicU64,
    half_close_seen: &AtomicBool,
) -> RelayResult {
    tokio::select! {
        upstream_join = &mut upstream => {
            let upstream_result = map_join_result(upstream_join, Direction::Upstream, upstream_progress);
            match upstream_result {
                Ok(_) => {
                    let downstream_result = map_join_result(
                        downstream.await,
                        Direction::Downstream,
                        downstream_progress,
                    );
                    finish_after_both_completed(
                        upstream_result,
                        downstream_result,
                        upstream_progress,
                        downstream_progress,
                        half_close_seen,
                    )
                }
                Err(err) => {
                    downstream.abort();
                    let _ = downstream.await;
                    Err(RelayErrorWithStats {
                        stats: RelayStats {
                            bytes_up: err
                                .partial_bytes
                                .max(upstream_progress.load(Ordering::Relaxed)),
                            bytes_down: downstream_progress.load(Ordering::Relaxed),
                        },
                        error: err.error,
                        direction: err.direction,
                        has_half_close: half_close_seen.load(Ordering::Relaxed),
                    })
                }
            }
        }
        downstream_join = &mut downstream => {
            let downstream_result = map_join_result(
                downstream_join,
                Direction::Downstream,
                downstream_progress,
            );
            match downstream_result {
                Ok(_) => {
                    let upstream_result = map_join_result(
                        upstream.await,
                        Direction::Upstream,
                        upstream_progress,
                    );
                    finish_after_both_completed(
                        upstream_result,
                        downstream_result,
                        upstream_progress,
                        downstream_progress,
                        half_close_seen,
                    )
                }
                Err(err) => {
                    upstream.abort();
                    let _ = upstream.await;
                    Err(RelayErrorWithStats {
                        stats: RelayStats {
                            bytes_up: upstream_progress.load(Ordering::Relaxed),
                            bytes_down: err
                                .partial_bytes
                                .max(downstream_progress.load(Ordering::Relaxed)),
                        },
                        error: err.error,
                        direction: err.direction,
                        has_half_close: half_close_seen.load(Ordering::Relaxed),
                    })
                }
            }
        }
    }
}

fn map_join_result(
    result: std::result::Result<OneWayRelayResult, JoinError>,
    direction: Direction,
    progress: &AtomicU64,
) -> OneWayRelayResult {
    match result {
        Ok(result) => result,
        Err(err) => Err(OneWayRelayError {
            partial_bytes: progress.load(Ordering::Relaxed),
            direction: direction.join_failure(),
            error: ProxyError::relay(format!(
                "{} relay task join failed: {}",
                direction.as_str(),
                err
            )),
        }),
    }
}

fn finish_after_both_completed(
    upstream_result: OneWayRelayResult,
    downstream_result: OneWayRelayResult,
    upstream_progress: &AtomicU64,
    downstream_progress: &AtomicU64,
    half_close_seen: &AtomicBool,
) -> RelayResult {
    let stats = stats_from_results(
        &upstream_result,
        &downstream_result,
        upstream_progress,
        downstream_progress,
    );
    match (upstream_result, downstream_result) {
        (Ok(_), Ok(_)) => Ok(stats),
        (Err(err), _) | (_, Err(err)) => Err(RelayErrorWithStats {
            stats,
            error: err.error,
            direction: err.direction,
            has_half_close: half_close_seen.load(Ordering::Relaxed),
        }),
    }
}

fn stats_from_results(
    upstream_result: &OneWayRelayResult,
    downstream_result: &OneWayRelayResult,
    upstream_progress: &AtomicU64,
    downstream_progress: &AtomicU64,
) -> RelayStats {
    RelayStats {
        bytes_up: match upstream_result {
            Ok(bytes) => *bytes,
            Err(err) => err
                .partial_bytes
                .max(upstream_progress.load(Ordering::Relaxed)),
        },
        bytes_down: match downstream_result {
            Ok(bytes) => *bytes,
            Err(err) => err
                .partial_bytes
                .max(downstream_progress.load(Ordering::Relaxed)),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        pin::Pin,
        sync::atomic::AtomicU64,
        task::{Context, Poll},
    };

    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        time::Duration,
    };

    use super::{
        map_join_result, relay_bidirectional, relay_bidirectional_with_trace, Direction,
        OneWayRelayError, RelayTraceContext,
    };
    use crate::{
        test_support::{assert_has_event, captured_events, install_test_subscriber},
        types::BoxedAsyncStream,
    };

    enum ReadStep {
        Data(&'static [u8]),
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

    struct PendingStream;
    impl AsyncRead for ScriptedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.read_steps.pop_front().unwrap_or(ReadStep::Eof) {
                ReadStep::Data(data) => {
                    buf.put_slice(data);
                    Poll::Ready(Ok(()))
                }
                ReadStep::Error(err) => Poll::Ready(Err(err)),
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
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn relay_success_keeps_bidirectional_stats() {
        let inbound: BoxedAsyncStream = Box::new(ScriptedStream::new([
            ReadStep::Data(b"ping"),
            ReadStep::Eof,
        ]));
        let outbound: BoxedAsyncStream = Box::new(ScriptedStream::new([
            ReadStep::Data(b"pong"),
            ReadStep::Eof,
        ]));

        let stats = relay_bidirectional(inbound, outbound)
            .await
            .expect("relay should succeed");

        assert_eq!(stats.bytes_up, 4);
        assert_eq!(stats.bytes_down, 4);
    }

    #[tokio::test]
    async fn upstream_failure_keeps_partial_stats() {
        let inbound: BoxedAsyncStream = Box::new(ScriptedStream::new([
            ReadStep::Data(b"ping"),
            ReadStep::Error(io::Error::other("boom")),
        ]));
        let outbound: BoxedAsyncStream = Box::new(ScriptedStream::new([
            ReadStep::Data(b"pong"),
            ReadStep::Eof,
        ]));

        let err = relay_bidirectional(inbound, outbound)
            .await
            .expect_err("relay should surface the upstream read error");

        assert_eq!(err.stats.bytes_up, 4);
        assert_eq!(err.stats.bytes_down, 4);
        assert_eq!(err.error.kind(), crate::ErrorKind::Relay);
    }

    #[tokio::test]
    async fn relay_half_close_event_is_emitted_on_eof() {
        let (_guard, trace_buffer) = install_test_subscriber();
        let inbound: BoxedAsyncStream = Box::new(ScriptedStream::new([
            ReadStep::Data(b"ping"),
            ReadStep::Eof,
        ]));
        let outbound: BoxedAsyncStream = Box::new(ScriptedStream::new([
            ReadStep::Data(b"pong"),
            ReadStep::Eof,
        ]));

        let stats = relay_bidirectional_with_trace(
            inbound,
            outbound,
            Some(RelayTraceContext { session_id: 15 }),
        )
        .await
        .expect("relay should succeed");

        assert_eq!(stats.bytes_up, 4);
        assert_eq!(stats.bytes_down, 4);

        let events = captured_events(&trace_buffer);
        assert_has_event(
            &events,
            "relay_half_close",
            &[
                ("session_id", "15"),
                ("direction", "upstream"),
                ("bytes_transferred", "4"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "relay_half_close",
            &[
                ("session_id", "15"),
                ("direction", "downstream"),
                ("bytes_transferred", "4"),
                ("level", "DEBUG"),
            ],
        );
    }

    #[tokio::test]
    async fn downstream_failure_keeps_partial_stats() {
        let inbound: BoxedAsyncStream = Box::new(ScriptedStream::new([
            ReadStep::Data(b"ping"),
            ReadStep::Eof,
        ]));
        let outbound: BoxedAsyncStream = Box::new(ScriptedStream::new([
            ReadStep::Data(b"pong"),
            ReadStep::Error(io::Error::other("boom")),
        ]));

        let err = relay_bidirectional(inbound, outbound)
            .await
            .expect_err("relay should surface the downstream read error");

        assert_eq!(err.stats.bytes_up, 4);
        assert_eq!(err.stats.bytes_down, 4);
        assert_eq!(err.error.kind(), crate::ErrorKind::Relay);
    }

    #[tokio::test]
    async fn join_error_is_mapped_to_relay_error() {
        let task = tokio::spawn(async move {
            panic!("boom");
            #[allow(unreachable_code)]
            Ok::<u64, OneWayRelayError>(0)
        });
        let progress = AtomicU64::new(0);

        let err = map_join_result(task.await, Direction::Upstream, &progress)
            .expect_err("join error should map to relay error");

        assert_eq!(err.partial_bytes, 0);
        assert_eq!(err.direction, "upstream_task");
        assert_eq!(err.error.kind(), crate::ErrorKind::Relay);
        assert!(
            err.error
                .to_string()
                .contains("upstream relay task join failed"),
            "unexpected error: {}",
            err.error
        );
    }

    #[tokio::test]
    async fn relay_failure_does_not_wait_for_pending_peer_direction() {
        let inbound: BoxedAsyncStream = Box::new(PendingStream);
        let outbound: BoxedAsyncStream = Box::new(ScriptedStream::new([ReadStep::Error(
            io::Error::other("boom"),
        )]));

        let err = tokio::time::timeout(
            Duration::from_millis(100),
            relay_bidirectional(inbound, outbound),
        )
        .await
        .expect("relay should not hang after one direction fails")
        .expect_err("relay should surface the upstream failure");

        assert_eq!(err.stats.bytes_up, 0);
        assert_eq!(err.stats.bytes_down, 0);
        assert_eq!(err.direction, "downstream_read");
        assert!(!err.has_half_close);
        assert_eq!(err.error.kind(), crate::ErrorKind::Relay);
    }
}
