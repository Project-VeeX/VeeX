use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinError;

use crate::{error::ProxyError, types::BoxedAsyncStream};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayStats {
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Debug)]
pub struct RelayErrorWithStats {
    pub stats: RelayStats,
    pub error: ProxyError,
}

pub type RelayResult = std::result::Result<RelayStats, RelayErrorWithStats>;

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
}

#[derive(Debug)]
struct OneWayRelayError {
    partial_bytes: u64,
    error: ProxyError,
}

type OneWayRelayResult = std::result::Result<u64, OneWayRelayError>;

pub async fn relay_bidirectional(
    inbound_stream: BoxedAsyncStream,
    outbound_stream: BoxedAsyncStream,
) -> RelayResult {
    let (inbound_reader, inbound_writer) = tokio::io::split(inbound_stream);
    let (outbound_reader, outbound_writer) = tokio::io::split(outbound_stream);
    let upstream_progress = Arc::new(AtomicU64::new(0));
    let downstream_progress = Arc::new(AtomicU64::new(0));

    let upstream = tokio::spawn(relay_one_way(
        inbound_reader,
        outbound_writer,
        Direction::Upstream,
        Arc::clone(&upstream_progress),
    ));
    let downstream = tokio::spawn(relay_one_way(
        outbound_reader,
        inbound_writer,
        Direction::Downstream,
        Arc::clone(&downstream_progress),
    ));

    wait_for_relay_tasks(
        upstream,
        downstream,
        &upstream_progress,
        &downstream_progress,
    )
    .await
}

async fn relay_one_way<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    progress: Arc<AtomicU64>,
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
                error: ProxyError::relay(format!(
                    "{} relay read failed: {}",
                    direction.as_str(),
                    err
                )),
            })?;

        if read == 0 {
            writer.shutdown().await.map_err(|err| OneWayRelayError {
                partial_bytes: transferred,
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

async fn wait_for_relay_tasks(
    mut upstream: tokio::task::JoinHandle<OneWayRelayResult>,
    mut downstream: tokio::task::JoinHandle<OneWayRelayResult>,
    upstream_progress: &AtomicU64,
    downstream_progress: &AtomicU64,
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

    use super::{map_join_result, relay_bidirectional, Direction, OneWayRelayError};
    use crate::types::BoxedAsyncStream;

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
        assert_eq!(err.error.kind(), crate::ErrorKind::Relay);
    }
}
