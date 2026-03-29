use std::time::Duration;

use crate::logging::{log_line, LogLevel};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSummary {
    pub session_id: u64,
    pub inbound: String,
    pub outbound: String,
    pub peer: String,
    pub destination: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub duration: Duration,
    pub error_kind: Option<String>,
}

impl SessionSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn succeeded(
        session_id: u64,
        inbound: impl Into<String>,
        outbound: impl Into<String>,
        peer: impl Into<String>,
        destination: impl Into<String>,
        bytes_up: u64,
        bytes_down: u64,
        duration: Duration,
    ) -> Self {
        Self {
            session_id,
            inbound: inbound.into(),
            outbound: outbound.into(),
            peer: peer.into(),
            destination: destination.into(),
            bytes_up,
            bytes_down,
            duration,
            error_kind: None,
        }
    }

    pub fn failed(mut self, error_kind: impl Into<String>) -> Self {
        self.error_kind = Some(error_kind.into());
        self
    }
}

pub fn emit_session_summary(summary: &SessionSummary) {
    log_line(LogLevel::Info, &format_session_summary(summary));
}

pub fn format_session_summary(summary: &SessionSummary) -> String {
    let duration_ms = summary.duration.as_millis();
    let error_kind = summary.error_kind.as_deref().unwrap_or("none");

    format!(
        "event=session_finish session_id={} inbound={} outbound={} peer={} dest={} bytes_up={} bytes_down={} duration_ms={} error_kind={}",
        summary.session_id,
        summary.inbound,
        summary.outbound,
        summary.peer,
        summary.destination,
        summary.bytes_up,
        summary.bytes_down,
        duration_ms,
        error_kind,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{format_session_summary, SessionSummary};

    #[test]
    fn formats_session_summary_as_flat_kv_line() {
        let summary = SessionSummary::succeeded(
            7,
            "socks-in",
            "proxy",
            "127.0.0.1:10000",
            "example.com:443",
            12,
            34,
            Duration::from_millis(56),
        )
        .failed("tls");

        let line = format_session_summary(&summary);
        assert!(line.contains("event=session_finish"));
        assert!(line.contains("session_id=7"));
        assert!(line.contains("inbound=socks-in"));
        assert!(line.contains("outbound=proxy"));
        assert!(line.contains("peer=127.0.0.1:10000"));
        assert!(line.contains("dest=example.com:443"));
        assert!(line.contains("bytes_up=12"));
        assert!(line.contains("bytes_down=34"));
        assert!(line.contains("duration_ms=56"));
        assert!(line.contains("error_kind=tls"));
    }
}
