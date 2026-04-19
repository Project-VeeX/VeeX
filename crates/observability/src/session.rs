use std::time::Duration;

use crate::logging::{LogLevel, log_line};

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ErrorKind {
    Config,
    Dial,
    Resolve,
    Tls,
    Protocol,
    Relay,
    Timeout,
    Io,
    Shutdown,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Dial => "dial",
            Self::Resolve => "resolve",
            Self::Tls => "tls",
            Self::Protocol => "protocol",
            Self::Relay => "relay",
            Self::Timeout => "timeout",
            Self::Io => "io",
            Self::Shutdown => "shutdown",
        }
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Debug for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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
    pub error_kind: Option<ErrorKind>,
}

impl SessionSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn success(
        session_id: u64,
        inbound: impl Into<String>,
        outbound: impl Into<String>,
        peer: impl Into<String>,
        destination: impl Into<String>,
        bytes_up: u64,
        bytes_down: u64,
        duration: Duration,
    ) -> Self {
        Self::build(
            session_id,
            inbound,
            outbound,
            peer,
            destination,
            bytes_up,
            bytes_down,
            duration,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn failure(
        session_id: u64,
        inbound: impl Into<String>,
        outbound: impl Into<String>,
        peer: impl Into<String>,
        destination: impl Into<String>,
        bytes_up: u64,
        bytes_down: u64,
        duration: Duration,
        error_kind: ErrorKind,
    ) -> Self {
        Self::build(
            session_id,
            inbound,
            outbound,
            peer,
            destination,
            bytes_up,
            bytes_down,
            duration,
            Some(error_kind),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        session_id: u64,
        inbound: impl Into<String>,
        outbound: impl Into<String>,
        peer: impl Into<String>,
        destination: impl Into<String>,
        bytes_up: u64,
        bytes_down: u64,
        duration: Duration,
        error_kind: Option<ErrorKind>,
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
            error_kind,
        }
    }
}

pub fn emit_session_summary(summary: &SessionSummary) {
    log_line(LogLevel::Info, &format_session_summary(summary));
}

pub fn emit_session_finish<E>(summary: &SessionSummary, route_reason: &str, error: Option<&E>)
where
    E: std::fmt::Display,
{
    match (summary.error_kind, error) {
        (Some(error_kind), Some(error)) => {
            tracing::warn!(
                event = "session_finish",
                session_id = summary.session_id,
                inbound = %summary.inbound,
                peer = %summary.peer,
                destination = %summary.destination,
                outbound = %summary.outbound,
                route_reason,
                success = false,
                duration_ms = summary.duration.as_millis(),
                bytes_up = summary.bytes_up,
                bytes_down = summary.bytes_down,
                error_kind = %error_kind,
                error = %error,
                "session finished with error"
            );
        }
        (Some(error_kind), None) => {
            tracing::warn!(
                event = "session_finish",
                session_id = summary.session_id,
                inbound = %summary.inbound,
                peer = %summary.peer,
                destination = %summary.destination,
                outbound = %summary.outbound,
                route_reason,
                success = false,
                duration_ms = summary.duration.as_millis(),
                bytes_up = summary.bytes_up,
                bytes_down = summary.bytes_down,
                error_kind = %error_kind,
                "session finished with error"
            );
        }
        (None, _) => {
            tracing::info!(
                event = "session_finish",
                session_id = summary.session_id,
                inbound = %summary.inbound,
                peer = %summary.peer,
                destination = %summary.destination,
                outbound = %summary.outbound,
                route_reason,
                success = true,
                duration_ms = summary.duration.as_millis(),
                bytes_up = summary.bytes_up,
                bytes_down = summary.bytes_down,
                "session finished"
            );
        }
    }
}

pub fn format_session_summary(summary: &SessionSummary) -> String {
    let duration_ms = summary.duration.as_millis();
    let error_kind = summary.error_kind.map(ErrorKind::as_str).unwrap_or("none");

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

    use super::{ErrorKind, SessionSummary, format_session_summary};

    #[test]
    fn formats_session_summary_as_flat_kv_line() {
        let summary = SessionSummary::failure(
            7,
            "socks-in",
            "proxy",
            "127.0.0.1:10000",
            "example.com:443",
            12,
            34,
            Duration::from_millis(56),
            ErrorKind::Tls,
        );

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
