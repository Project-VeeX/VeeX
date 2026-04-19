use std::time::Duration;

pub const DEFAULT_DIRECT_OUTBOUND_TAG: &str = "direct";

pub const DEFAULT_LOG_LEVEL: &str = "error";
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
