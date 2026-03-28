use serde::{Deserialize, Serialize};

/// 事件级别，用于区分观测强度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventLevel {
    Note,
    Warning,
    Critical,
}

/// 事件记录，保留周期、级别与摘要。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub cycle: u32,
    pub level: EventLevel,
    pub message: String,
}
