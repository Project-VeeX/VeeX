use serde::{Deserialize, Serialize};

/// 归档摘要，用于最终输出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveSummary {
    pub total: usize,
    pub warnings: usize,
    pub criticals: usize,
}
