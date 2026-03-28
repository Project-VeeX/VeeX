use serde::{Deserialize, Serialize};

/// 上下文帧，保留短期片段与长期权重。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextFrame {
    pub short_term: Vec<String>,
    pub long_term_weight: usize,
}

impl ContextFrame {
    pub fn capture(&mut self, line: impl Into<String>) {
        self.short_term.push(line.into());
        if self.short_term.len() > 3 {
            self.short_term.remove(0);
            self.long_term_weight += 1;
        }
    }
}
