use serde::{Deserialize, Serialize};

/// 记忆片段，保留必要痕迹并折叠重复部分。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Memory {
    pub traces: Vec<String>,
    pub retained: usize,
    pub folded: usize,
}

impl Memory {
    pub fn retain(&mut self, trace: impl Into<String>) {
        self.traces.push(trace.into());
        self.retained += 1;
    }

    pub fn fold(&mut self, trace: impl Into<String>) {
        let trace = trace.into();

        if let Some(last) = self.traces.last_mut() {
            *last = trace;
        } else {
            self.traces.push(trace);
        }

        self.folded += 1;
    }

    pub fn snapshot(&self) -> String {
        match self.traces.last() {
            Some(last) => {
                format!("保留 {} 条，折叠 {} 条，最近片段：{}", self.retained, self.folded, last)
            }
            None => format!("保留 {} 条，折叠 {} 条。", self.retained, self.folded),
        }
    }
}
