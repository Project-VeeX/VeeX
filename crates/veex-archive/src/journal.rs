use crate::{ArchiveSummary, Event, EventLevel};

/// 记录簿，保留关键事件并提供汇总。
#[derive(Debug, Clone, Default)]
pub struct Journal {
    events: Vec<Event>,
}

impl Journal {
    pub fn push(&mut self, event: Event) {
        self.events.push(event);
    }

    pub fn count_by_level(&self, level: EventLevel) -> usize {
        self.events.iter().filter(|event| event.level == level).count()
    }

    pub fn recent(&self, limit: usize) -> Vec<&Event> {
        self.events.iter().rev().take(limit).collect()
    }

    pub fn summary(&self) -> ArchiveSummary {
        ArchiveSummary {
            total: self.events.len(),
            warnings: self.count_by_level(EventLevel::Warning),
            criticals: self.count_by_level(EventLevel::Critical),
        }
    }
}
