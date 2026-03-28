use serde::{Deserialize, Serialize};

use crate::{Memory, Phase};

/// 稳定度与偏移值，用于表达当前状态的张力。
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Stability {
    pub level: u8,
    pub drift: u8,
}

impl Stability {
    pub fn reinforce(&mut self) {
        self.level = self.level.saturating_add(8).min(100);
        self.drift = self.drift.saturating_sub(7);
    }

    pub fn disturb(&mut self) {
        self.level = self.level.saturating_sub(6);
        self.drift = self.drift.saturating_add(9).min(100);
    }

    pub fn needs_alignment(&self) -> bool {
        self.drift >= 18 || self.level <= 55
    }
}

/// 信号状态，贯穿整个推进过程。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalState {
    pub phase: Phase,
    pub stability: Stability,
    pub cycle: u32,
    pub memory: Memory,
    pub synchronized: bool,
}

impl SignalState {
    pub fn new() -> Self {
        let mut memory = Memory::default();
        memory.retain("记录已建立。");

        Self {
            phase: Phase::Dormant,
            stability: Stability { level: 58, drift: 4 },
            cycle: 0,
            memory,
            synchronized: true,
        }
    }

    pub fn mark_active(&mut self) {
        self.phase = Phase::Active;
        self.cycle += 1;
        self.stability.disturb();
        self.synchronized = false;
        self.memory.retain("过程开始活跃。");
    }

    pub fn align(&mut self) {
        self.phase = Phase::Aligning;
        self.cycle += 1;
        self.stability.level = self.stability.level.saturating_add(4).min(100);
        self.stability.drift = self.stability.drift.saturating_sub(3);
        self.synchronized = false;
        self.memory.retain("局部偏移已进入处理。");
    }

    pub fn converge(&mut self) {
        self.phase = Phase::Converging;
        self.cycle += 1;
        self.stability.reinforce();
        self.synchronized = self.stability.drift <= 12;
        self.memory.fold("异常已被吸收。");
    }

    pub fn stabilize(&mut self) {
        self.phase = Phase::Stabilized;
        self.cycle += 1;
        self.stability.reinforce();
        self.stability.drift = 8;
        self.synchronized = true;
        self.memory.retain("系统已回落至稳定域。");
    }
}
