use veex_signal::{Phase, Stability};

/// 单轮推进结果。
#[derive(Debug, Clone)]
pub struct StepOutcome {
    pub cycle: u32,
    pub phase: Phase,
    pub summary: String,
}

/// 整体运行结果。
#[derive(Debug, Clone)]
pub struct OrbitReport {
    pub total_cycles: u32,
    pub final_phase: Phase,
    pub final_stability: Stability,
    pub synchronized: bool,
    pub expression_count: usize,
    pub steps: Vec<StepOutcome>,
}
