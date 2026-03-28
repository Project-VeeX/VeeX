use tokio::time::{sleep, Duration};
use veex_archive::{Event, EventLevel, Journal};
use veex_echo::{compose_expression, ContextFrame};
use veex_signal::{Phase, SignalState};

use crate::{
    cycle::{OrbitReport, StepOutcome},
    stabilizer::normalize_after_peak,
};

/// 周期调度器，负责推进阶段并生成汇总结果。
#[derive(Debug, Clone)]
pub struct OrbitScheduler {
    max_cycles: u32,
}

impl OrbitScheduler {
    pub fn new(max_cycles: u32) -> Self {
        Self { max_cycles }
    }

    pub async fn run(
        &self,
        state: &mut SignalState,
        context: &mut ContextFrame,
        journal: &mut Journal,
    ) -> OrbitReport {
        let mut expression_count = 0usize;
        let mut steps = Vec::new();

        for _ in 0..self.max_cycles {
            let outcome = self.tick(state, context, journal).await;
            expression_count += 1;
            let should_stop = outcome.phase == Phase::Stabilized;
            steps.push(outcome);

            if should_stop {
                break;
            }
        }

        OrbitReport {
            total_cycles: state.cycle,
            final_phase: state.phase,
            final_stability: state.stability,
            synchronized: state.synchronized,
            expression_count,
            steps,
        }
    }

    pub async fn tick(
        &self,
        state: &mut SignalState,
        context: &mut ContextFrame,
        journal: &mut Journal,
    ) -> StepOutcome {
        sleep(Duration::from_millis(60)).await;

        match state.phase {
            Phase::Dormant => {
                journal.push(Event {
                    cycle: state.cycle,
                    level: EventLevel::Note,
                    message: "初始状态已建立。".to_string(),
                });
            }
            Phase::Active => {
                state.stability.disturb();
                state.memory.fold("偏移仍在抬升。");
                if state.stability.drift >= 22 {
                    journal.push(Event {
                        cycle: state.cycle + 1,
                        level: EventLevel::Warning,
                        message: "高活跃区已被标记。".to_string(),
                    });
                }
            }
            Phase::Aligning => {
                normalize_after_peak(state);
                if state.stability.drift >= 24 {
                    journal.push(Event {
                        cycle: state.cycle + 1,
                        level: EventLevel::Critical,
                        message: "局部失衡接近阈值。".to_string(),
                    });
                } else {
                    journal.push(Event {
                        cycle: state.cycle + 1,
                        level: EventLevel::Note,
                        message: "校准正在进行。".to_string(),
                    });
                }
            }
            Phase::Converging => {
                journal.push(Event {
                    cycle: state.cycle + 1,
                    level: EventLevel::Note,
                    message: "收敛段保持稳定推进。".to_string(),
                });
            }
            Phase::Stabilized => {
                journal.push(Event {
                    cycle: state.cycle,
                    level: EventLevel::Note,
                    message: "稳定阶段已确认。".to_string(),
                });
            }
        }

        let next_phase = match state.phase {
            Phase::Dormant => Phase::Active,
            Phase::Active if state.stability.needs_alignment() => Phase::Aligning,
            Phase::Active => Phase::Active,
            Phase::Aligning if state.cycle >= 3 => Phase::Converging,
            Phase::Aligning => Phase::Aligning,
            Phase::Converging if state.stability.level >= 80 && state.stability.drift <= 10 => {
                Phase::Stabilized
            }
            Phase::Converging => Phase::Converging,
            Phase::Stabilized => Phase::Stabilized,
        };

        match next_phase {
            Phase::Active => state.mark_active(),
            Phase::Aligning => state.align(),
            Phase::Converging => state.converge(),
            Phase::Stabilized => {
                state.stabilize();
                journal.push(Event {
                    cycle: state.cycle,
                    level: EventLevel::Note,
                    message: "系统已回落至稳定域。".to_string(),
                });
            }
            Phase::Dormant => {}
        }

        let expression = compose_expression(state, context);
        context.capture(expression.line.clone());

        StepOutcome { cycle: state.cycle, phase: state.phase, summary: expression.line }
    }
}
