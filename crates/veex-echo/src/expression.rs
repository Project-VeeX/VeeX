use serde::{Deserialize, Serialize};
use veex_signal::SignalState;

use crate::{derive_pattern, ContextFrame, Pattern};

/// 表达结果，作为单轮摘要输出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Expression {
    pub pattern: Pattern,
    pub line: String,
}

pub fn compose_expression(state: &SignalState, context: &ContextFrame) -> Expression {
    let pattern = derive_pattern(&state.phase, state.stability.drift);
    let line = match (state.phase, pattern, state.stability.drift, context.long_term_weight) {
        (_, Pattern::Settled, _, _) => "系统回落至稳定域。".to_string(),
        (veex_signal::Phase::Converging, _, drift, _) if drift <= 12 => {
            "异常已被吸收，结构持续收敛。".to_string()
        }
        (veex_signal::Phase::Aligning, _, _, _) if context.short_term.len() <= 1 => {
            "状态进入校准阶段。".to_string()
        }
        (veex_signal::Phase::Aligning, Pattern::Focused, _, _) if context.short_term.len() >= 2 => {
            "高活跃区已被标记。".to_string()
        }
        (veex_signal::Phase::Active, Pattern::Emergent, _, _) => "局部异常已进入处理。".to_string(),
        (veex_signal::Phase::Active, _, _, _) => "过程开始活跃。".to_string(),
        (veex_signal::Phase::Dormant, _, _, _) => "记录已建立。".to_string(),
        _ => "记录仍在继续。".to_string(),
    };

    Expression { pattern, line }
}
