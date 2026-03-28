use serde::{Deserialize, Serialize};
use veex_signal::Phase;

/// 表达模式，用于约束输出语气。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pattern {
    Quiet,
    Focused,
    Emergent,
    Settled,
}

pub fn derive_pattern(phase: &Phase, drift: u8) -> Pattern {
    match (phase, drift) {
        (Phase::Dormant, _) => Pattern::Quiet,
        (Phase::Active, d) if d >= 18 => Pattern::Emergent,
        (Phase::Aligning, _) => Pattern::Focused,
        (Phase::Converging, _) => Pattern::Focused,
        (Phase::Stabilized, _) => Pattern::Settled,
        _ => Pattern::Quiet,
    }
}
