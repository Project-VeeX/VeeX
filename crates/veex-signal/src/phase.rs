use std::fmt;

use serde::{Deserialize, Serialize};

/// 阶段枚举，用于标记当前周期所处的位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Dormant,
    Active,
    Aligning,
    Converging,
    Stabilized,
}

impl Phase {
    pub fn next(self) -> Self {
        match self {
            Self::Dormant => Self::Active,
            Self::Active => Self::Aligning,
            Self::Aligning => Self::Converging,
            Self::Converging => Self::Stabilized,
            Self::Stabilized => Self::Stabilized,
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Dormant => "Dormant",
            Self::Active => "Active",
            Self::Aligning => "Aligning",
            Self::Converging => "Converging",
            Self::Stabilized => "Stabilized",
        };

        f.write_str(text)
    }
}
