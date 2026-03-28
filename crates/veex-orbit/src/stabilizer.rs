use veex_signal::SignalState;

pub fn normalize_after_peak(state: &mut SignalState) {
    state.stability.level = state.stability.level.saturating_add(6).min(100);
    state.stability.drift = state.stability.drift.saturating_sub(5);
}
