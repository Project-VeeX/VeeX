use anyhow::Result;
use veex_archive::Journal;
use veex_echo::ContextFrame;
use veex_orbit::OrbitScheduler;
use veex_signal::SignalState;

#[tokio::main]
async fn main() -> Result<()> {
    let mut state = SignalState::new();
    let mut context = ContextFrame::default();
    let mut journal = Journal::default();
    let scheduler = OrbitScheduler::new(7);

    let report = scheduler.run(&mut state, &mut context, &mut journal).await;

    for step in &report.steps {
        println!("周期 {:02} | 阶段：{}", step.cycle, step.phase);
        println!("摘要：{}", step.summary);
    }

    println!("最终阶段：{}", report.final_phase);

    Ok(())
}
