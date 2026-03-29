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

    println!("[ VeeX ]");
    println!("状态：初始化");
    println!();
    println!("周期 {:02} | 阶段：{}", state.cycle, state.phase);
    println!("摘要：记录已建立。");
    println!();

    let report = scheduler.run(&mut state, &mut context, &mut journal).await;

    for step in &report.steps {
        println!("周期 {:02} | 阶段：{}", step.cycle, step.phase);
        println!("摘要：{}", step.summary);
        println!();
    }

    let summary = journal.summary();

    println!(
        "归档摘要：记录 {} 条，Warning {} 条，Critical {} 条。",
        summary.total, summary.warnings, summary.criticals
    );
    println!("最终阶段：{}", report.final_phase);
    println!("稳定度：{}", report.final_stability.level);
    println!("偏移值：{}", report.final_stability.drift);
    println!("同步状态：{}", report.synchronized);
    println!();
    println!("VeeX 维持秩序。");
    println!("状态：稳定。");

    Ok(())
}
