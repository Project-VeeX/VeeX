use std::{future::Future, sync::Arc};

use tokio::task::JoinSet;
use veex_config::ProxyConfig;

use crate::bootstrap::{build_runtime_state, RuntimeState};

pub async fn run_with_shutdown<F>(config: &ProxyConfig, shutdown: F) -> Result<(), String>
where
    F: Future<Output = Result<(), String>>,
{
    let state = build_runtime_state(config)?;
    let RuntimeState {
        dispatcher,
        inbounds,
        shutdown: shutdown_trigger,
    } = state;
    let mut tasks = JoinSet::new();

    for inbound in inbounds {
        tasks.spawn(inbound.serve(Arc::clone(&dispatcher)));
    }

    tokio::pin!(shutdown);
    let mut shutdown_requested = false;

    loop {
        if shutdown_requested && tasks.is_empty() {
            return Ok(());
        }

        tokio::select! {
            result = &mut shutdown, if !shutdown_requested => {
                result?;
                shutdown_trigger.trigger();
                shutdown_requested = true;
            }
            maybe_task = tasks.join_next(), if !tasks.is_empty() => {
                match maybe_task {
                    Some(Ok(Ok(()))) => continue,
                    Some(Ok(Err(err))) => return Err(format!("runtime task failed: {err}")),
                    Some(Err(err)) => return Err(format!("runtime task panicked: {err}")),
                    None => return Ok(()),
                }
            }
        }
    }
}
