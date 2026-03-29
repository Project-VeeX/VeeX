use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::Notify;

#[derive(Debug)]
struct ShutdownState {
    triggered: AtomicBool,
    notify: Notify,
}

#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    state: Arc<ShutdownState>,
}

#[derive(Clone, Debug)]
pub struct ShutdownTrigger {
    state: Arc<ShutdownState>,
}

pub fn shutdown_channel() -> (ShutdownTrigger, ShutdownSignal) {
    let state = Arc::new(ShutdownState {
        triggered: AtomicBool::new(false),
        notify: Notify::new(),
    });

    (
        ShutdownTrigger {
            state: Arc::clone(&state),
        },
        ShutdownSignal { state },
    )
}

impl ShutdownSignal {
    pub fn is_triggered(&self) -> bool {
        self.state.triggered.load(Ordering::Acquire)
    }

    pub async fn wait(&self) {
        if self.is_triggered() {
            return;
        }

        let notified = self.state.notify.notified();
        if self.is_triggered() {
            return;
        }

        notified.await;
    }
}

impl ShutdownTrigger {
    pub fn trigger(&self) {
        if !self.state.triggered.swap(true, Ordering::AcqRel) {
            self.state.notify.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::shutdown_channel;

    #[tokio::test]
    async fn wait_returns_after_trigger() {
        let (trigger, signal) = shutdown_channel();

        let wait_task = tokio::spawn(async move {
            signal.wait().await;
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        trigger.trigger();

        tokio::time::timeout(Duration::from_secs(1), wait_task)
            .await
            .expect("wait task should complete")
            .expect("wait task should not panic");
    }
}
