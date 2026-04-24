//! Test-only tracing capture helpers shared across workspace crates.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::Context as LayerContext, prelude::*, registry::LookupSpan};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapturedEvent {
    pub fields: BTreeMap<String, String>,
}

#[derive(Default)]
struct EventVisitor {
    fields: BTreeMap<String, String>,
}

impl Visit for EventVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

#[derive(Clone, Default)]
struct CaptureLayer;

type EventBuffer = Arc<Mutex<Vec<CapturedEvent>>>;
type ActiveEventBuffer = Mutex<Option<EventBuffer>>;

pub struct CaptureGuard {
    lock_guard: Option<MutexGuard<'static, ()>>,
}

static CAPTURE_LOCK: Mutex<()> = Mutex::new(());
static ACTIVE_BUFFER: OnceLock<ActiveEventBuffer> = OnceLock::new();
static SUBSCRIBER_INIT: OnceLock<()> = OnceLock::new();

fn active_buffer() -> &'static ActiveEventBuffer {
    ACTIVE_BUFFER.get_or_init(|| Mutex::new(None))
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn ensure_capture_subscriber() {
    SUBSCRIBER_INIT.get_or_init(|| {
        let subscriber = tracing_subscriber::registry().with(CaptureLayer);
        tracing::subscriber::set_global_default(subscriber)
            .expect("test tracing subscriber should install exactly once");
    });
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        *lock_unpoisoned(active_buffer()) = None;
        self.lock_guard.take();
    }
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        let Some(events) = lock_unpoisoned(active_buffer()).as_ref().cloned() else {
            return;
        };
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        visitor
            .fields
            .insert("level".to_string(), event.metadata().level().to_string());
        lock_unpoisoned(&events).push(CapturedEvent {
            fields: visitor.fields,
        });
    }
}

pub fn install_test_subscriber() -> (CaptureGuard, EventBuffer) {
    ensure_capture_subscriber();
    let capture_lock = lock_unpoisoned(&CAPTURE_LOCK);
    let events = Arc::new(Mutex::new(Vec::new()));
    *lock_unpoisoned(active_buffer()) = Some(Arc::clone(&events));

    (
        CaptureGuard {
            lock_guard: Some(capture_lock),
        },
        events,
    )
}

pub fn captured_events(buffer: &Arc<Mutex<Vec<CapturedEvent>>>) -> Vec<CapturedEvent> {
    lock_unpoisoned(buffer).clone()
}

pub fn assert_has_event(
    events: &[CapturedEvent],
    event_name: &str,
    expected_fields: &[(&str, &str)],
) {
    let matched = events.iter().any(|event| {
        event.fields.get("event").map(String::as_str) == Some(event_name)
            && expected_fields.iter().all(|(key, expected)| {
                event.fields.get(*key).map(String::as_str) == Some(*expected)
            })
    });

    assert!(
        matched,
        "expected event `{event_name}` with fields {:?}, captured events: {:?}",
        expected_fields, events
    );
}

pub fn assert_event_has_fields(
    events: &[CapturedEvent],
    event_name: &str,
    expected_fields: &[&str],
) {
    let matched = events.iter().any(|event| {
        event.fields.get("event").map(String::as_str) == Some(event_name)
            && expected_fields
                .iter()
                .all(|field| event.fields.contains_key(*field))
    });

    assert!(
        matched,
        "expected event `{event_name}` with fields {:?}, captured events: {:?}",
        expected_fields, events
    );
}
