//! Test-only tracing capture helpers shared across workspace crates.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use tracing::{
    field::{Field, Visit},
    Event, Subscriber,
};
use tracing_subscriber::{layer::Context as LayerContext, prelude::*, registry::LookupSpan, Layer};

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

#[derive(Clone)]
struct CaptureLayer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        visitor
            .fields
            .insert("level".to_string(), event.metadata().level().to_string());
        self.events
            .lock()
            .expect("captured events lock poisoned")
            .push(CapturedEvent {
                fields: visitor.fields,
            });
    }
}

pub fn install_test_subscriber() -> (
    tracing::subscriber::DefaultGuard,
    Arc<Mutex<Vec<CapturedEvent>>>,
) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(CaptureLayer {
        events: Arc::clone(&events),
    });

    (tracing::subscriber::set_default(subscriber), events)
}

pub fn captured_events(buffer: &Arc<Mutex<Vec<CapturedEvent>>>) -> Vec<CapturedEvent> {
    buffer
        .lock()
        .expect("captured events lock poisoned")
        .clone()
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
