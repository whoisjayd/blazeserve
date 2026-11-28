//! Timings and sizes a command records about itself while it runs, for its closing event.
//!
//! One `blaze` process runs one command, so the record is process-wide. It holds numbers
//! under fixed names and no request configuration.

use std::sync::Mutex;
use std::time::Instant;

use serde_json::{Map, Value};

static RECORD: Mutex<Option<Map<String, Value>>> = Mutex::new(None);

fn with(f: impl FnOnce(&mut Map<String, Value>)) {
    if let Ok(mut guard) = RECORD.lock() {
        f(guard.get_or_insert_with(Map::new));
    }
}

/// Records a number or flag about the running command.
pub fn note(key: &'static str, value: impl Into<Value>) {
    with(|map| {
        map.insert(key.to_owned(), value.into());
    });
}

/// Times one phase; the time is added when the guard is dropped.
pub struct Phase {
    key: &'static str,
    started: Instant,
}

pub fn phase(key: &'static str) -> Phase {
    Phase {
        key,
        started: Instant::now(),
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        let millis = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        with(|map| {
            let so_far = map.get(self.key).and_then(Value::as_u64).unwrap_or(0);
            map.insert(self.key.to_owned(), so_far.saturating_add(millis).into());
        });
    }
}

/// Everything recorded since the last call.
pub(super) fn take() -> Map<String, Value> {
    RECORD
        .lock()
        .ok()
        .and_then(|mut guard| guard.take())
        .unwrap_or_default()
}

/// A copy of what has been recorded so far.
pub fn peek() -> Map<String, Value> {
    RECORD
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_default()
}
