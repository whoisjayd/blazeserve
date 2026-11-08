//! Per-connection cap on how fast one HTTP/2 connection may open streams. Cancelled streams
//! free their concurrency slot immediately, so the stream limit alone does not stop a client
//! from queueing unbounded file work by opening and resetting streams (CVE-2023-44487).

use std::sync::Mutex;
use std::time::Instant;

const BURST: f64 = 256.0;
const PER_SECOND: f64 = 128.0;

pub(super) struct StreamBudget {
    state: Mutex<(f64, Instant)>,
}

impl StreamBudget {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new((BURST, Instant::now())),
        }
    }

    pub(super) fn try_take(&self) -> bool {
        self.take_at(Instant::now())
    }

    fn take_at(&self, now: Instant) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let elapsed = now.saturating_duration_since(s.1).as_secs_f64();
        s.1 = now;
        s.0 = (s.0 + elapsed * PER_SECOND).min(BURST);
        if s.0 >= 1.0 {
            s.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn burst_then_refill() {
        let b = StreamBudget::new();
        let t0 = Instant::now();
        let granted = (0..400).filter(|_| b.take_at(t0)).count();
        assert_eq!(granted, 256);
        assert!(!b.take_at(t0));
        assert!(b.take_at(t0 + Duration::from_millis(100)));
    }
}
