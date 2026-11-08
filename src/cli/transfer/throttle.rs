//! Total download rate cap shared by every connection of one `blaze get`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

const MIN_RATE: u64 = 1024;

/// Parses bytes per second with an optional case-insensitive `K`, `M` or `G` suffix
/// (1024-based, decimals allowed), at least 1K.
pub fn parse_rate(raw: &str) -> Result<u64, String> {
    let text = raw.trim();
    let (digits, unit) = match text.char_indices().last() {
        Some((i, 'k' | 'K')) => (&text[..i], 1u64 << 10),
        Some((i, 'm' | 'M')) => (&text[..i], 1 << 20),
        Some((i, 'g' | 'G')) => (&text[..i], 1 << 30),
        _ => (text, 1),
    };
    let value: f64 = digits.parse().map_err(|_| {
        format!("invalid rate '{raw}'; use bytes per second such as 500K, 2M or 1.5M")
    })?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!("invalid rate '{raw}'"));
    }
    let rate = (value * unit as f64) as u64;
    if rate < MIN_RATE {
        return Err("rate must be at least 1K".to_owned());
    }
    Ok(rate)
}

/// Hands out time slots on a single timeline, so the average rate is exact from the
/// first byte and no connection can bank unused capacity.
pub struct Throttle {
    rate: u64,
    next: Mutex<Instant>,
}

impl Throttle {
    pub fn new(rate: u64) -> Self {
        Self {
            rate: rate.max(1),
            next: Mutex::new(Instant::now()),
        }
    }

    /// Largest read worth issuing: a single read never costs more than about a second.
    pub fn chunk(&self, buf_len: usize) -> usize {
        usize::try_from(self.rate).map_or(buf_len, |r| r.min(buf_len))
    }

    /// Reserves the slot for `bytes` and returns how long the caller must wait.
    fn reserve(&self, bytes: u64, now: Instant) -> Duration {
        let cost = Duration::from_secs_f64(bytes as f64 / self.rate as f64);
        let mut next = self
            .next
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = (*next).max(now) + cost;
        *next = end;
        end.saturating_duration_since(now)
    }

    /// Blocks until `bytes` just received fit within the cap. The lock is released
    /// before sleeping.
    pub fn throttle(&self, bytes: usize) {
        let wait = self.reserve(bytes as u64, Instant::now());
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn parses_suffixes_and_decimals() {
        assert_eq!(parse_rate("500K").unwrap(), 500 * 1024);
        assert_eq!(parse_rate("2m").unwrap(), 2 << 20);
        assert_eq!(parse_rate("1.5M").unwrap(), 3 << 19);
        assert_eq!(parse_rate("1G").unwrap(), 1 << 30);
        assert_eq!(parse_rate("2048").unwrap(), 2048);
    }

    #[test]
    fn rejects_bad_and_tiny_rates() {
        for bad in [
            "", "K", "abc", "-1M", "0", "1023", "0.5K", "1x", "NaN", "infM",
        ] {
            assert!(parse_rate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reservations_queue_on_one_timeline() {
        let t = Throttle::new(1000);
        let now = Instant::now();
        assert_eq!(t.reserve(500, now), Duration::from_millis(500));
        assert_eq!(t.reserve(500, now), Duration::from_millis(1000));
        let later = now + Duration::from_secs(5);
        assert_eq!(t.reserve(250, later), Duration::from_millis(250));
    }

    #[test]
    fn chunk_is_capped_by_rate() {
        assert_eq!(Throttle::new(4096).chunk(256 * 1024), 4096);
        assert_eq!(Throttle::new(1 << 30).chunk(256 * 1024), 256 * 1024);
    }

    #[test]
    fn shared_threads_stay_under_the_total_rate() {
        let t = Arc::new(Throttle::new(64 * 1024));
        let start = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..4 {
                let t = &t;
                s.spawn(move || {
                    for _ in 0..4 {
                        t.throttle(4096);
                    }
                });
            }
        });
        // 64 KiB total at 64 KiB/s
        assert!(start.elapsed() >= Duration::from_millis(950));
    }
}
