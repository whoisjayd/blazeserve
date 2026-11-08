//! Token-bucket throttling and a bounded per-IP LRU pool.
//!
//! Locks are held only for arithmetic, never across `.await` or I/O.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct BucketState {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

#[derive(Debug)]
pub struct TokenBucket {
    state: Mutex<BucketState>,
}

fn norm(rate: Option<f64>) -> f64 {
    rate.filter(|r| r.is_finite() && *r > 0.0).unwrap_or(0.0)
}

impl TokenBucket {
    pub fn new(rate_bps: Option<f64>) -> Self {
        let rate = norm(rate_bps);
        let capacity = if rate > 0.0 {
            (rate * 2.0).max(1.0)
        } else {
            0.0
        };
        Self {
            state: Mutex::new(BucketState {
                rate,
                capacity,
                tokens: capacity,
                last: Instant::now(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BucketState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn refill(s: &mut BucketState, now: Instant) {
        let elapsed = now.saturating_duration_since(s.last).as_secs_f64();
        s.last = now;
        s.tokens = (s.tokens + elapsed * s.rate).min(s.capacity);
    }

    /// Change the rate while keeping accrued tokens (clamped to the new capacity).
    pub fn update_rate(&self, rate_bps: Option<f64>) {
        let new_rate = norm(rate_bps);
        let mut s = self.lock();
        if new_rate == s.rate {
            return;
        }
        Self::refill(&mut s, Instant::now());
        let was_unlimited = s.rate <= 0.0;
        s.rate = new_rate;
        s.capacity = if new_rate > 0.0 {
            (new_rate * 2.0).max(1.0)
        } else {
            0.0
        };
        s.tokens = if new_rate <= 0.0 {
            0.0
        } else if was_unlimited {
            s.capacity
        } else {
            s.tokens.min(s.capacity)
        };
    }

    pub fn remaining(&self) -> u64 {
        let mut s = self.lock();
        if s.rate <= 0.0 {
            return 0;
        }
        Self::refill(&mut s, Instant::now());
        s.tokens.max(0.0) as u64
    }

    /// Non-blocking: take up to `n` bytes now. Returns `Err(wait)` when empty.
    pub fn try_take(&self, n: usize) -> Result<usize, Duration> {
        if n == 0 {
            return Ok(0);
        }
        let mut s = self.lock();
        if s.rate <= 0.0 {
            return Ok(n);
        }
        Self::refill(&mut s, Instant::now());
        let allowed = (n as f64).min(s.tokens.floor()) as usize;
        if allowed > 0 {
            s.tokens -= allowed as f64;
            return Ok(allowed);
        }
        Err(Duration::from_secs_f64(
            ((1.0 - s.tokens) / s.rate).clamp(0.0005, 0.05),
        ))
    }

    pub async fn take(&self, n: usize) -> usize {
        loop {
            match self.try_take(n) {
                Ok(v) => return v,
                Err(wait) => tokio::time::sleep(wait).await,
            }
        }
    }
}

#[derive(Debug)]
pub struct IpLimiterPool {
    inner: Mutex<lru::LruCache<IpAddr, Arc<TokenBucket>>>,
    unbounded: bool,
}

impl IpLimiterPool {
    pub fn new(max_entries: usize) -> Self {
        let cap = NonZeroUsize::new(max_entries.max(1)).expect("nonzero");
        Self {
            inner: Mutex::new(lru::LruCache::new(cap)),
            unbounded: max_entries == 0,
        }
    }

    pub fn get(&self, ip: IpAddr, rate_bps: Option<f64>) -> Arc<TokenBucket> {
        if self.unbounded {
            return Arc::new(TokenBucket::new(rate_bps));
        }
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(b) = g.get(&ip) {
            b.update_rate(rate_bps);
            return b.clone();
        }
        let b = Arc::new(TokenBucket::new(rate_bps));
        g.put(ip, b.clone());
        b
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_passes_through() {
        assert_eq!(TokenBucket::new(None).try_take(10), Ok(10));
    }

    #[test]
    fn limited_bucket_caps_burst() {
        let b = TokenBucket::new(Some(100.0));
        assert_eq!(b.try_take(1000), Ok(200));
        assert!(b.try_take(1).is_err());
    }

    #[test]
    fn pool_is_bounded_lru() {
        let p = IpLimiterPool::new(2);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let c: IpAddr = "10.0.0.3".parse().unwrap();
        let first = p.get(a, Some(10.0));
        p.get(b, Some(10.0));
        p.get(c, Some(10.0));
        assert_eq!(p.len(), 2);
        assert!(!Arc::ptr_eq(&first, &p.get(a, Some(10.0))), "a was evicted");
    }
}
