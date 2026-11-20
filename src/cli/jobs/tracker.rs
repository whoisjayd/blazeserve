//! Progress of the one job a worker process runs. `Progress` in `cli::util` is the single
//! source of byte accounting and publishes its position here; the worker's reporter reads it.
//! In a foreground command nothing reads these values, and the stores are cheap.

use super::record::Phase;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

const UNKNOWN: u64 = u64::MAX;

static DONE: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(UNKNOWN);
/// Bumped whenever the position is set rather than advanced (a new attempt, a resume, an
/// upload resync), so speed never counts bytes that were already there.
static EPOCH: AtomicU64 = AtomicU64::new(0);
static PHASE: AtomicU8 = AtomicU8::new(PREPARING);
static CANCEL: AtomicBool = AtomicBool::new(false);

const PREPARING: u8 = 0;
const TRANSFERRING: u8 = 1;
const RETRYING: u8 = 2;
const FINALIZING: u8 = 3;

/// The error text every transfer returns when it stops because the job was stopped.
pub const INTERRUPTED: &str = "interrupted";

fn code(phase: Phase) -> u8 {
    match phase {
        Phase::Preparing => PREPARING,
        Phase::Transferring => TRANSFERRING,
        Phase::Retrying => RETRYING,
        Phase::Finalizing => FINALIZING,
    }
}

pub fn set_phase(phase: Phase) {
    PHASE.store(code(phase), Ordering::Relaxed);
}

pub fn phase() -> Phase {
    match PHASE.load(Ordering::Relaxed) {
        TRANSFERRING => Phase::Transferring,
        RETRYING => Phase::Retrying,
        FINALIZING => Phase::Finalizing,
        _ => Phase::Preparing,
    }
}

/// A new progress display starts at `base` of `total`.
pub fn begin(total: Option<u64>, base: u64) {
    TOTAL.store(total.unwrap_or(UNKNOWN), Ordering::Relaxed);
    rebase(base);
    set_phase(Phase::Transferring);
}

/// The position jumped to `pos` without those bytes being transferred now.
pub fn rebase(pos: u64) {
    DONE.store(pos, Ordering::Relaxed);
    EPOCH.fetch_add(1, Ordering::Relaxed);
}

pub fn set_done(pos: u64) {
    DONE.store(pos, Ordering::Relaxed);
    if PHASE.load(Ordering::Relaxed) == RETRYING {
        set_phase(Phase::Transferring);
    }
}

pub struct Snapshot {
    pub done: u64,
    pub total: Option<u64>,
    pub epoch: u64,
    pub phase: Phase,
}

pub fn snapshot() -> Snapshot {
    let total = TOTAL.load(Ordering::Relaxed);
    Snapshot {
        done: DONE.load(Ordering::Relaxed),
        total: (total != UNKNOWN).then_some(total),
        epoch: EPOCH.load(Ordering::Relaxed),
        phase: phase(),
    }
}

pub fn request_cancel() {
    CANCEL.store(true, Ordering::SeqCst);
}

pub fn cancelled() -> bool {
    CANCEL.load(Ordering::Relaxed)
}

/// `Err` once the job was stopped; transfers call this between chunks and attempts.
pub fn check() -> Result<(), String> {
    if cancelled() {
        Err(INTERRUPTED.to_owned())
    } else {
        Ok(())
    }
}

/// Sits out a retry delay, shown as the retrying phase, and returns early with an error
/// when the job is stopped.
pub fn retry_wait(wait: Duration) -> Result<(), String> {
    set_phase(Phase::Retrying);
    let end = std::time::Instant::now() + wait;
    while let Some(left) = end.checked_duration_since(std::time::Instant::now()) {
        check()?;
        std::thread::sleep(left.min(Duration::from_millis(100)));
    }
    check()
}

/// Recent speed from successive samples. Only bytes beyond the highest position seen in
/// the current epoch count, so a retried segment or a resumed offset never inflates it.
pub struct SpeedMeter {
    epoch: u64,
    high: u64,
    smoothed: Option<f64>,
}

impl SpeedMeter {
    pub fn new() -> Self {
        Self {
            epoch: 0,
            high: 0,
            smoothed: None,
        }
    }

    /// `None` until a full interval has been seen since the position was last set.
    pub fn sample(&mut self, epoch: u64, done: u64, elapsed: Duration) -> Option<u64> {
        if epoch != self.epoch {
            *self = Self {
                epoch,
                high: done,
                smoothed: None,
            };
            return None;
        }
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 {
            return self.smoothed.map(|s| s.round() as u64);
        }
        let gained = done.saturating_sub(self.high) as f64;
        self.high = self.high.max(done);
        let now = gained / secs;
        let next = self.smoothed.map_or(now, |prev| 0.3 * now + 0.7 * prev);
        self.smoothed = Some(next);
        Some(next.round() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    #[test]
    fn speed_is_unknown_until_an_interval_has_passed() {
        let mut m = SpeedMeter::new();
        assert_eq!(m.sample(1, 500, SEC), None);
        assert_eq!(m.sample(1, 1500, SEC), Some(1000));
    }

    #[test]
    fn resumed_bytes_do_not_count_toward_speed() {
        let mut m = SpeedMeter::new();
        assert_eq!(m.sample(1, 0, SEC), None);
        // The download resumes at 10 MiB: a new epoch, not 10 MiB in one second.
        assert_eq!(m.sample(2, 10 << 20, SEC), None);
        assert_eq!(m.sample(2, (10 << 20) + 2000, SEC), Some(2000));
    }

    #[test]
    fn retried_bytes_do_not_count_twice() {
        let mut m = SpeedMeter::new();
        m.sample(1, 0, SEC);
        assert_eq!(m.sample(1, 1000, SEC), Some(1000));
        // A failed segment gives 600 bytes back; fetching them again adds nothing new.
        let after_loss = m.sample(1, 400, SEC).unwrap();
        assert!(after_loss < 1000);
        let regained = m.sample(1, 1000, SEC).unwrap();
        assert!(regained < after_loss + 1, "{regained} vs {after_loss}");
    }

    #[test]
    fn an_idle_transfer_decays_towards_zero() {
        let mut m = SpeedMeter::new();
        m.sample(1, 0, SEC);
        m.sample(1, 1000, SEC);
        let idle = m.sample(1, 1000, SEC).unwrap();
        assert!(idle < 1000 && idle > 0);
    }

    #[test]
    fn retry_wait_ends_early_when_cancelled() {
        // Cancellation is process-wide, so this is the only test that sets it.
        let t = std::time::Instant::now();
        let waiter = std::thread::spawn(|| retry_wait(Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(150));
        request_cancel();
        assert_eq!(waiter.join().unwrap(), Err(INTERRUPTED.to_owned()));
        assert!(t.elapsed() < Duration::from_secs(10));
        assert!(check().is_err());
        CANCEL.store(false, Ordering::SeqCst);
    }
}
