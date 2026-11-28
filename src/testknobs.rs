//! Settings only the test suite uses. Release builds ignore them.
//!
//! `crash_point` keeps a debug-only process-wide call counter so child-process
//! tests running one server can abort after N passes at a named point. It
//! holds no request configuration, and `cfg!(debug_assertions)` compiles every
//! knob read out of release binaries.

use std::sync::atomic::{AtomicU32, Ordering};

fn knob(name: &str) -> Option<u32> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var(name).ok()?.parse().ok()
}

/// Kills the process, without running destructors, at a named step. Lets a test
/// stop the program at the moments that matter for crash safety.
#[allow(dead_code)]
pub(crate) fn crash_point(name: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    if std::env::var("BLAZE_CRASH_AT").map_or(true, |v| v != name) {
        return;
    }
    static PASSED: AtomicU32 = AtomicU32::new(0);
    if PASSED.fetch_add(1, Ordering::Relaxed) >= knob("BLAZE_CRASH_AFTER").unwrap_or(0) {
        std::process::abort();
    }
}

/// Panics at a named step, so a test can see how a crash is reported.
pub(crate) fn panic_point(name: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    if std::env::var("BLAZE_PANIC_AT").is_ok_and(|v| v == name) {
        panic!("test panic at /home/someone/secret.txt");
    }
}

/// Free space to report instead of asking the filesystem.
#[allow(dead_code)]
pub(crate) fn free_space_override() -> Option<u64> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var("BLAZE_FREE").ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_knobs_are_noops() {
        crash_point("nonexistent-point");
        assert_eq!(knob("BLAZE_NONEXISTENT_KNOB_FOR_TEST"), None);
        if std::env::var_os("BLAZE_FREE").is_none() {
            assert_eq!(free_space_override(), None);
        }
    }
}
