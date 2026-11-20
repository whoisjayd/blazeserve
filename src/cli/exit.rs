//! Exit codes for failures that have a known cause. Everything else is 1, and a usage error is
//! 2 (reported by clap). The cause is recorded where it is known and read once, by `run`.

use std::sync::atomic::{AtomicU8, Ordering};

/// Not enough free disk space, or the disk filled up while writing.
pub const NO_SPACE: u8 = 3;
/// A checksum, size or archive check failed: the data cannot be trusted.
pub const INTEGRITY: u8 = 4;
/// The server refused the credentials (HTTP 401 or 403).
pub const AUTH: u8 = 5;

const OTHER: u8 = 1;

static CAUSE: AtomicU8 = AtomicU8::new(OTHER);

pub(crate) fn reset() {
    CAUSE.store(OTHER, Ordering::SeqCst);
}

/// The first cause recorded wins, so a later, vaguer failure cannot hide it.
pub(crate) fn record(code: u8) {
    let _ = CAUSE.compare_exchange(OTHER, code, Ordering::SeqCst, Ordering::SeqCst);
}

pub(crate) fn failure() -> u8 {
    CAUSE.load(Ordering::SeqCst)
}

/// Records a full disk when `e` says so.
pub(crate) fn note_io(e: &std::io::Error) {
    if e.kind() == std::io::ErrorKind::StorageFull {
        record(NO_SPACE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_cause_wins_and_reset_clears_it() {
        reset();
        assert_eq!(failure(), 1);
        record(INTEGRITY);
        record(AUTH);
        assert_eq!(failure(), INTEGRITY);
        reset();
        assert_eq!(failure(), 1);
    }

    #[test]
    fn a_full_disk_is_recognised() {
        reset();
        note_io(&std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(failure(), 1);
        note_io(&std::io::Error::from(std::io::ErrorKind::StorageFull));
        assert_eq!(failure(), NO_SPACE);
        reset();
    }
}
