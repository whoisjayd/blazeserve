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

/// The code a write error stands for, if it has one.
fn io_cause(e: &std::io::Error) -> Option<u8> {
    (e.kind() == std::io::ErrorKind::StorageFull).then_some(NO_SPACE)
}

pub(crate) fn failure() -> u8 {
    CAUSE.load(Ordering::SeqCst)
}

/// Records a full disk when `e` says so.
pub(crate) fn note_io(e: &std::io::Error) {
    if let Some(code) = io_cause(e) {
        record(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The cause is a process-wide value, so these tests exercise the pure parts only; the
    // exit codes themselves are checked end to end in tests/cli_transfer.rs.
    #[test]
    fn a_full_disk_is_recognised() {
        assert_eq!(
            io_cause(&std::io::Error::from(std::io::ErrorKind::StorageFull)),
            Some(NO_SPACE)
        );
        assert_eq!(
            io_cause(&std::io::Error::from(std::io::ErrorKind::NotFound)),
            None
        );
    }

    #[test]
    fn the_codes_are_distinct_and_stable() {
        assert_eq!([NO_SPACE, INTEGRITY, AUTH], [3, 4, 5]);
    }
}
