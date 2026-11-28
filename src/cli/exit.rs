//! Exit codes for failures that have a known cause. Everything else is 1, and a usage error is
//! 2 (reported by clap).

/// Generic runtime failure.
pub const OTHER: u8 = 1;
/// Not enough free disk space, or the disk filled up while writing.
pub const NO_SPACE: u8 = 3;
/// A checksum, size or archive check failed: the data cannot be trusted.
pub const INTEGRITY: u8 = 4;
/// The server refused the credentials (HTTP 401 or 403).
pub const AUTH: u8 = 5;

/// Whether an I/O error reports a full disk.
pub(crate) fn is_disk_full(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::StorageFull
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_disk_is_recognised() {
        assert!(is_disk_full(&std::io::Error::from(
            std::io::ErrorKind::StorageFull
        )));
        assert!(!is_disk_full(&std::io::Error::from(
            std::io::ErrorKind::NotFound
        )));
    }

    #[test]
    fn the_codes_are_distinct_and_stable() {
        assert_eq!([OTHER, NO_SPACE, INTEGRITY, AUTH], [1, 3, 4, 5]);
    }
}
