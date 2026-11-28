//! Typed failure reasons for transfers and verification so exit codes map directly from the
//! error without a process-wide side channel.

use crate::cli::exit;
use std::fmt;

/// Why a transfer (`get` / `put`) or verification (`verify`) failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    /// Not enough free disk space before or while writing.
    NoSpace(String),
    /// A checksum, size, or archive integrity check failed.
    Integrity(String),
    /// Authentication or authorization was refused (HTTP 401 or 403).
    Auth(String),
    /// Network, timeout, or retry failure.
    Network(String),
    /// Remote file changed or returned inconsistent responses or metadata.
    Unstable(String),
    /// Server refused the request with another permanent HTTP status.
    Http(String),
    /// Post-download archive extraction failed for a non-space, non-integrity reason.
    Extract(String),
    /// Local filesystem or I/O error.
    Io(String),
    /// Invalid runtime argument, URL, destination, or credential setup.
    Usage(String),
    /// Interrupted by a stop request (for example background `blaze stop`).
    Interrupted(String),
}

impl TransferError {
    /// Process exit code for this failure.
    ///
    /// Preserves the documented contract: 3 (no space), 4 (integrity), 5 (auth), and 1 for all
    /// other runtime transfer failures.
    pub fn code(&self) -> u8 {
        match self {
            Self::NoSpace(_) => exit::NO_SPACE,
            Self::Integrity(_) => exit::INTEGRITY,
            Self::Auth(_) => exit::AUTH,
            Self::Network(_)
            | Self::Unstable(_)
            | Self::Http(_)
            | Self::Extract(_)
            | Self::Io(_)
            | Self::Usage(_)
            | Self::Interrupted(_) => exit::OTHER,
        }
    }

    /// A fixed word naming the cause, for the usage report. The message is never reported.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NoSpace(_) => "no_space",
            Self::Integrity(_) => "integrity",
            Self::Auth(_) => "auth",
            Self::Network(_) => "network",
            Self::Unstable(_) => "unstable",
            Self::Http(_) => "http",
            Self::Extract(_) => "extract",
            Self::Io(_) => "io",
            Self::Usage(_) => "usage",
            Self::Interrupted(_) => "interrupted",
        }
    }

    pub(super) fn map_message(self, f: impl FnOnce(String) -> String) -> Self {
        match self {
            Self::NoSpace(m) => Self::NoSpace(f(m)),
            Self::Integrity(m) => Self::Integrity(f(m)),
            Self::Auth(m) => Self::Auth(f(m)),
            Self::Network(m) => Self::Network(f(m)),
            Self::Unstable(m) => Self::Unstable(f(m)),
            Self::Http(m) => Self::Http(f(m)),
            Self::Extract(m) => Self::Extract(f(m)),
            Self::Io(m) => Self::Io(f(m)),
            Self::Usage(m) => Self::Usage(f(m)),
            Self::Interrupted(m) => Self::Interrupted(f(m)),
        }
    }
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSpace(m)
            | Self::Integrity(m)
            | Self::Auth(m)
            | Self::Network(m)
            | Self::Unstable(m)
            | Self::Http(m)
            | Self::Extract(m)
            | Self::Io(m)
            | Self::Usage(m)
            | Self::Interrupted(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for TransferError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_maps_every_variant_to_documented_exit_status() {
        let cases = [
            (TransferError::NoSpace("disk full".into()), exit::NO_SPACE),
            (
                TransferError::Integrity("sha256 mismatch".into()),
                exit::INTEGRITY,
            ),
            (TransferError::Auth("HTTP 401".into()), exit::AUTH),
            (TransferError::Network("timed out".into()), 1),
            (TransferError::Unstable("file changed".into()), 1),
            (TransferError::Http("HTTP 404".into()), 1),
            (TransferError::Extract("cannot unpack".into()), 1),
            (TransferError::Io("permission denied".into()), 1),
            (TransferError::Usage("bad url".into()), 1),
            (TransferError::Interrupted("interrupted".into()), 1),
        ];
        for (err, expected) in cases {
            assert_eq!(err.code(), expected, "{err:?}");
        }
    }
}
