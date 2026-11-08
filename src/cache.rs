use sha2::{Digest, Sha256};
use std::fs::Metadata;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CACHE_PUBLIC: &str = "public, max-age=3600";
pub const CACHE_DISABLED: &str = "no-cache, no-store, must-revalidate";

pub fn cache_control(no_cache: bool) -> &'static str {
    if no_cache {
        CACHE_DISABLED
    } else {
        CACHE_PUBLIC
    }
}

pub fn mtime(meta: &Metadata) -> SystemTime {
    meta.modified().unwrap_or(UNIX_EPOCH)
}

pub fn mtime_secs(meta: &Metadata) -> u64 {
    mtime(meta)
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn file_id(meta: &Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(meta)
}

#[cfg(not(unix))]
fn file_id(_meta: &Metadata) -> u64 {
    0
}

/// Strong validator derived from mtime, size and inode of the file actually served,
/// so a precompressed sibling gets its own tag.
pub fn etag_for(meta: &Metadata) -> String {
    let nanos = mtime(meta)
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let digest = Sha256::digest(format!("{nanos}-{}-{}", meta.len(), file_id(meta)).as_bytes());
    let mut tag = String::with_capacity(22);
    tag.push('"');
    for byte in &digest[..10] {
        tag.push_str(&format!("{byte:02x}"));
    }
    tag.push('"');
    tag
}

pub fn http_date(t: SystemTime) -> String {
    httpdate::fmt_http_date(t)
}

fn opaque(tag: &str) -> &str {
    tag.strip_prefix("W/").unwrap_or(tag)
}

/// Weak comparison, as required for `If-None-Match` on GET and HEAD.
pub fn if_none_match_matches(header: &str, current_etag: &str) -> bool {
    let current = opaque(current_etag);
    header.split(',').map(str::trim).any(|token| {
        if token == "*" {
            return true;
        }
        let candidate = opaque(token);
        candidate.len() >= 2
            && candidate.starts_with('"')
            && candidate.ends_with('"')
            && candidate == current
    })
}

/// True when the representation has not changed since the date in `If-Modified-Since`.
/// Unparseable dates are ignored (not-modified is never assumed).
pub fn not_modified_since(header: &str, mtime_secs: u64) -> bool {
    httpdate::parse_http_date(header.trim())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .is_some_and(|since| mtime_secs <= since.as_secs())
}

/// `If-Range` needs a strong match: a weak tag never validates, a date must equal
/// the modification time exactly.
pub fn if_range_ok(header: &str, etag: &str, mtime_secs: u64) -> bool {
    let header = header.trim();
    if header.starts_with('"') {
        return header == etag;
    }
    if header.starts_with("W/") {
        return false;
    }
    httpdate::parse_http_date(header)
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .is_some_and(|d| d.as_secs() == mtime_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_comparison_and_wildcard() {
        let tag = "\"abc\"";
        assert!(if_none_match_matches("\"abc\"", tag));
        assert!(if_none_match_matches("W/\"abc\"", tag));
        assert!(if_none_match_matches("\"x\", W/\"abc\"", tag));
        assert!(if_none_match_matches("*", tag));
        assert!(!if_none_match_matches("\"abd\"", tag));
        assert!(!if_none_match_matches("abc", tag));
        assert!(!if_none_match_matches("\"", tag));
    }

    #[test]
    fn if_modified_since_semantics() {
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        assert!(not_modified_since(date, 784_111_777));
        assert!(not_modified_since(date, 784_111_000));
        assert!(!not_modified_since(date, 784_111_778));
        assert!(!not_modified_since("garbage", 0));
    }

    #[test]
    fn if_range_requires_strong_match() {
        assert!(if_range_ok("\"abc\"", "\"abc\"", 0));
        assert!(!if_range_ok("W/\"abc\"", "\"abc\"", 0));
        assert!(!if_range_ok("\"abd\"", "\"abc\"", 0));
        assert!(if_range_ok(
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "\"abc\"",
            784_111_777
        ));
        assert!(!if_range_ok(
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "\"abc\"",
            784_111_778
        ));
        assert!(!if_range_ok("nonsense", "\"abc\"", 0));
    }
}
