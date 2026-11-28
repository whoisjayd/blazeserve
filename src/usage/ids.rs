//! Random identifiers: a version 4 UUID names an install, a version 7 UUID names one run.

use std::time::{SystemTime, UNIX_EPOCH};

fn random() -> Option<[u8; 16]> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).ok()?;
    Some(raw)
}

fn format(mut raw: [u8; 16], version: u8) -> String {
    raw[6] = (raw[6] & 0x0F) | (version << 4);
    raw[8] = (raw[8] & 0x3F) | 0x80;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

pub(super) fn install_id() -> Option<String> {
    random().map(|raw| format(raw, 4))
}

/// PostHog requires a session ID to be a version 7 UUID whose time is not after its events.
pub(super) fn session_id() -> Option<String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    let mut raw = random()?;
    raw[..6].copy_from_slice(&u64::try_from(millis).ok()?.to_be_bytes()[2..]);
    Some(format(raw, 7))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_have_the_uuid_shape_and_version() {
        let (a, b) = (install_id().unwrap(), install_id().unwrap());
        assert_ne!(a, b);
        for (id, version) in [(a, '4'), (session_id().unwrap(), '7')] {
            assert_eq!(id.len(), 36, "{id}");
            assert_eq!(id.as_bytes()[14] as char, version, "{id}");
            assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        }
    }
}
