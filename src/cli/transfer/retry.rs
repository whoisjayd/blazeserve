//! Server-directed retry timing: `Retry-After` parsing and the wait policy shared by every transfer path.

use crate::cli::util::backoff;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::{Duration, SystemTime};

/// The longest server-directed wait a transfer will honour. A longer request fails the
/// transfer rather than being cut short and retried early.
pub(super) const MAX_SERVER_WAIT: Duration = Duration::from_secs(300);

const MAX_JITTER_MS: u64 = 500;

/// `Retry-After` as a delay: non-negative delay-seconds, or an HTTP-date measured from `now`.
/// Malformed values and dates that have already passed give `None`.
pub(super) fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        // More digits than a u64 holds is still a valid, absurdly long delay.
        return Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    at.duration_since(now).ok().filter(|d| !d.is_zero())
}

/// Random delay in `0..=500` ms that only ever lengthens a wait.
pub(super) fn jitter() -> Duration {
    let r = RandomState::new().build_hasher().finish();
    Duration::from_millis(r % (MAX_JITTER_MS + 1))
}

/// How long to wait before retry number `fails`. Without a server hint this is the local
/// backoff. With one it is at least the larger of the two, plus `jitter`. A hint beyond
/// [`MAX_SERVER_WAIT`] is an error.
pub(super) fn plan_wait(
    fails: u32,
    hint: Option<Duration>,
    jitter: Duration,
) -> Result<Duration, String> {
    let local = backoff(fails);
    match hint {
        None => Ok(local),
        Some(h) if h > MAX_SERVER_WAIT => Err(format!(
            "the server asked to wait {} before retrying, longer than the {}s this client accepts",
            describe_delay(h),
            MAX_SERVER_WAIT.as_secs()
        )),
        Some(h) => Ok(local.max(h) + jitter),
    }
}

fn describe_delay(d: Duration) -> String {
    match d.as_secs() {
        s if s >= 1 << 32 => "an unreasonably long time".to_owned(),
        s => format!("{s}s"),
    }
}

/// Text for the "Retrying" line.
pub(super) fn retry_note(wait: Duration, hint: Option<Duration>, attempt: u32, max: u32) -> String {
    let base = format!("in {}s (attempt {attempt} of {max})", wait.as_secs().max(1));
    match hint {
        Some(h) => format!("{base}, as the server asked (Retry-After {}s)", h.as_secs()),
        None => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn parses_delay_seconds() {
        let now = at(1_000);
        assert_eq!(parse_retry_after("0", now), Some(Duration::ZERO));
        assert_eq!(
            parse_retry_after(" 120 ", now),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after("99999999999999999999999", now),
            Some(Duration::from_secs(u64::MAX))
        );
    }

    #[test]
    fn rejects_malformed_values() {
        let now = at(1_000);
        for bad in ["", "-5", "+5", "1.5", "soon", "5s", "0x10"] {
            assert_eq!(parse_retry_after(bad, now), None, "{bad}");
        }
    }

    #[test]
    fn parses_http_dates_against_the_given_clock() {
        // 1994-11-06T08:49:37Z is 784111777.
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        assert_eq!(
            parse_retry_after(date, at(784_111_777 - 30)),
            Some(Duration::from_secs(30))
        );
        assert_eq!(parse_retry_after(date, at(784_111_777)), None);
        assert_eq!(parse_retry_after(date, at(784_111_777 + 60)), None);
    }

    #[test]
    fn without_a_hint_the_local_backoff_applies() {
        assert_eq!(
            plan_wait(1, None, Duration::from_millis(400)),
            Ok(backoff(1))
        );
    }

    #[test]
    fn a_hint_never_shortens_the_wait() {
        let j = Duration::from_millis(250);
        assert_eq!(
            plan_wait(1, Some(Duration::from_secs(10)), j),
            Ok(Duration::from_secs(10) + j)
        );
        assert_eq!(
            plan_wait(5, Some(Duration::from_secs(1)), Duration::ZERO),
            Ok(backoff(5))
        );
    }

    #[test]
    fn a_hint_past_the_limit_fails_instead_of_clamping() {
        let at_limit = plan_wait(1, Some(MAX_SERVER_WAIT), Duration::ZERO);
        assert_eq!(at_limit, Ok(MAX_SERVER_WAIT));
        let over = plan_wait(
            1,
            Some(MAX_SERVER_WAIT + Duration::from_secs(1)),
            Duration::ZERO,
        );
        assert!(over.unwrap_err().contains("longer than"));
        assert!(plan_wait(1, Some(Duration::from_secs(u64::MAX)), Duration::ZERO).is_err());
    }

    #[test]
    fn jitter_is_bounded() {
        for _ in 0..100 {
            assert!(jitter() <= Duration::from_millis(MAX_JITTER_MS));
        }
    }
}
