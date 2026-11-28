//! Time limits shared by `blaze get` and `blaze put`: connection setup, idle time and one overall budget.

use super::error::TransferError;
use crate::cli::serve::{format_span, parse_span};
use clap::Args;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const MAX_LIMIT_SECS: u64 = 30 * 86_400;
const DEFAULT_CONNECT: Duration = Duration::from_secs(15);

/// A limit that is either a length of time or switched off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit(Option<Duration>);

fn parse_limit(s: &str) -> Result<Limit, String> {
    if s.eq_ignore_ascii_case("off") {
        return Ok(Limit(None));
    }
    parse_span(s, "limit", MAX_LIMIT_SECS)
        .map(|d| Limit(Some(d)))
        .map_err(|e| format!("{e}, or `off`"))
}

#[derive(Args, Debug, Clone, Copy)]
pub struct TimeoutArgs {
    /// Give up if the connection is not made within this time, e.g. 20s or `off`
    #[arg(long, value_name = "TIME", default_value = "15s", value_parser = parse_limit)]
    pub connect_timeout: Limit,
    /// Give up when no data moves for this long, e.g. 45s or `off`. Rate-limit and retry waits do not count
    #[arg(long, value_name = "TIME", default_value = "off", value_parser = parse_limit)]
    pub idle_timeout: Limit,
    /// Give up when the whole command, retries included, runs longer than this, e.g. 30m or `off`
    #[arg(long, value_name = "TIME", default_value = "off", value_parser = parse_limit)]
    pub max_time: Limit,
}

#[derive(Clone, Copy)]
struct Active {
    connect: Option<Duration>,
    idle: Option<Duration>,
    max: Option<Duration>,
    deadline: Option<Instant>,
}

const UNSET: Active = Active {
    connect: Some(DEFAULT_CONNECT),
    idle: None,
    max: None,
    deadline: None,
};

static ACTIVE: RwLock<Active> = RwLock::new(UNSET);

fn active() -> Active {
    *ACTIVE
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Starts the overall budget now. Call once per command, after the arguments are validated.
pub(super) fn install(args: &TimeoutArgs) {
    let now = Instant::now();
    let max = args.max_time.0;
    *ACTIVE
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Active {
        connect: args.connect_timeout.0,
        idle: args.idle_timeout.0,
        max,
        deadline: max.and_then(|m| now.checked_add(m)),
    };
}

pub(super) fn connect() -> Option<Duration> {
    active().connect
}

pub(super) fn idle() -> Option<Duration> {
    active().idle
}

fn remaining() -> Option<Duration> {
    active()
        .deadline
        .map(|d| d.saturating_duration_since(Instant::now()))
}

fn expired_message(a: &Active) -> String {
    let max = a.max.unwrap_or_default();
    format!(
        "--max-time {} ran out; progress is kept, so run the same command to continue",
        format_span(max)
    )
}

/// The overall budget has run out.
pub(super) fn check() -> Result<(), TransferError> {
    let a = active();
    match remaining() {
        Some(left) if left.is_zero() => Err(TransferError::Network(expired_message(&a))),
        _ => Ok(()),
    }
}

/// Like [`check`] for code that returns I/O errors.
pub(super) fn check_io() -> std::io::Result<()> {
    check().map_err(|m| std::io::Error::new(std::io::ErrorKind::TimedOut, m))
}

/// A wait of `wait` must end before the overall budget does, else it is not worth starting.
pub(super) fn fits(wait: Duration) -> Result<(), TransferError> {
    match remaining() {
        Some(left) if wait >= left => Err(TransferError::Network(format!(
            "{}; waiting {}s more would not leave time to retry",
            expired_message(&active()),
            wait.as_secs().max(1)
        ))),
        _ => Ok(()),
    }
}

/// Caps one request at the time left in the overall budget.
pub(super) fn bound<B>(req: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
    match remaining() {
        Some(left) => req
            .config()
            .timeout_global(Some(left.max(Duration::from_millis(1))))
            .build(),
        None => req,
    }
}

/// Wording for a timeout that ureq reported, when one of ours caused it.
pub(super) fn explain(timeout: ureq::Timeout) -> Option<String> {
    use ureq::Timeout::{Connect, Global, PerRead, PerWrite, Resolve};
    let a = active();
    match timeout {
        Global => Some(expired_message(&a)),
        PerRead | PerWrite => a.idle.map(|i| {
            format!(
                "no data moved for {} (--idle-timeout); progress is kept, so run the same command to continue",
                format_span(i)
            )
        }),
        Connect | Resolve => a.connect.map(|c| {
            format!(
                "could not connect within {} (--connect-timeout); check the network or raise the limit",
                format_span(c)
            )
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_parse_spans_and_off() {
        assert_eq!(
            parse_limit("45s").unwrap(),
            Limit(Some(Duration::from_secs(45)))
        );
        assert_eq!(
            parse_limit("1h30m").unwrap(),
            Limit(Some(Duration::from_secs(5400)))
        );
        assert_eq!(parse_limit("OFF").unwrap(), Limit(None));
    }

    #[test]
    fn ambiguous_or_empty_limits_are_rejected() {
        for bad in ["", "30", "0s", "1.5s", "-1s", "s", "5x", "31d", "off1"] {
            assert!(parse_limit(bad).is_err(), "{bad:?}");
        }
    }
}
