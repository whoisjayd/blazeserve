//! The job record: one small versioned JSON document per background job, plus the
//! rules that turn it into something safe to show.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

/// An active job whose record has not been refreshed for this long is reported as failed.
/// Workers refresh every second, so this only fires after a crash, a kill or a long suspend.
pub const STALE_AFTER_SECS: u64 = 30;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Get,
    Put,
    Serve,
    Send,
}

impl Kind {
    pub fn is_server(self) -> bool {
        matches!(self, Self::Serve | Self::Send)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Put => "put",
            Self::Serve => "serve",
            Self::Send => "send",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Starting,
    Running,
    Stopping,
    Completed,
    Failed,
    Interrupted,
    Stopped,
}

impl State {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Starting | Self::Running | Self::Stopping)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Download,
    Upload,
}

impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Preparing,
    Transferring,
    Retrying,
    Finalizing,
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Transferring => "transferring",
            Self::Retrying => "retrying",
            Self::Finalizing => "finalizing",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Record {
    pub version: u32,
    pub id: String,
    pub kind: Kind,
    pub pid: u32,
    pub state: State,
    /// Seconds since the Unix epoch.
    pub started_at: u64,
    pub updated_at: u64,
    /// Set once the worker has finished its checks (and, for servers, bound its socket).
    /// A job that ends without it failed to launch.
    pub ready_at: Option<u64>,
    pub label: String,
    /// Given by the user with `--name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub remote: Option<String>,
    pub direction: Option<Direction>,
    pub phase: Option<Phase>,
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
    pub speed_bps: Option<u64>,
    pub listen: Option<String>,
    pub result: Option<String>,
    pub log: String,
}

impl Record {
    pub fn new(id: &str, kind: Kind, pid: u32, now: u64, log: &str) -> Self {
        Self {
            version: SCHEMA_VERSION,
            id: id.to_owned(),
            kind,
            pid,
            state: State::Starting,
            started_at: now,
            updated_at: now,
            ready_at: None,
            label: String::new(),
            name: None,
            remote: None,
            direction: None,
            phase: (!kind.is_server()).then_some(Phase::Preparing),
            bytes_done: 0,
            bytes_total: None,
            speed_bps: None,
            listen: None,
            result: None,
            log: log.to_owned(),
        }
    }

    /// What a reader should show at `now`: an active record nobody has refreshed lately
    /// belongs to a process that is gone, so it is reported as failed.
    pub fn effective(mut self, now: u64) -> Self {
        if self.state.is_active() && now.saturating_sub(self.updated_at) > STALE_AFTER_SECS {
            self.state = State::Failed;
            self.phase = None;
            self.speed_bps = None;
            self.result = Some(
                "the worker stopped updating its record (it crashed or was killed); no final result was saved"
                    .to_owned(),
            );
        }
        self
    }

    pub fn percent(&self) -> Option<f64> {
        let total = self.bytes_total.filter(|t| *t > 0)?;
        Some((self.bytes_done as f64 * 100.0 / total as f64).min(100.0))
    }

    pub fn eta_secs(&self) -> Option<u64> {
        let total = self.bytes_total?;
        let speed = self.speed_bps.filter(|s| *s > 0)?;
        Some(total.saturating_sub(self.bytes_done).div_ceil(speed))
    }
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 8 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

const LABEL_MAX: usize = 120;

/// Control characters become visible escapes so a name can never drive the terminal.
pub fn escape_control(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// A short display name: escaped, never a full path, capped in length.
pub fn label(name: &str) -> String {
    let escaped = escape_control(name);
    if escaped.chars().count() <= LABEL_MAX {
        return escaped;
    }
    let cut: String = escaped.chars().take(LABEL_MAX - 1).collect();
    format!("{cut}…")
}

/// `scheme://host[:port]` of a URL, without user information, path, query or fragment.
pub fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    if host.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    Some(escape_control(&format!("{scheme}://{host}")))
}

/// Error text for a record or log: known secret shapes masked, URLs cut back to their
/// origin and path, control characters escaped.
pub fn scrub(text: &str) -> String {
    let masked = crate::logging::redact(text);
    let cleaned: Vec<String> = masked
        .split(' ')
        .map(|word| {
            let Some((scheme, rest)) = word.split_once("://") else {
                return word.to_owned();
            };
            let rest = rest.split(['?', '#']).next().unwrap_or("");
            match rest.split_once('/') {
                Some((auth, path)) => {
                    format!(
                        "{scheme}://{}/{path}",
                        auth.rsplit('@').next().unwrap_or("")
                    )
                }
                None => format!("{scheme}://{}", rest.rsplit('@').next().unwrap_or("")),
            }
        })
        .collect();
    escape_control(&cleaned.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record::new("0123abcd", Kind::Get, 42, 1_000, "log")
    }

    #[test]
    fn ids_are_eight_lowercase_hex_characters() {
        assert!(valid_id("0123abcd"));
        for bad in [
            "",
            "0123abc",
            "0123abcde",
            "0123ABCD",
            "../../x1",
            "0123abc/",
        ] {
            assert!(!valid_id(bad), "{bad}");
        }
    }

    #[test]
    fn active_record_without_a_heartbeat_is_reported_failed() {
        let mut r = record();
        r.state = State::Running;
        r.speed_bps = Some(10);
        let fresh = r.clone().effective(1_000 + STALE_AFTER_SECS);
        assert_eq!(fresh.state, State::Running);
        let stale = r.effective(1_000 + STALE_AFTER_SECS + 1);
        assert_eq!(stale.state, State::Failed);
        assert_eq!(stale.speed_bps, None);
        assert!(stale.result.unwrap().contains("stopped updating"));
    }

    #[test]
    fn finished_record_is_never_rewritten_by_staleness() {
        let mut r = record();
        r.state = State::Completed;
        assert_eq!(r.effective(1_000_000).state, State::Completed);
    }

    #[test]
    fn percent_and_eta_are_unknown_without_data() {
        let mut r = record();
        assert_eq!((r.percent(), r.eta_secs()), (None, None));
        r.bytes_total = Some(0);
        assert_eq!(r.percent(), None);
        r.bytes_total = Some(200);
        r.bytes_done = 50;
        assert_eq!(r.percent(), Some(25.0));
        assert_eq!(r.eta_secs(), None);
        r.speed_bps = Some(0);
        assert_eq!(r.eta_secs(), None);
        r.speed_bps = Some(40);
        assert_eq!(r.eta_secs(), Some(4));
    }

    #[test]
    fn origin_drops_credentials_path_query_and_fragment() {
        assert_eq!(
            origin("https://user:secret@host.example:8443/a/b?token=abc#frag").as_deref(),
            Some("https://host.example:8443")
        );
        assert_eq!(origin("http://h:1").as_deref(), Some("http://h:1"));
        assert_eq!(origin("not a url"), None);
        assert_eq!(origin("http://u:p@/x"), None);
    }

    #[test]
    fn labels_escape_control_characters_and_are_capped() {
        assert_eq!(label("a\x1b[31mb\n"), "a\\u{1b}[31mb\\n");
        assert_eq!(label("x\u{202e}y"), "x\\u{202e}y");
        let long = label(&"n".repeat(500));
        assert_eq!(long.chars().count(), LABEL_MAX);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn scrub_removes_userinfo_query_and_fragment_from_urls() {
        let out = scrub(
            "request to https://bob:hunter2@host:9/p/f.bin?X-Signature=abc123#top failed: boom",
        );
        assert_eq!(out, "request to https://host:9/p/f.bin failed: boom");
        assert!(!scrub("Authorization: Basic Zm9vOmJhcg==").contains("Zm9v"));
        assert_eq!(scrub("bad\x07bell"), "bad\\u{7}bell");
    }
}
