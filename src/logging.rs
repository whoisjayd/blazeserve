//! Human and JSON request/application logs with credential redaction.
//!
//! JSON mode owns stdout (one object per line); human lines go to stderr so they
//! never corrupt a JSON stream.

use crate::config::Config;
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
pub struct RequestLog<'a> {
    pub request_id: &'a str,
    /// Identity used for rate limiting (resolved through trusted proxies).
    pub client_ip: IpAddr,
    pub peer_ip: IpAddr,
    pub method: &'a str,
    pub target: &'a str,
    pub status: u16,
    pub bytes: u64,
    pub trace_id: Option<&'a str>,
    pub span_id: Option<&'a str>,
}

pub fn utc_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc(secs)
}

pub fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

const REDACTED: &str = "[REDACTED]";

pub fn redact(input: &str) -> String {
    redact_with(input, &[])
}

/// Like [`redact`], additionally masking every literal in `secrets` (for example
/// the values read from an `--auth-env` variable).
pub fn redact_with(input: &str, secrets: &[&str]) -> String {
    let mut out = redact_pem(input);
    out = redact_authorization(&out);
    out = redact_userinfo(&out);
    for s in secrets.iter().filter(|s| s.len() >= 3) {
        out = out.replace(s, REDACTED);
    }
    out
}

fn redact_pem(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start..];
        let header_end = after[11..].find("-----").map(|i| i + 11 + 5);
        let is_private = header_end.is_some_and(|e| after[..e].contains("PRIVATE KEY"));
        if !is_private {
            out.push_str(&rest[..start + 11]);
            rest = &rest[start + 11..];
            continue;
        }
        out.push_str(&rest[..start]);
        out.push_str(REDACTED);
        match after.find("-----END ") {
            Some(e) => {
                let tail = &after[e + 9..];
                rest = match tail.find("-----") {
                    Some(t) => &tail[t + 5..],
                    None => "",
                };
            }
            None => rest = "",
        }
    }
    out.push_str(rest);
    out
}

fn redact_authorization(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let needle = "authorization";
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while let Some(i) = lower[pos..].find(needle) {
        let at = pos + i;
        let after = at + needle.len();
        let bytes = s.as_bytes();
        let mut j = after;
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
            j += 1;
        }
        if j < bytes.len() && matches!(bytes[j], b':' | b'=') {
            j += 1;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'"' | b'\'') {
                j += 1;
            }
            let mut end = j;
            while end < bytes.len() && !matches!(bytes[end], b'\r' | b'\n' | b'"' | b'\'') {
                end += 1;
            }
            out.push_str(&s[pos..j]);
            out.push_str(REDACTED);
            pos = end;
        } else {
            out.push_str(&s[pos..after]);
            pos = after;
        }
    }
    out.push_str(&s[pos..]);
    out
}

fn redact_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let stop = tail
            .find(['/', '?', '#', ' ', '"', '\'', '\n'])
            .unwrap_or(tail.len());
        match tail[..stop].rfind('@') {
            Some(at) if tail[..at].contains(':') || at > 0 => {
                out.push_str(REDACTED);
                rest = &tail[at..];
            }
            _ => rest = tail,
        }
    }
    out.push_str(rest);
    out
}

fn json_escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn request_json(r: &RequestLog<'_>) -> String {
    let mut s = String::with_capacity(256);
    let _ = write!(
        s,
        "{{\"timestamp\":\"{}\",\"level\":\"INFO\",\"request_id\":",
        utc_timestamp()
    );
    json_escape(&redact(r.request_id), &mut s);
    let _ = write!(
        s,
        ",\"client_ip\":\"{}\",\"peer_ip\":\"{}\",\"request\":",
        r.client_ip, r.peer_ip
    );
    json_escape(&redact(&format!("{} {}", r.method, r.target)), &mut s);
    let _ = write!(s, ",\"status\":{},\"size\":{}", r.status, r.bytes);
    if let (Some(trace), Some(span)) = (r.trace_id, r.span_id) {
        s.push_str(",\"trace_id\":");
        json_escape(trace, &mut s);
        s.push_str(",\"span_id\":");
        json_escape(span, &mut s);
    }
    s.push('}');
    s
}

pub fn request_line(r: &RequestLog<'_>) -> String {
    let who = if r.client_ip == r.peer_ip {
        r.client_ip.to_string()
    } else {
        format!("{} via {}", r.client_ip, r.peer_ip)
    };
    format!(
        "{} {} {} {} {} {}B [{}]",
        utc_timestamp(),
        who,
        r.method,
        redact(r.target),
        r.status,
        r.bytes,
        r.request_id
    )
}

/// Emit an access-log record. JSON mode writes stdout; otherwise stderr, and only
/// when `verbose` is set so quiet servers stay quiet.
pub fn log_request(config: &Config, r: &RequestLog<'_>) {
    if config.log_json {
        let mut line = request_json(r);
        line.push('\n');
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    } else if config.verbose {
        eprintln!("{}", request_line(r));
    }
}

pub fn log_app(config: &Config, level: &str, message: &str) {
    let message = redact(message);
    if config.log_json {
        let mut s = String::new();
        let _ = write!(s, "{{\"timestamp\":\"{}\",\"level\":", utc_timestamp());
        json_escape(level, &mut s);
        s.push_str(",\"message\":");
        json_escape(&message, &mut s);
        s.push_str("}\n");
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(s.as_bytes());
        let _ = out.flush();
    } else {
        eprintln!("{} {} {}", utc_timestamp(), level, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_formats_known_instants() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(format_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn redacts_authorization_and_userinfo() {
        let m = redact("sent Authorization: Basic dXNlcjpwYXNz ok");
        assert!(!m.contains("dXNlcjpwYXNz") && m.contains(REDACTED));
        let u = redact("GET https://bob:s3cret@host/path");
        assert!(!u.contains("s3cret") && u.contains("host/path"));
    }

    #[test]
    fn redacts_private_keys_and_secrets() {
        let pem = "x -----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY----- y";
        let m = redact(pem);
        assert!(!m.contains("AAAA") && m.starts_with("x ") && m.ends_with(" y"));
        assert!(!redact_with("pw=hunter22", &["hunter22"]).contains("hunter22"));
        assert!(
            redact("-----BEGIN CERTIFICATE-----\nAB\n-----END CERTIFICATE-----").contains("AB")
        );
    }

    #[test]
    fn json_record_is_one_valid_object() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let r = RequestLog {
            request_id: "abc",
            client_ip: ip,
            peer_ip: ip,
            method: "GET",
            target: "/a\"b",
            status: 200,
            bytes: 5,
            trace_id: None,
            span_id: None,
        };
        let v: serde_json::Value = serde_json::from_str(&request_json(&r)).unwrap();
        assert_eq!(v["status"], 200);
        assert_eq!(v["size"], 5);
        assert_eq!(v["request"], "GET /a\"b");
        assert!(v["timestamp"].as_str().unwrap().ends_with('Z'));
        assert!(v.get("trace_id").is_none() && v.get("span_id").is_none());
    }

    #[test]
    fn json_record_carries_trace_ids_when_present() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let r = RequestLog {
            request_id: "abc",
            client_ip: ip,
            peer_ip: ip,
            method: "GET",
            target: "/",
            status: 200,
            bytes: 0,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736"),
            span_id: Some("00f067aa0ba902b7"),
        };
        let v: serde_json::Value = serde_json::from_str(&request_json(&r)).unwrap();
        assert_eq!(v["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(v["span_id"], "00f067aa0ba902b7");
    }
}
