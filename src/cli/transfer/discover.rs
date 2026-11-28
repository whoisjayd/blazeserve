//! `blaze get --verify server-sha256`: ask the server for the file's SHA-256 before downloading.

use super::http::{describe_error, header, http_failure};
use base64::Engine as _;
use std::time::Duration;

/// Hashing a large file can take a while, so the wait for the reply is generous.
const HASH_WAIT: Duration = Duration::from_secs(600);
const MAX_BODY: u64 = 4096;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ServerDigest {
    pub(super) sha256: String,
    pub(super) size: u64,
}

/// Adds the `hash` query parameter, keeping every existing parameter and dropping any fragment.
pub(super) fn hash_url(url: &str) -> String {
    let base = url.split_once('#').map_or(url, |(u, _)| u);
    let sep = match base.find('?') {
        None => "?",
        Some(_) if base.ends_with(['?', '&']) => "",
        Some(_) => "&",
    };
    format!("{base}{sep}hash")
}

pub(super) fn parse_digest(body: &[u8], repr_digest: Option<&str>) -> Result<ServerDigest, String> {
    let bad = |why: &str| format!("the server's hash reply is not usable: {why}");
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| bad("it is not valid JSON"))?;
    let sha256 = value
        .get("sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("no sha256 field"))?;
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad("sha256 is not 64 hexadecimal characters"));
    }
    let size = value
        .get("size")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| bad("no size field"))?;
    let sha256 = sha256.to_ascii_lowercase();
    if let Some(header) = repr_digest {
        let b64 = header
            .trim()
            .strip_prefix("sha-256=:")
            .and_then(|r| r.strip_suffix(':'))
            .ok_or_else(|| bad("Repr-Digest is not a single sha-256 value"))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| bad("Repr-Digest is not valid base64"))?;
        if crate::cli::util::hex(&raw) != sha256 {
            return Err(bad("the body and Repr-Digest disagree"));
        }
    }
    Ok(ServerDigest { sha256, size })
}

pub(super) fn discover(url: &str, auth: Option<&str>) -> Result<ServerDigest, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(None)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(HASH_WAIT))
        .build()
        .into();
    let mut req = agent
        .get(hash_url(url))
        .header("Accept-Encoding", "identity");
    if let Some(a) = auth {
        req = req.header("Authorization", a);
    }
    let resp = req.call().map_err(|e| describe_error(&e))?;
    let status = resp.status().as_u16();
    if status != 200 {
        let why = match status {
            404 | 405 | 501 => {
                "the server does not offer a SHA-256 for this URL; --verify server-sha256 needs a BlazeServe server"
                    .to_owned()
            }
            _ => http_failure(status, false),
        };
        return Err(format!("cannot get the server's SHA-256: {why}"));
    }
    let is_json =
        header(&resp, "content-type").is_some_and(|v| v.to_ascii_lowercase().contains("json"));
    if !is_json {
        return Err(
            "cannot get the server's SHA-256: the server did not answer with JSON; --verify server-sha256 needs a BlazeServe server"
                .to_owned(),
        );
    }
    let repr = header(&resp, "repr-digest");
    let body = resp
        .into_body()
        .with_config()
        .limit(MAX_BODY)
        .read_to_vec()
        .map_err(|_| "the server's hash reply is too large or was cut short".to_owned())?;
    parse_digest(&body, repr.as_deref())
}

#[cfg(fuzzing)]
pub fn parse_digest_for_fuzz(body: &[u8], repr_digest: Option<&str>) -> Option<(String, u64)> {
    parse_digest(body, repr_digest)
        .ok()
        .map(|d| (d.sha256, d.size))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_B64: &str = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";

    #[test]
    fn hash_url_keeps_existing_parameters() {
        assert_eq!(hash_url("http://h/a.bin"), "http://h/a.bin?hash");
        assert_eq!(hash_url("http://h/a.bin?t=1"), "http://h/a.bin?t=1&hash");
        assert_eq!(hash_url("http://h/a.bin?"), "http://h/a.bin?hash");
        assert_eq!(hash_url("http://h/a.bin?t=1&"), "http://h/a.bin?t=1&hash");
        assert_eq!(
            hash_url("http://h/a.bin?t=1#frag"),
            "http://h/a.bin?t=1&hash"
        );
    }

    #[test]
    fn accepts_a_consistent_reply() {
        let body = format!(r#"{{"path":"/a","size":3,"sha256":"{ABC}"}}"#);
        let repr = format!("sha-256=:{ABC_B64}:");
        let d = parse_digest(body.as_bytes(), Some(&repr)).unwrap();
        assert_eq!((d.sha256.as_str(), d.size), (ABC, 3));
        assert!(parse_digest(body.as_bytes(), None).is_ok());
    }

    #[test]
    fn rejects_malformed_or_ambiguous_replies() {
        let ok = |h: &str| format!(r#"{{"size":3,"sha256":"{h}"}}"#);
        assert!(parse_digest(b"not json", None).is_err());
        assert!(parse_digest(br#"{"size":3}"#, None).is_err());
        assert!(parse_digest(ok("abc").as_bytes(), None).is_err());
        assert!(parse_digest(ok(&"g".repeat(64)).as_bytes(), None).is_err());
        assert!(parse_digest(format!(r#"{{"sha256":"{ABC}"}}"#).as_bytes(), None).is_err());
        assert!(parse_digest(ok(ABC).as_bytes(), Some("sha-256=:AAAA:")).is_err());
        assert!(parse_digest(ok(ABC).as_bytes(), Some("sha-512=:AAAA:")).is_err());
    }

    proptest::proptest! {
        #[test]
        fn parsed_digests_are_lowercase_sha256(
            body in proptest::collection::vec(proptest::num::u8::ANY, 0..128),
            repr in proptest::option::of(".{0,80}"),
        ) {
            if let Ok(d) = parse_digest(&body, repr.as_deref()) {
                proptest::prop_assert_eq!(d.sha256.len(), 64);
                proptest::prop_assert!(
                    d.sha256
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                );
            }
        }
    }
}
