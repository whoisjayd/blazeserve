//! Parsing of upload request headers: digests, `If-Match`, `Content-Range` and `Content-Length`.

use base64::Engine as _;
use hyper::header::{self, HeaderMap};

fn parse_sha256_token(v: &str) -> Result<[u8; 32], ()> {
    let v = v.trim().trim_matches(':');
    if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (i, pair) in v.as_bytes().chunks(2).enumerate() {
            let hi = (pair[0] as char).to_digit(16).ok_or(())?;
            let lo = (pair[1] as char).to_digit(16).ok_or(())?;
            out[i] = (hi * 16 + lo) as u8;
        }
        return Ok(out);
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(v)
        .map_err(|_| ())?;
    raw.try_into().map_err(|_| ())
}

/// SHA-256 member of an `alg=value` list header; `Err` when present but malformed.
fn sha256_from_list(headers: &HeaderMap, name: &str) -> Result<Option<[u8; 32]>, ()> {
    for value in headers.get_all(name) {
        let value = value.to_str().map_err(|_| ())?;
        for member in value.split(',') {
            if let Some((alg, token)) = member.split_once('=') {
                let alg = alg.trim();
                if alg.eq_ignore_ascii_case("sha-256") || alg.eq_ignore_ascii_case("sha256") {
                    return parse_sha256_token(token).map(Some);
                }
            }
        }
    }
    Ok(None)
}

#[derive(Default)]
pub(super) struct Digests {
    pub(super) body: Option<[u8; 32]>,
    pub(super) repr: Option<[u8; 32]>,
}

pub(super) fn request_digests(headers: &HeaderMap) -> Result<Digests, ()> {
    let mut body = sha256_from_list(headers, "content-digest")?;
    if body.is_none() {
        body = sha256_from_list(headers, "digest")?;
    }
    if body.is_none()
        && let Some(v) = headers.get("x-content-sha256")
    {
        body = Some(parse_sha256_token(v.to_str().map_err(|_| ())?)?);
    }
    let repr = sha256_from_list(headers, "repr-digest")?;
    Ok(Digests { body, repr })
}

/// `Ok(None)`: header absent. `Err`: `*` or an unparsable list.
pub(super) fn if_match(headers: &HeaderMap) -> Result<Option<Vec<String>>, ()> {
    let mut tags = Vec::new();
    for value in headers.get_all(header::IF_MATCH) {
        for tag in value.to_str().map_err(|_| ())?.split(',') {
            let tag = tag.trim();
            if tag == "*" || tag.is_empty() {
                return Err(());
            }
            tags.push(tag.to_owned());
        }
    }
    Ok((!tags.is_empty()).then_some(tags))
}

pub(super) struct ContentRange {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) total: u64,
}

pub(super) fn parse_content_range(v: &str) -> Option<ContentRange> {
    let spec = v.trim().strip_prefix("bytes ")?;
    let (range, total) = spec.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let (start, end, total) = (
        start.trim().parse().ok()?,
        end.trim().parse().ok()?,
        total.trim().parse().ok()?,
    );
    (start <= end && end < total).then_some(ContentRange { start, end, total })
}

pub(super) enum LengthError {
    Missing,
    Invalid,
}

pub(super) fn content_length(headers: &HeaderMap) -> Result<u64, LengthError> {
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return Err(LengthError::Missing);
    }
    let v = headers
        .get(header::CONTENT_LENGTH)
        .ok_or(LengthError::Missing)?;
    let s = v.to_str().map_err(|_| LengthError::Invalid)?.trim();
    if s.is_empty() {
        return Err(LengthError::Missing);
    }
    s.parse::<u64>().map_err(|_| LengthError::Invalid)
}

#[cfg(test)]
mod tests {
    use hyper::header::HeaderValue;
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn digest_token_forms_agree() {
        let digest = Sha256::digest(b"hello");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let b64v = base64::engine::general_purpose::STANDARD.encode(digest);
        let a = parse_sha256_token(&hex).unwrap();
        assert_eq!(a, parse_sha256_token(&b64v).unwrap());
        assert_eq!(a, parse_sha256_token(&format!(":{b64v}:")).unwrap());
        assert!(parse_sha256_token("not-a-digest").is_err());
        assert!(parse_sha256_token("AAAA").is_err());
    }

    #[test]
    fn digest_headers_pick_sha256_and_ignore_other_algorithms() {
        let mut h = HeaderMap::new();
        let d = Sha256::digest(b"x");
        h.insert(
            "digest",
            HeaderValue::from_str(&format!(
                "md5=zzz, sha-256={}",
                base64::engine::general_purpose::STANDARD.encode(d)
            ))
            .unwrap(),
        );
        assert_eq!(request_digests(&h).unwrap().body, Some(d.into()));
        let mut only_md5 = HeaderMap::new();
        only_md5.insert("digest", HeaderValue::from_static("md5=abc"));
        assert!(request_digests(&only_md5).unwrap().body.is_none());
        let mut bad = HeaderMap::new();
        bad.insert("content-digest", HeaderValue::from_static("sha-256=:AAAA:"));
        assert!(request_digests(&bad).is_err());
    }

    #[test]
    fn content_range_validation() {
        let r = parse_content_range("bytes 5-9/10").unwrap();
        assert_eq!((r.start, r.end, r.total), (5, 9, 10));
        for bad in [
            "bytes 9-5/10",
            "bytes 0-10/10",
            "bytes */10",
            "bytes 0-4/*",
            "items 0-1/2",
            "bytes a-b/c",
        ] {
            assert!(parse_content_range(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn if_match_rejects_wildcard() {
        let mut h = HeaderMap::new();
        h.insert(header::IF_MATCH, HeaderValue::from_static("*"));
        assert!(if_match(&h).is_err());
        h.insert(header::IF_MATCH, HeaderValue::from_static("\"a\", \"b\""));
        assert_eq!(if_match(&h).unwrap().unwrap(), ["\"a\"", "\"b\""]);
        assert!(if_match(&HeaderMap::new()).unwrap().is_none());
    }
}
