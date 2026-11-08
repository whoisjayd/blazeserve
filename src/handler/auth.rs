use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use hyper::header::{self, HeaderMap};
use hyper::{Response, StatusCode};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::response::{empty, finish};
use crate::Body;
use crate::config::Config;

pub(super) fn unauthorized() -> Response<Body> {
    finish(
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"blazeserve\"")
            .header(header::CONTENT_LENGTH, 0),
        empty(),
    )
}

pub(super) fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = String::from_utf8(ENGINE.decode(token.trim()).ok()?).ok()?;
    let (user, password) = raw.split_once(':')?;
    Some((user.to_owned(), password.to_owned()))
}

/// Hashing first makes the comparison length-independent as well as constant-time.
pub(super) fn secret_eq(a: &str, b: &str) -> bool {
    Sha256::digest(a.as_bytes())
        .ct_eq(&Sha256::digest(b.as_bytes()))
        .into()
}

pub(super) fn auth_ok(cfg: &Config, headers: &HeaderMap) -> bool {
    let Some(expected) = &cfg.auth else {
        return true;
    };
    let Some((user, password)) = basic_credentials(headers) else {
        return false;
    };
    // `&` rather than `&&`: both fields are always compared.
    secret_eq(&user, &expected.user) & secret_eq(&password, &expected.password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::response::hv;
    use hyper::header::HeaderValue;

    #[test]
    fn basic_credentials_parse_and_reject() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic dTpwOmE="),
        );
        assert_eq!(basic_credentials(&h), Some(("u".into(), "p:a".into())));
        for bad in ["Bearer abc", "Basic", "Basic !!!", "Basic bm9jb2xvbg=="] {
            h.insert(header::AUTHORIZATION, hv(bad));
            assert_eq!(basic_credentials(&h), None, "{bad}");
        }
    }
}
