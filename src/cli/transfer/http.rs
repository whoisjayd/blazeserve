//! Shared HTTP client setup, auth header, error wording and retry classification.

use crate::cli::serve::resolve_auth;
use base64::Engine as _;
use std::time::Duration;

pub(super) fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(None)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(60)))
        .build()
        .into()
}

pub(super) fn basic_header(
    auth: Option<&str>,
    auth_env: Option<&str>,
) -> Result<Option<String>, String> {
    Ok(resolve_auth(auth, auth_env)?.map(|c| {
        let raw = format!("{}:{}", c.user, c.password);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }))
}

pub(super) fn http_url(url: &str) -> Result<(), String> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(())
    } else {
        Err("URL must start with http:// or https://".to_owned())
    }
}

pub(super) fn transient_error(e: &ureq::Error) -> bool {
    !matches!(e, ureq::Error::BadUri(_) | ureq::Error::Http(_))
}

/// Network failures phrased for a person, keeping the OS detail only when nothing better is known.
fn explain_network_error(text: &str) -> String {
    let text = text.strip_prefix("io: ").unwrap_or(text);
    let lower = text.to_ascii_lowercase();
    if lower.contains("actively refused") || lower.contains("connection refused") {
        "connection refused: nothing is listening at that address; check the host and port"
            .to_owned()
    } else if lower.contains("timed out") || lower.contains("timeout") {
        "the connection timed out; check the network or try again".to_owned()
    } else if lower.contains("lookup")
        || lower.contains("no such host")
        || lower.contains("dns")
        || lower.contains("name or service")
        || lower.contains("no such host is known")
    {
        "cannot resolve the host name; check the URL and your network".to_owned()
    } else if lower.contains("certificate") || lower.contains("invalid peer") {
        format!("TLS verification failed: {text}")
    } else {
        text.to_owned()
    }
}

pub(super) fn describe_error(e: &ureq::Error) -> String {
    use std::io::ErrorKind;
    match e {
        ureq::Error::HostNotFound => {
            "cannot resolve the host name; check the URL and your network".to_owned()
        }
        ureq::Error::Timeout(_) => {
            "the connection timed out; check the network or try again".to_owned()
        }
        ureq::Error::ConnectionFailed => {
            "could not connect; check the host, the port and your network".to_owned()
        }
        ureq::Error::TooManyRedirects => "the server redirected too many times".to_owned(),
        ureq::Error::Tls(reason) => format!("TLS failure: {reason}"),
        ureq::Error::Io(io) if io.kind() == ErrorKind::ConnectionRefused => {
            "connection refused: nothing is listening at that address; check the host and port"
                .to_owned()
        }
        ureq::Error::Io(io) if io.kind() == ErrorKind::TimedOut => {
            "the connection timed out; check the network or try again".to_owned()
        }
        _ => explain_network_error(&e.to_string()),
    }
}

pub(super) fn transient_status(code: u16) -> bool {
    matches!(code, 408 | 425 | 429) || (500..=599).contains(&code)
}

/// A refusal the user can act on, never just a bare status code.
pub(super) fn http_failure(code: u16, upload: bool) -> String {
    let hint = match code {
        400 => "the server rejected the request as malformed",
        401 => "authentication is required; pass --auth USER:PASS or --auth-env VAR",
        403 if upload => {
            "the server refused the upload; check the credentials, and that it was started with --max-upload-mb above 0"
        }
        403 => {
            "the server refused access; check the credentials with --auth or --auth-env, or the host may block non-browser clients or require a signed link"
        }
        404 => "nothing exists at that URL; check the path",
        405 | 501 if upload => {
            "the server does not accept uploads at that URL; BlazeServe takes them under /__upload__/ when started with --max-upload-mb"
        }
        405 | 501 => "the server does not support this request",
        409 => "the destination already exists or changed; remove it or choose another name",
        410 => "the resource is gone",
        413 => "the server says the upload is too large",
        _ => "the server refused the request",
    };
    format!("server returned HTTP {code}: {hint}")
}

pub(super) fn header(resp: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_errors_are_explained() {
        let refused = explain_network_error(
            "io: No connection could be made because the target machine actively refused it. (os error 10061)",
        );
        assert!(refused.starts_with("connection refused"), "{refused}");
        assert!(explain_network_error("io: operation timed out").contains("timed out"));
        assert!(explain_network_error("failed to lookup address information").contains("resolve"));
        assert_eq!(explain_network_error("io: broken pipe"), "broken pipe");
    }

    #[test]
    fn http_failures_explain_the_next_step() {
        assert!(http_failure(403, false).contains("--auth"));
        assert!(http_failure(403, true).contains("--max-upload-mb"));
        assert!(http_failure(401, false).contains("--auth-env"));
        assert!(http_failure(404, false).starts_with("server returned HTTP 404"));
        assert!(http_failure(418, false).contains("HTTP 418"));
    }
}
