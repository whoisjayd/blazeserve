use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::response::Builder;
use hyper::{Response, StatusCode};

use super::scope::{RequestScope, Tracked};
use crate::{AppState, Body, PeerInfo};

pub(super) const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
pub(super) const CORS_METHODS: &str = "GET, HEAD, OPTIONS, PUT, POST";
pub(super) const CORS_ALLOW_HEADERS: &str = "Range, Content-Type, Authorization, X-Request-ID";
pub(super) const CORS_EXPOSE_HEADERS: &str = "Accept-Ranges, Content-Length, Content-Range, ETag, Last-Modified, X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining";

pub(super) fn hv(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static(""))
}

pub(super) fn finalize(
    state: &Arc<AppState>,
    peer: &PeerInfo,
    request_id: &str,
    head: bool,
    mut scope: RequestScope,
    mut resp: Response<Body>,
) -> Response<Body> {
    let cfg = &state.config;
    scope.status = resp.status().as_u16();
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    h.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    if peer.tls {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    h.insert(HeaderName::from_static("x-request-id"), hv(request_id));

    if let Some(bps) = cfg.rate_bps() {
        let remaining = state.limiters.get(peer.client_ip, Some(bps)).remaining();
        h.insert(
            HeaderName::from_static("x-ratelimit-limit"),
            hv(&(bps as u64).to_string()),
        );
        h.insert(
            HeaderName::from_static("x-ratelimit-remaining"),
            hv(&remaining.to_string()),
        );
    }

    if cfg.cors {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, hv(&cfg.cors_origin));
        h.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static(CORS_METHODS),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(CORS_ALLOW_HEADERS),
        );
        h.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static(CORS_EXPOSE_HEADERS),
        );
        add_vary(h, "Origin");
    }

    let (parts, body) = resp.into_parts();
    let inner = if head { empty() } else { body };
    Response::from_parts(parts, Tracked { inner, scope }.boxed())
}

pub(super) fn add_vary(h: &mut HeaderMap, token: &str) {
    let existing: Vec<&str> = h
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();
    if existing.iter().any(|t| t.eq_ignore_ascii_case(token)) {
        return;
    }
    let mut all = existing;
    all.push(token);
    let joined = all.join(", ");
    h.insert(header::VARY, hv(&joined));
}

pub(super) fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

pub(super) fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub(super) fn finish(builder: Builder, body: Body) -> Response<Body> {
    builder
        .body(body)
        .unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR))
}

pub(super) fn error(status: StatusCode) -> Response<Body> {
    let text = format!(
        "{} {}\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    );
    finish(
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::CONTENT_LENGTH, text.len()),
        full(text),
    )
}

pub(super) fn closing(mut resp: Response<Body>) -> Response<Body> {
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    resp
}

pub(super) fn no_content() -> Response<Body> {
    finish(Response::builder().status(StatusCode::NO_CONTENT), empty())
}

pub(super) fn method_not_allowed() -> Response<Body> {
    let mut resp = error(StatusCode::METHOD_NOT_ALLOWED);
    resp.headers_mut().insert(
        header::ALLOW,
        HeaderValue::from_static("GET, HEAD, OPTIONS"),
    );
    resp
}

pub(super) fn json_response(status: StatusCode, value: &serde_json::Value) -> Response<Body> {
    let body = serde_json::to_vec_pretty(value).unwrap_or_default();
    finish(
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::CACHE_CONTROL, "no-store"),
        full(body),
    )
}
