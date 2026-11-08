//! Plain-text responses and the status mapping for I/O errors.

use std::io;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};

use crate::Body;
use crate::security;

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

pub(super) fn build(
    status: StatusCode,
    extra: &[(&'static str, String)],
    body: Bytes,
) -> Response<Body> {
    let mut resp = Response::new(full(body.clone()));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    if !body.is_empty() {
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (k, v) in extra {
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(*k, v);
        }
    }
    resp
}

pub(super) fn text(status: StatusCode, msg: &str) -> Response<Body> {
    build(status, &[], Bytes::from(msg.to_owned()))
}

/// Early rejection leaves the request body unread; closing prevents it being parsed
/// as the next request on a keep-alive connection.
pub(super) fn reject(status: StatusCode, msg: &str) -> Response<Body> {
    let mut resp = text(status, msg);
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    resp
}

pub(super) fn reject_with(
    status: StatusCode,
    msg: &str,
    extra: &[(&'static str, String)],
) -> Response<Body> {
    let mut resp = build(status, extra, Bytes::from(msg.to_owned()));
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    resp
}

pub(super) fn io_status(e: &io::Error) -> (StatusCode, &'static str) {
    if security::is_unsafe_path_error(e) {
        (StatusCode::FORBIDDEN, "Forbidden")
    } else if e.kind() == io::ErrorKind::AlreadyExists {
        (StatusCode::CONFLICT, "Already exists")
    } else if e.kind() == io::ErrorKind::StorageFull {
        (StatusCode::INSUFFICIENT_STORAGE, "Insufficient storage")
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "Upload failed")
    }
}

pub(super) fn finish_io(e: &io::Error) -> Response<Body> {
    let (status, msg) = io_status(e);
    text(status, msg)
}
