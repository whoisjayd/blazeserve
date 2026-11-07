//! Upload path under `/__upload__/<name>`.
//!
//! Protocol summary (all responses carry `Content-Length`):
//!
//! | Request | Result |
//! |---|---|
//! | `PUT`/`POST`, target absent | stream to a same-directory staging file, verify, publish no-replace: `201`, `ETag`, `Content-Digest`, `Location` |
//! | target present, no `If-Match` | `409`, target untouched |
//! | target present, `If-Match: "<etag>"` current | atomic replace: `200` |
//! | `If-Match` stale or target missing | `412` |
//! | digest header mismatch | `422`; nothing published |
//! | `Content-Range: bytes S-E/T` | resumable: appends only when `S` equals the staged length (else `409` + `Upload-Offset`); `202` until `E+1==T`, then verify and publish |
//! | `HEAD`/`GET` | `Upload-Offset` of a partial, or `Upload-Complete: ?1` for a published file; `404` otherwise |
//! | `DELETE` | discard a partial only; published files are never deleted |
//!
//! Digest headers: `Content-Digest`, `Digest`, `X-Content-SHA256` verify the request
//! body (a single chunk on `Content-Range` requests); `Repr-Digest` verifies the
//! whole assembled file. SHA-256 only; unknown algorithms are ignored.

mod plain;
mod publish;
mod request;
mod response;
mod resumable;
mod stream;
mod target;

use std::sync::Arc;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};

use crate::{AppState, Body, PeerInfo};

pub use publish::etag_for_metadata;
pub use target::is_reserved_name;

use plain::plain;
use publish::precheck;
use request::{LengthError, content_length, if_match, parse_content_range, request_digests};
use response::{build, io_status, reject, text};
use resumable::resumable;
use stream::ActiveGuard;
use target::{Staging, Target, parse_target};

/// Entry point for `/__upload__/` requests. The caller authenticates first and decorates the response.
/// A zero `max_upload_bytes` disables the whole namespace, status requests included.
pub async fn handle_upload(
    state: &Arc<AppState>,
    _peer: &PeerInfo,
    req: Request<Incoming>,
) -> Response<Body> {
    if state.config.max_upload_bytes == 0 {
        return reject(StatusCode::FORBIDDEN, "Uploads are disabled");
    }
    let target = match parse_target(state, req.uri().path()) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    match *req.method() {
        Method::PUT | Method::POST => upload(state, req, target).await,
        Method::GET | Method::HEAD => status(&target).await,
        Method::DELETE => abort(state, &target).await,
        _ => {
            let mut resp = reject(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed");
            resp.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_static("PUT, POST, GET, HEAD, DELETE"),
            );
            resp
        }
    }
}

async fn status(t: &Target) -> Response<Body> {
    let resume = t.staging_path(Staging::Resume);
    if let Ok(meta) = tokio::fs::symlink_metadata(&resume).await
        && meta.file_type().is_file()
    {
        return build(
            StatusCode::OK,
            &[
                ("upload-offset", meta.len().to_string()),
                ("upload-complete", "?0".into()),
            ],
            Bytes::new(),
        );
    }
    match tokio::fs::symlink_metadata(&t.path).await {
        Ok(meta) if meta.file_type().is_file() => build(
            StatusCode::OK,
            &[
                ("upload-offset", meta.len().to_string()),
                ("upload-complete", "?1".into()),
            ],
            Bytes::new(),
        ),
        _ => text(StatusCode::NOT_FOUND, "No upload"),
    }
}

async fn abort(state: &Arc<AppState>, t: &Target) -> Response<Body> {
    let resume = t.staging_path(Staging::Resume);
    let Some(_active) = ActiveGuard::acquire(&resume) else {
        return text(StatusCode::CONFLICT, "Upload in progress");
    };
    match tokio::fs::symlink_metadata(&resume).await {
        Ok(m) if m.file_type().is_file() => match tokio::fs::remove_file(&resume).await {
            Ok(()) => build(StatusCode::NO_CONTENT, &[], Bytes::new()),
            Err(e) => {
                state.metrics.add_error();
                let (status, msg) = io_status(&e);
                text(status, msg)
            }
        },
        _ => text(StatusCode::NOT_FOUND, "No partial upload"),
    }
}

async fn upload(state: &Arc<AppState>, req: Request<Incoming>, t: Target) -> Response<Body> {
    let tags = match if_match(req.headers()) {
        Ok(v) => v,
        Err(()) => return reject(StatusCode::BAD_REQUEST, "Unsupported If-Match value"),
    };
    let digests = match request_digests(req.headers()) {
        Ok(d) => d,
        Err(()) => return reject(StatusCode::BAD_REQUEST, "Malformed digest header"),
    };
    let range = match req.headers().get(header::CONTENT_RANGE) {
        None => None,
        Some(v) => match v.to_str().ok().and_then(parse_content_range) {
            Some(r) => Some(r),
            None => return reject(StatusCode::BAD_REQUEST, "Invalid Content-Range"),
        },
    };
    if range.is_none()
        && let Err(resp) = precheck(&t, &tags).await
    {
        return resp;
    }
    let len = match content_length(req.headers()) {
        Ok(n) => n,
        Err(LengthError::Missing) => {
            return reject(StatusCode::LENGTH_REQUIRED, "Content-Length required");
        }
        Err(LengthError::Invalid) => {
            return reject(StatusCode::BAD_REQUEST, "Invalid Content-Length");
        }
    };
    let max = state.config.max_upload_bytes;
    let declared = range.as_ref().map_or(len, |r| r.total);
    if max > 0 && declared > max {
        return reject(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Upload exceeds the size limit",
        );
    }
    match range {
        None => plain(state, req, t, len, digests, tags).await,
        Some(r) => resumable(state, req, t, len, r, digests, tags).await,
    }
}
