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

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncSeekExt, AsyncWriteExt, BufWriter};

use crate::metrics::Metrics;
use crate::security::{self, ResolveError};
use crate::{AppState, Body, PeerInfo};

const PREFIX: &str = "/__upload__/";
const PART_MARK: &str = ".blaze-part-";
const RESUME_SUFFIX: &str = ".blaze-resume";
const RESUME_PREFIX: &str = ".blaze-resume-";
const MAX_STAGED_NAME: usize = 180;
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Serializes check-then-publish so two in-process writers cannot interleave.
static COMMIT_LOCK: Mutex<()> = Mutex::new(());

fn active_set() -> &'static Mutex<HashSet<PathBuf>> {
    static SET: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

struct ActiveGuard(PathBuf);

impl ActiveGuard {
    fn acquire(path: &Path) -> Option<Self> {
        let mut set = active_set().lock().unwrap_or_else(|e| e.into_inner());
        set.insert(path.to_path_buf())
            .then(|| Self(path.to_path_buf()))
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        active_set()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

/// Removes the staging file on drop, including when the request future is cancelled.
struct StagingGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

fn build(status: StatusCode, extra: &[(&'static str, String)], body: Bytes) -> Response<Body> {
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

fn text(status: StatusCode, msg: &str) -> Response<Body> {
    build(status, &[], Bytes::from(msg.to_owned()))
}

/// Early rejection leaves the request body unread; closing prevents it being parsed
/// as the next request on a keep-alive connection.
fn reject(status: StatusCode, msg: &str) -> Response<Body> {
    let mut resp = text(status, msg);
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    resp
}

fn reject_with(status: StatusCode, msg: &str, extra: &[(&'static str, String)]) -> Response<Body> {
    let mut resp = build(status, extra, Bytes::from(msg.to_owned()));
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    resp
}

fn io_status(e: &io::Error) -> (StatusCode, &'static str) {
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

/// Validator for `If-Match`; also returned as `ETag` after a publish.
pub fn etag_for_metadata(meta: &std::fs::Metadata) -> String {
    crate::cache::etag_for(meta)
}

fn b64(digest: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(digest)
}

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
struct Digests {
    body: Option<[u8; 32]>,
    repr: Option<[u8; 32]>,
}

fn request_digests(headers: &HeaderMap) -> Result<Digests, ()> {
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
fn if_match(headers: &HeaderMap) -> Result<Option<Vec<String>>, ()> {
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

struct ContentRange {
    start: u64,
    end: u64,
    total: u64,
}

fn parse_content_range(v: &str) -> Option<ContentRange> {
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

struct Target {
    base: PathBuf,
    path: PathBuf,
    rel: String,
}

impl Target {
    fn name(&self) -> String {
        self.path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
    }

    fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(&self.base)
    }

    fn staging_path(&self, kind: Staging) -> PathBuf {
        let name = self.name();
        let file = match kind {
            Staging::Part => {
                let id = security::generate_request_id(None);
                if name.len() <= MAX_STAGED_NAME {
                    format!(".{name}{PART_MARK}{id}")
                } else {
                    format!("{PART_MARK}{id}")
                }
            }
            Staging::Resume => {
                if name.len() <= MAX_STAGED_NAME {
                    format!(".{name}{RESUME_SUFFIX}")
                } else {
                    let h = Sha256::digest(name.as_bytes());
                    let hex: String = h[..8].iter().map(|b| format!("{b:02x}")).collect();
                    format!("{RESUME_PREFIX}{hex}")
                }
            }
        };
        self.dir().join(file)
    }

    fn location(&self) -> String {
        let mut out = String::new();
        for seg in self.rel.split('/').filter(|s| !s.is_empty() && *s != ".") {
            out.push('/');
            out.push_str(&utf8_percent_encode(seg, PATH_SEGMENT).to_string());
        }
        out
    }
}

#[derive(Clone, Copy)]
enum Staging {
    Part,
    Resume,
}

pub fn is_reserved_name(name: &str) -> bool {
    name.contains(PART_MARK)
        || name.ends_with(RESUME_SUFFIX)
        || name.starts_with(PART_MARK)
        || name.starts_with(RESUME_PREFIX)
}

#[allow(clippy::result_large_err)]
fn parse_target(state: &AppState, req_path: &str) -> Result<Target, Response<Body>> {
    let raw = req_path
        .strip_prefix(PREFIX)
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "Not found"))?;
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "Invalid path encoding"))?;
    let rel = decoded.trim_matches(|c| c == '/' || c == '\\').to_owned();
    if rel.is_empty() {
        return Err(reject(StatusCode::BAD_REQUEST, "Missing file name"));
    }
    let base = state
        .config
        .base
        .canonicalize()
        .map_err(|_| reject(StatusCode::INTERNAL_SERVER_ERROR, "Upload failed"))?;
    let path = match security::resolve_under(&base, &rel) {
        Ok(p) => p,
        Err(ResolveError::Invalid) => {
            return Err(reject(StatusCode::BAD_REQUEST, "Invalid file name"));
        }
        Err(ResolveError::Escape) => return Err(reject(StatusCode::FORBIDDEN, "Forbidden")),
    };
    if path == base {
        return Err(reject(StatusCode::BAD_REQUEST, "Missing file name"));
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if is_reserved_name(&name) {
        return Err(reject(StatusCode::BAD_REQUEST, "Reserved file name"));
    }
    Ok(Target { base, path, rel })
}

enum LengthError {
    Missing,
    Invalid,
}

fn content_length(headers: &HeaderMap) -> Result<u64, LengthError> {
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

enum PublishError {
    Exists,
    Stale,
    NotRegular,
    Io(io::Error),
}

fn publish_create(base: &Path, staging: &Path, target: &Path) -> Result<(), PublishError> {
    let _lock = COMMIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !security::is_safe_path(base, target) {
        return Err(PublishError::Io(security::unsafe_io(
            "publish path escapes the root",
        )));
    }
    match std::fs::hard_link(staging, target) {
        Ok(()) => {
            let _ = std::fs::remove_file(staging);
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(PublishError::Exists),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(PublishError::Io(e)),
        // Filesystems without hard links: reserve the name exclusively, then copy.
        // Readers can observe the file while it is being filled.
        Err(_) => {
            let mut dst = match security::create_upload_file(base, target) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(PublishError::Exists);
                }
                Err(e) => return Err(PublishError::Io(e)),
            };
            let copied =
                std::fs::File::open(staging).and_then(|mut src| io::copy(&mut src, &mut dst));
            if let Err(e) = copied {
                drop(dst);
                let _ = std::fs::remove_file(target);
                return Err(PublishError::Io(e));
            }
            let _ = std::fs::remove_file(staging);
            Ok(())
        }
    }
}

fn publish_replace(
    base: &Path,
    staging: &Path,
    target: &Path,
    etags: &[String],
) -> Result<(), PublishError> {
    let _lock = COMMIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let meta = match std::fs::symlink_metadata(target) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(PublishError::Stale),
        Err(e) => return Err(PublishError::Io(e)),
    };
    if !meta.file_type().is_file() {
        return Err(PublishError::NotRegular);
    }
    if !etags.contains(&etag_for_metadata(&meta)) {
        return Err(PublishError::Stale);
    }
    if !security::is_safe_path(base, target) {
        return Err(PublishError::Io(security::unsafe_io(
            "publish path escapes the root",
        )));
    }
    std::fs::rename(staging, target).map_err(PublishError::Io)
}

async fn publish(
    t: &Target,
    staging: PathBuf,
    etags: Option<Vec<String>>,
) -> Result<(), PublishError> {
    let (base, target) = (t.base.clone(), t.path.clone());
    let joined = tokio::task::spawn_blocking(move || match etags {
        Some(tags) => publish_replace(&base, &staging, &target, &tags),
        None => publish_create(&base, &staging, &target),
    })
    .await;
    joined.unwrap_or_else(|e| Err(PublishError::Io(io::Error::other(e))))
}

fn publish_failure(e: PublishError) -> Response<Body> {
    match e {
        PublishError::Exists => text(StatusCode::CONFLICT, "Already exists"),
        PublishError::Stale => text(
            StatusCode::PRECONDITION_FAILED,
            "If-Match precondition failed",
        ),
        PublishError::NotRegular => text(StatusCode::CONFLICT, "Target is not a regular file"),
        PublishError::Io(e) => {
            let (status, msg) = io_status(&e);
            text(status, msg)
        }
    }
}

fn success(t: &Target, replaced: bool, digest: &[u8; 32]) -> Response<Body> {
    let mut extra = vec![
        ("content-digest", format!("sha-256=:{}:", b64(digest))),
        ("location", t.location()),
    ];
    if let Ok(meta) = std::fs::metadata(&t.path) {
        extra.push(("etag", etag_for_metadata(&meta)));
    }
    let status = if replaced {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    build(status, &extra, Bytes::new())
}

enum StreamError {
    Timeout,
    Body,
    Io(io::Error),
}

async fn pump(
    mut body: Incoming,
    out: &mut BufWriter<tokio::fs::File>,
    hasher: &mut Sha256,
    idle: Duration,
    expected: u64,
    metrics: &Metrics,
    accepted: &mut u64,
) -> Result<(), StreamError> {
    loop {
        let frame = match tokio::time::timeout(idle, body.frame()).await {
            Err(_) => return Err(StreamError::Timeout),
            Ok(None) => return Ok(()),
            Ok(Some(Err(_))) => return Err(StreamError::Body),
            Ok(Some(Ok(f))) => f,
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let n = data.len() as u64;
        if *accepted + n > expected {
            return Err(StreamError::Body);
        }
        out.write_all(&data).await.map_err(StreamError::Io)?;
        hasher.update(&data);
        *accepted += n;
        metrics.add_bytes_received(n);
    }
}

fn stream_failure(e: StreamError) -> Response<Body> {
    match e {
        StreamError::Timeout => reject(StatusCode::REQUEST_TIMEOUT, "Request body timed out"),
        StreamError::Body => reject(
            StatusCode::BAD_REQUEST,
            "Request body ended before Content-Length",
        ),
        StreamError::Io(e) => {
            let (status, msg) = io_status(&e);
            reject(status, msg)
        }
    }
}

fn buf_capacity(state: &AppState) -> usize {
    state.config.chunk_bytes.clamp(64 * 1024, 1024 * 1024)
}

fn idle(state: &AppState) -> Duration {
    Duration::from_secs(state.config.timeout_secs.max(1))
}

enum Existing {
    Absent,
    Regular,
    Other,
}

async fn probe(path: &Path) -> io::Result<Existing> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(m) if m.file_type().is_file() => Ok(Existing::Regular),
        Ok(_) => Ok(Existing::Other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Existing::Absent),
        Err(e) => Err(e),
    }
}

#[allow(clippy::result_large_err)]
async fn precheck(t: &Target, tags: &Option<Vec<String>>) -> Result<(), Response<Body>> {
    let existing = probe(&t.path).await.map_err(|e| {
        let (status, msg) = io_status(&e);
        reject(status, msg)
    })?;
    match (existing, tags) {
        (Existing::Absent, None) => Ok(()),
        (Existing::Absent, Some(_)) => Err(reject(
            StatusCode::PRECONDITION_FAILED,
            "Target does not exist",
        )),
        (Existing::Other, _) => Err(reject(StatusCode::CONFLICT, "Target is not a regular file")),
        (Existing::Regular, None) => Err(reject(StatusCode::CONFLICT, "Already exists")),
        (Existing::Regular, Some(tags)) => {
            let meta = tokio::fs::symlink_metadata(&t.path)
                .await
                .map_err(|_| reject(StatusCode::PRECONDITION_FAILED, "Target does not exist"))?;
            if tags.contains(&etag_for_metadata(&meta)) {
                Ok(())
            } else {
                Err(reject(
                    StatusCode::PRECONDITION_FAILED,
                    "If-Match precondition failed",
                ))
            }
        }
    }
}

async fn create_staging(t: &Target, path: PathBuf) -> io::Result<std::fs::File> {
    let base = t.base.clone();
    tokio::task::spawn_blocking(move || security::create_upload_file(&base, &path))
        .await
        .unwrap_or_else(|e| Err(io::Error::other(e)))
}

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

async fn plain(
    state: &Arc<AppState>,
    req: Request<Incoming>,
    t: Target,
    len: u64,
    digests: Digests,
    tags: Option<Vec<String>>,
) -> Response<Body> {
    let staging = t.staging_path(Staging::Part);
    let file = match create_staging(&t, staging.clone()).await {
        Ok(f) => f,
        Err(e) => {
            let (status, msg) = io_status(&e);
            return reject(status, msg);
        }
    };
    let mut guard = StagingGuard {
        path: staging.clone(),
        armed: true,
    };
    let mut out = BufWriter::with_capacity(buf_capacity(state), tokio::fs::File::from_std(file));
    let mut hasher = Sha256::new();
    let mut accepted = 0u64;
    let streamed = pump(
        req.into_body(),
        &mut out,
        &mut hasher,
        idle(state),
        len,
        &state.metrics,
        &mut accepted,
    )
    .await;
    if let Err(e) = streamed {
        return stream_failure(e);
    }
    if accepted != len {
        return reject(
            StatusCode::BAD_REQUEST,
            "Request body ended before Content-Length",
        );
    }
    if let Err(e) = out.flush().await {
        return finish_io(&e);
    }
    if let Err(e) = out.get_ref().sync_data().await {
        return finish_io(&e);
    }
    drop(out);
    let digest: [u8; 32] = hasher.finalize().into();
    if [digests.body, digests.repr]
        .into_iter()
        .flatten()
        .any(|d| d != digest)
    {
        return text(StatusCode::UNPROCESSABLE_ENTITY, "Digest mismatch");
    }
    let replaced = tags.is_some();
    match publish(&t, staging, tags).await {
        Ok(()) => {
            guard.armed = false;
            success(&t, replaced, &digest)
        }
        Err(e) => publish_failure(e),
    }
}

fn finish_io(e: &io::Error) -> Response<Body> {
    let (status, msg) = io_status(e);
    text(status, msg)
}

async fn resumable(
    state: &Arc<AppState>,
    req: Request<Incoming>,
    t: Target,
    len: u64,
    range: ContentRange,
    digests: Digests,
    tags: Option<Vec<String>>,
) -> Response<Body> {
    if len != range.end - range.start + 1 {
        return reject(
            StatusCode::BAD_REQUEST,
            "Content-Length does not match Content-Range",
        );
    }
    if let Some(tags) = &tags {
        if let Err(resp) = precheck(&t, &Some(tags.clone())).await {
            return resp;
        }
    } else if let Err(resp) = precheck(&t, &None).await {
        return resp;
    }
    let resume = t.staging_path(Staging::Resume);
    let Some(_active) = ActiveGuard::acquire(&resume) else {
        return reject(StatusCode::CONFLICT, "Upload in progress");
    };
    let base = t.base.clone();
    let path = resume.clone();
    let opened = tokio::task::spawn_blocking(move || match std::fs::symlink_metadata(&path) {
        Ok(_) => security::open_existing_for_append(&base, &path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            security::create_upload_file(&base, &path).map(|f| (f, 0))
        }
        Err(e) => Err(e),
    })
    .await
    .unwrap_or_else(|e| Err(io::Error::other(e)));
    let (file, staged) = match opened {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = io_status(&e);
            return reject(status, msg);
        }
    };
    if staged != range.start {
        return reject_with(
            StatusCode::CONFLICT,
            "Upload offset mismatch",
            &[("upload-offset", staged.to_string())],
        );
    }

    let mut file = tokio::fs::File::from_std(file);
    let mut out = BufWriter::with_capacity(buf_capacity(state), {
        if file.seek(io::SeekFrom::Start(staged)).await.is_err() {
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "Upload failed");
        }
        file
    });
    let mut hasher = Sha256::new();
    let mut accepted = 0u64;
    let streamed = pump(
        req.into_body(),
        &mut out,
        &mut hasher,
        idle(state),
        len,
        &state.metrics,
        &mut accepted,
    )
    .await;
    let flushed = out.flush().await;
    if let Err(e) = streamed {
        return stream_failure(e);
    }
    if let Err(e) = flushed {
        return finish_io(&e);
    }
    if accepted != len {
        return reject(
            StatusCode::BAD_REQUEST,
            "Request body ended before Content-Length",
        );
    }
    let chunk_digest: [u8; 32] = hasher.finalize().into();
    if digests.body.is_some_and(|d| d != chunk_digest) {
        let rolled_back = out.get_ref().set_len(range.start).await;
        return match rolled_back {
            Ok(()) => text(StatusCode::UNPROCESSABLE_ENTITY, "Chunk digest mismatch"),
            Err(e) => finish_io(&e),
        };
    }
    if let Err(e) = out.get_ref().sync_data().await {
        return finish_io(&e);
    }
    drop(out);

    let new_len = range.start + accepted;
    if new_len < range.total {
        return build(
            StatusCode::ACCEPTED,
            &[
                ("upload-offset", new_len.to_string()),
                ("upload-length", range.total.to_string()),
            ],
            Bytes::new(),
        );
    }

    let whole = {
        let path = resume.clone();
        tokio::task::spawn_blocking(move || hash_file(&path))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)))
    };
    let whole = match whole {
        Ok(d) => d,
        Err(e) => return finish_io(&e),
    };
    if digests.repr.is_some_and(|d| d != whole) {
        let _ = tokio::fs::remove_file(&resume).await;
        return text(StatusCode::UNPROCESSABLE_ENTITY, "Digest mismatch");
    }
    let replaced = tags.is_some();
    match publish(&t, resume, tags).await {
        Ok(()) => success(&t, replaced, &whole),
        Err(e) => publish_failure(e),
    }
}

fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buf[..n]);
    }
}

#[cfg(test)]
mod tests {
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
            HeaderValue::from_str(&format!("md5=zzz, sha-256={}", b64(&d.into()))).unwrap(),
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

    #[test]
    fn reserved_names_are_blocked() {
        assert!(is_reserved_name(".x.blaze-resume"));
        assert!(is_reserved_name(".x.blaze-part-abc"));
        assert!(is_reserved_name(".blaze-resume-0011"));
        assert!(!is_reserved_name("report.txt"));
    }

    #[test]
    fn etag_changes_with_content_size() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, b"a").unwrap();
        let a = etag_for_metadata(&std::fs::metadata(&p).unwrap());
        std::fs::write(&p, b"abcdef").unwrap();
        let b = etag_for_metadata(&std::fs::metadata(&p).unwrap());
        assert_ne!(a, b);
        assert!(a.starts_with('"') && a.ends_with('"') && a.len() == 22);
    }

    #[test]
    fn publish_create_never_overwrites() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().canonicalize().unwrap();
        let target = base.join("t");
        let (s1, s2) = (base.join("s1"), base.join("s2"));
        std::fs::write(&s1, b"one").unwrap();
        std::fs::write(&s2, b"two").unwrap();
        assert!(publish_create(&base, &s1, &target).is_ok());
        assert!(matches!(
            publish_create(&base, &s2, &target),
            Err(PublishError::Exists)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"one");
    }

    #[test]
    fn publish_replace_requires_current_etag() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().canonicalize().unwrap();
        let target = base.join("t");
        let staging = base.join("s");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&staging, b"new").unwrap();
        assert!(matches!(
            publish_replace(&base, &staging, &target, &["\"stale\"".into()]),
            Err(PublishError::Stale)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        let current = etag_for_metadata(&std::fs::metadata(&target).unwrap());
        assert!(publish_replace(&base, &staging, &target, &[current]).is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }
}
