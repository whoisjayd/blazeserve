use std::collections::VecDeque;
use std::convert::Infallible;
use std::ffi::OsString;
use std::fs::Metadata;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::response::Builder;
use hyper::{Method, Request, Response, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::limiter::TokenBucket;
use crate::logging::{self, RequestLog};
use crate::metrics::RequestGuard;
use crate::range::{MAX_RANGES, RangeSpec, parse_range_header};
use crate::telemetry::{Outcome, RequestInfo, RequestSpan};
use crate::{AppState, Body, PeerInfo, VERSION, cache, security, ui, upload, zip_stream};

const MAX_SPEED_BYTES: u64 = 1000 * 1024 * 1024;
const SPEED_DEFAULT_BYTES: u64 = 100_000_000;
const ZERO_FRAME: usize = 1024 * 1024;
const UPLOAD_PREFIX: &str = "/__upload__/";
const MIB: usize = 1024 * 1024;

const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
const CORS_METHODS: &str = "GET, HEAD, OPTIONS, PUT, POST";
const CORS_ALLOW_HEADERS: &str = "Range, Content-Type, Authorization, X-Request-ID";
const CORS_EXPOSE_HEADERS: &str = "Accept-Ranges, Content-Length, Content-Range, ETag, Last-Modified, X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining";

pub async fn handle(
    state: Arc<AppState>,
    peer: PeerInfo,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let request_id = security::generate_request_id(
        req.headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok()),
    );
    let head = req.method() == Method::HEAD;
    let scope = RequestScope::begin(&state, &peer, &req, &request_id);
    let response = route(&state, &peer, req).await;
    Ok(finalize(&state, &peer, &request_id, head, scope, response))
}

async fn route(state: &Arc<AppState>, peer: &PeerInfo, req: Request<Incoming>) -> Response<Body> {
    let cfg = &state.config;
    let method = req.method().clone();

    if method == Method::OPTIONS {
        return if cfg.cors {
            no_content()
        } else {
            method_not_allowed()
        };
    }
    let reading = method == Method::GET || method == Method::HEAD;
    let writing = matches!(method, Method::PUT | Method::POST | Method::DELETE);
    if !reading && !writing {
        return method_not_allowed();
    }

    // The request body of a rejected write is never read, so those errors close the
    // connection instead of leaving unread bytes to be parsed as the next request.
    if !auth_ok(cfg, req.headers()) {
        return if writing {
            closing(unauthorized())
        } else {
            unauthorized()
        };
    }

    let path = req.uri().path().to_owned();
    if path.starts_with(UPLOAD_PREFIX) {
        return upload::handle_upload(state, peer, req).await;
    }
    if writing {
        return closing(method_not_allowed());
    }

    let head = method == Method::HEAD;
    match path.as_str() {
        "/__health__" => health(state),
        "/__live__" => json_response(StatusCode::OK, &json!({ "status": "alive" })),
        "/__ready__" => ready(cfg).await,
        "/__version__" => json_response(
            StatusCode::OK,
            &json!({
                "name": "blazeserve",
                "version": VERSION,
                "runtime": "rust",
                "platform": std::env::consts::OS,
                "architecture": std::env::consts::ARCH,
            }),
        ),
        "/__metrics__" | "/metrics" => metrics_response(state),
        "/__stats__" => json_response(
            StatusCode::OK,
            &json!({ "bytes_sent": state.metrics.bytes_sent() }),
        ),
        "/__perf__" => perf(state),
        "/__speed__" => speed(state, peer, req.uri().query(), head),
        "/__zip__" => zip_stream::handle_zip(state, req.uri().query(), head).await,
        _ => static_response(state, peer, &req, &path, head).await,
    }
}

struct LogMeta {
    method: String,
    target: String,
    request_id: String,
}

/// Everything that must end exactly once per request: the in-flight gauge, the trace span
/// and the access-log record. It lives in the response body, so all three finish when the
/// body completes or is dropped, not merely when the headers are produced.
struct RequestScope {
    _guard: RequestGuard,
    state: Arc<AppState>,
    span: Option<RequestSpan>,
    log: Option<LogMeta>,
    client_ip: IpAddr,
    peer_ip: IpAddr,
    upload: bool,
    declared_bytes: Option<u64>,
    status: u16,
    response_bytes: u64,
    ended: bool,
}

impl RequestScope {
    fn begin(
        state: &Arc<AppState>,
        peer: &PeerInfo,
        req: &Request<Incoming>,
        request_id: &str,
    ) -> Self {
        let cfg = &state.config;
        let headers = req.headers();
        let text = |name: header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
        let span = state.telemetry.is_enabled().then(|| {
            let version = match req.version() {
                hyper::Version::HTTP_10 => "1.0",
                hyper::Version::HTTP_2 => "2",
                _ => "1.1",
            };
            state.telemetry.start_request(&RequestInfo {
                method: req.method().as_str(),
                path: req.uri().path(),
                scheme: if peer.tls { "https" } else { "http" },
                version,
                client_ip: peer.client_ip,
                peer_ip: peer.socket_addr.ip(),
                user_agent: text(header::USER_AGENT),
                host: text(header::HOST),
                request_id,
                headers,
            })
        });
        let upload = matches!(*req.method(), Method::PUT | Method::POST);
        let declared_bytes = upload
            .then(|| text(header::CONTENT_LENGTH).and_then(|v| v.parse().ok()))
            .flatten();
        let log = (cfg.log_json || cfg.verbose).then(|| LogMeta {
            method: req.method().as_str().to_owned(),
            target: req.uri().path().to_owned(),
            request_id: request_id.to_owned(),
        });
        Self {
            _guard: state.metrics.request_guard(),
            state: Arc::clone(state),
            span,
            log,
            client_ip: peer.client_ip,
            peer_ip: peer.socket_addr.ip(),
            upload,
            declared_bytes,
            status: 0,
            response_bytes: 0,
            ended: false,
        }
    }
}

impl Drop for RequestScope {
    fn drop(&mut self) {
        // Status stays 0 only if `finalize` never ran; the span then releases itself.
        if self.status == 0 {
            return;
        }
        let accepted = self.upload && (200..300).contains(&self.status);
        let outcome = Outcome {
            status: self.status,
            response_bytes: self.response_bytes,
            request_bytes: if accepted { self.declared_bytes } else { None },
            complete: self.ended,
        };
        let ids = match (&self.span, &self.log) {
            (Some(span), Some(_)) => span.trace_ids(),
            _ => None,
        };
        if let Some(span) = self.span.take() {
            span.finish(outcome);
        }
        if let Some(meta) = &self.log {
            logging::log_request(
                &self.state.config,
                &RequestLog {
                    request_id: &meta.request_id,
                    client_ip: self.client_ip,
                    peer_ip: self.peer_ip,
                    method: &meta.method,
                    target: &meta.target,
                    status: self.status,
                    bytes: self.response_bytes,
                    trace_id: ids.as_ref().map(|i| i.trace_id.as_str()),
                    span_id: ids.as_ref().map(|i| i.span_id.as_str()),
                },
            );
        }
    }
}

struct Tracked {
    inner: Body,
    scope: RequestScope,
}

impl Drop for Tracked {
    fn drop(&mut self) {
        if hyper::body::Body::is_end_stream(&self.inner) {
            self.scope.ended = true;
        }
    }
}

impl hyper::body::Body for Tracked {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.scope.response_bytes += data.len() as u64;
                }
            }
            Poll::Ready(None) => self.scope.ended = true,
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn hv(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn finalize(
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

fn add_vary(h: &mut HeaderMap, token: &str) {
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

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn finish(builder: Builder, body: Body) -> Response<Body> {
    builder
        .body(body)
        .unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR))
}

fn error(status: StatusCode) -> Response<Body> {
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

fn closing(mut resp: Response<Body>) -> Response<Body> {
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    resp
}

fn no_content() -> Response<Body> {
    finish(Response::builder().status(StatusCode::NO_CONTENT), empty())
}

fn method_not_allowed() -> Response<Body> {
    let mut resp = error(StatusCode::METHOD_NOT_ALLOWED);
    resp.headers_mut().insert(
        header::ALLOW,
        HeaderValue::from_static("GET, HEAD, OPTIONS"),
    );
    resp
}

fn unauthorized() -> Response<Body> {
    finish(
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"blazeserve\"")
            .header(header::CONTENT_LENGTH, 0),
        empty(),
    )
}

fn json_response(status: StatusCode, value: &serde_json::Value) -> Response<Body> {
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

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
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
fn secret_eq(a: &str, b: &str) -> bool {
    Sha256::digest(a.as_bytes())
        .ct_eq(&Sha256::digest(b.as_bytes()))
        .into()
}

fn auth_ok(cfg: &Config, headers: &HeaderMap) -> bool {
    let Some(expected) = &cfg.auth else {
        return true;
    };
    let Some((user, password)) = basic_credentials(headers) else {
        return false;
    };
    // `&` rather than `&&`: both fields are always compared.
    secret_eq(&user, &expected.user) & secret_eq(&password, &expected.password)
}

fn health(state: &Arc<AppState>) -> Response<Body> {
    json_response(
        StatusCode::OK,
        &json!({
            "status": "ok",
            "version": VERSION,
            "uptime_seconds": state.metrics.stats().uptime_seconds,
        }),
    )
}

async fn ready(cfg: &Config) -> Response<Body> {
    if tokio::fs::read_dir(&cfg.base).await.is_ok() {
        json_response(StatusCode::OK, &json!({ "status": "ready" }))
    } else {
        json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({ "status": "not_ready", "reason": "served directory is not accessible" }),
        )
    }
}

fn metrics_response(state: &Arc<AppState>) -> Response<Body> {
    let body = state.metrics.to_prometheus();
    finish(
        Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::CACHE_CONTROL, "no-store"),
        full(body),
    )
}

fn perf(state: &Arc<AppState>) -> Response<Body> {
    let cfg = &state.config;
    let mut value = serde_json::to_value(state.metrics.stats()).unwrap_or_else(|_| json!({}));
    value["connections_active"] = json!(state.metrics.connections_active());
    value["config"] = json!({
        "chunk_size_mb": cfg.chunk_bytes / MIB,
        "send_buffer_mb": cfg.sndbuf_bytes / MIB,
        "backlog": cfg.backlog,
        "timeout_seconds": cfg.timeout_secs,
        "max_connections": cfg.max_connections,
        "rate_limit_mbps": cfg.rate_mbps,
    });
    json_response(StatusCode::OK, &value)
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == key).then(|| percent_decode_str(v).decode_utf8_lossy().into_owned())
    })
}

fn speed(
    state: &Arc<AppState>,
    peer: &PeerInfo,
    query: Option<&str>,
    head: bool,
) -> Response<Body> {
    let total = match query_param(query, "bytes") {
        None => SPEED_DEFAULT_BYTES,
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) if n <= MAX_SPEED_BYTES => n,
            _ => return error(StatusCode::BAD_REQUEST),
        },
    };
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, total)
        .header(header::CACHE_CONTROL, "no-store");
    if head || total == 0 {
        return finish(builder, empty());
    }
    let pump = Pump {
        state: Arc::clone(state),
        file: None,
        segments: VecDeque::from([Segment::Zeros(total)]),
        cursor: None,
        frame: state.config.chunk_bytes,
        zeros: Bytes::from(vec![0u8; ZERO_FRAME.min(state.config.chunk_bytes.max(1))]),
        limiter: limiter_for(state, peer),
        failed: false,
    };
    finish(builder, pump.into_body())
}

fn limiter_for(state: &Arc<AppState>, peer: &PeerInfo) -> Option<Arc<TokenBucket>> {
    state
        .config
        .rate_bps()
        .map(|bps| state.limiters.get(peer.client_ip, Some(bps)))
}

enum PathError {
    Bad,
    Traversal,
    NotFound,
}

/// Decode exactly once, then split: a `%2F` or `%2e%2e` must never be decoded a
/// second time or smuggled past the component checks.
fn decode_components(raw: &str) -> Result<Vec<String>, PathError> {
    let decoded =
        String::from_utf8(percent_decode_str(raw).collect()).map_err(|_| PathError::Bad)?;
    if decoded.contains('\0') || decoded.contains('\\') {
        return Err(PathError::Bad);
    }
    let mut out = Vec::new();
    for part in decoded.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(PathError::Traversal),
            p => {
                if cfg!(windows) {
                    windows_component_ok(p)?;
                }
                out.push(p.to_owned());
            }
        }
    }
    Ok(out)
}

fn windows_component_ok(part: &str) -> Result<(), PathError> {
    if part.contains([':', '<', '>', '"', '|', '?', '*']) {
        return Err(PathError::Bad);
    }
    let stem = part
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        Err(PathError::NotFound)
    } else {
        Ok(())
    }
}

struct Served {
    file: Arc<std::fs::File>,
    meta: Metadata,
    name: String,
    content_type: &'static str,
    encoding: Option<&'static str>,
}

enum Resolved {
    NotFound,
    Forbidden,
    Listing {
        rel: String,
        entries: Vec<ui::Entry>,
    },
    File(Box<Served>),
}

#[derive(Clone, Copy)]
struct Encodings {
    br: bool,
    gzip: bool,
}

fn accepted_encodings(headers: &HeaderMap) -> Encodings {
    let mut enc = Encodings {
        br: false,
        gzip: false,
    };
    for value in headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        for item in value.split(',') {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            let acceptable = parts.all(|p| {
                match p
                    .trim()
                    .strip_prefix("q=")
                    .or_else(|| p.trim().strip_prefix("Q="))
                {
                    Some(q) => q.trim().parse::<f32>().map(|q| q > 0.0).unwrap_or(false),
                    None => true,
                }
            });
            if !acceptable {
                continue;
            }
            match coding.as_str() {
                "br" => enc.br = true,
                "gzip" | "x-gzip" => enc.gzip = true,
                _ => {}
            }
        }
    }
    enc
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn is_safe_file(cfg: &Config, path: &Path) -> bool {
    path.is_file() && security::is_safe_path(&cfg.base, path)
}

fn resolve(cfg: &Config, components: &[String], encodings: Option<Encodings>) -> Resolved {
    let mut path = match &cfg.single {
        Some(single) => single.clone(),
        None => components.iter().fold(cfg.base.clone(), |p, c| p.join(c)),
    };
    if !security::is_safe_path(&cfg.base, &path) {
        return Resolved::Forbidden;
    }
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Resolved::Forbidden,
        Err(_) => return Resolved::NotFound,
    };

    if meta.is_dir() {
        if !cfg.listing {
            return Resolved::Forbidden;
        }
        let index = ["index.html", "index.htm"]
            .into_iter()
            .chain(cfg.index.iter().map(String::as_str))
            .map(|name| path.join(name))
            .find(|candidate| is_safe_file(cfg, candidate));
        match index {
            Some(found) => path = found,
            None => return list_dir(cfg, &path, components.join("/")),
        }
    } else if !meta.is_file() {
        return Resolved::Forbidden;
    }

    let mut served_path = path.clone();
    let mut encoding = None;
    if let Some(enc) = encodings.filter(|_| cfg.precompress) {
        for (suffix, token, wanted) in [(".br", "br", enc.br), (".gz", "gzip", enc.gzip)] {
            if !wanted {
                continue;
            }
            let candidate = with_suffix(&path, suffix);
            if is_safe_file(cfg, &candidate) {
                served_path = candidate;
                encoding = Some(token);
                break;
            }
        }
    }

    let file = match std::fs::File::open(&served_path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Resolved::NotFound,
        Err(_) => return Resolved::Forbidden,
    };
    let meta = match file.metadata() {
        Ok(m) if m.is_file() => m,
        _ => return Resolved::Forbidden,
    };
    Resolved::File(Box::new(Served {
        file: Arc::new(file),
        meta,
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        content_type: mime_guess::from_path(&path)
            .first_raw()
            .unwrap_or("application/octet-stream"),
        encoding,
    }))
}

fn list_dir(cfg: &Config, dir: &Path, rel: String) -> Resolved {
    let Ok(read) = std::fs::read_dir(dir) else {
        return Resolved::Forbidden;
    };
    let mut entries = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if upload::is_reserved_name(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let is_link = entry.file_type().map(|t| t.is_symlink()).unwrap_or(false);
        // A listed symlink must not reveal that something outside the root exists.
        if is_link && !security::is_safe_path(&cfg.base, &path) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        entries.push(ui::Entry {
            name: entry.file_name().to_string_lossy().into_owned(),
            is_dir: meta.is_dir(),
            size: meta.len(),
            modified: meta.modified().ok(),
        });
    }
    Resolved::Listing { rel, entries }
}

fn header_str(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    headers.get(name)?.to_str().ok()
}

fn wants_json(headers: &HeaderMap) -> bool {
    header_str(headers, header::ACCEPT)
        .is_some_and(|a| a.contains("application/json") && !a.contains("text/html"))
}

async fn static_response(
    state: &Arc<AppState>,
    peer: &PeerInfo,
    req: &Request<Incoming>,
    path: &str,
    head: bool,
) -> Response<Body> {
    let components = match decode_components(path) {
        Ok(c) => c,
        Err(PathError::Bad) => return error(StatusCode::BAD_REQUEST),
        Err(PathError::Traversal) => return error(StatusCode::FORBIDDEN),
        Err(PathError::NotFound) => return error(StatusCode::NOT_FOUND),
    };
    let headers = req.headers();
    let encodings = (!headers.contains_key(header::RANGE)).then(|| accepted_encodings(headers));

    let task_state = Arc::clone(state);
    let resolved =
        tokio::task::spawn_blocking(move || resolve(&task_state.config, &components, encodings))
            .await;
    match resolved {
        Ok(Resolved::File(served)) => {
            file_response(state, peer, headers, req.uri().query(), head, *served)
        }
        Ok(Resolved::Listing { rel, entries }) => listing_response(state, headers, &rel, entries),
        Ok(Resolved::Forbidden) => error(StatusCode::FORBIDDEN),
        Ok(Resolved::NotFound) => error(StatusCode::NOT_FOUND),
        Err(_) => {
            state.metrics.add_error();
            error(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

fn listing_response(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    rel: &str,
    mut entries: Vec<ui::Entry>,
) -> Response<Body> {
    let (content_type, body) = if wants_json(headers) {
        entries.sort_by_cached_key(|e| (!e.is_dir, e.name.to_lowercase()));
        let items: Vec<_> = entries
            .iter()
            .map(|e| {
                json!({
                    "name": e.name,
                    "type": if e.is_dir { "directory" } else { "file" },
                    "size": if e.is_dir { serde_json::Value::Null } else { json!(e.size) },
                    "modified": e.modified.and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()),
                })
            })
            .collect();
        let doc = json!({ "path": format!("/{rel}"), "entries": items });
        (
            "application/json",
            serde_json::to_vec_pretty(&doc).unwrap_or_default(),
        )
    } else {
        let html = ui::render_directory_index(rel, &entries, state.config.max_upload_bytes > 0);
        ("text/html; charset=utf-8", html.into_bytes())
    };
    finish(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::VARY, "Accept"),
        full(body),
    )
}

fn content_disposition(name: &str) -> String {
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .map(|c| {
            if matches!(c, '"' | '\\' | ';' | '%') {
                '_'
            } else {
                c
            }
        })
        .collect();
    format!(
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{}",
        utf8_percent_encode(name, NON_ALPHANUMERIC)
    )
}

fn file_response(
    state: &Arc<AppState>,
    peer: &PeerInfo,
    headers: &HeaderMap,
    query: Option<&str>,
    head: bool,
    served: Served,
) -> Response<Body> {
    let cfg = &state.config;
    let size = served.meta.len();
    let etag = cache::etag_for(&served.meta);
    let last_modified = cache::http_date(cache::mtime(&served.meta));
    let mtime_secs = cache::mtime_secs(&served.meta);
    let cache_control = cache::cache_control(cfg.no_cache);

    let mut base = Response::builder()
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, &etag)
        .header(header::LAST_MODIFIED, &last_modified);
    if let Some(encoding) = served.encoding {
        base = base
            .header(header::CONTENT_ENCODING, encoding)
            .header(header::VARY, "Accept-Encoding");
    }

    let inm = headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    let not_modified = if !inm.is_empty() {
        cache::if_none_match_matches(&inm, &etag)
    } else {
        header_str(headers, header::IF_MODIFIED_SINCE)
            .is_some_and(|v| cache::not_modified_since(v, mtime_secs))
    };
    if not_modified {
        return finish(base.status(StatusCode::NOT_MODIFIED), empty());
    }

    let mut spec = parse_range_header(header_str(headers, header::RANGE), size);
    if matches!(spec, RangeSpec::Ranges(_) | RangeSpec::Unsatisfiable)
        && let Some(if_range) = header_str(headers, header::IF_RANGE)
        && !cache::if_range_ok(if_range, &etag, mtime_secs)
    {
        spec = RangeSpec::Ignore;
    }
    if let RangeSpec::Ranges(ranges) = &spec {
        let total: u64 = ranges.iter().map(|(s, e)| e - s + 1).sum();
        if ranges.len() > MAX_RANGES || total > size {
            spec = RangeSpec::Ignore;
        }
    }

    let download = query_param(query, "download").is_some_and(|v| v == "1" || v == "true");
    if download {
        base = base.header(
            header::CONTENT_DISPOSITION,
            content_disposition(&served.name),
        );
    }

    let limiter = limiter_for(state, peer);
    let make_body = |segments: Vec<Segment>| {
        Pump {
            state: Arc::clone(state),
            file: Some(Arc::clone(&served.file)),
            segments: segments.into(),
            cursor: None,
            frame: cfg.chunk_bytes,
            zeros: Bytes::new(),
            limiter: limiter.clone(),
            failed: false,
        }
        .into_body()
    };

    match spec {
        RangeSpec::Unsatisfiable => finish(
            base.status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                .header(header::CONTENT_LENGTH, 0),
            empty(),
        ),
        RangeSpec::Ignore => {
            let builder = base
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, served.content_type)
                .header(header::CONTENT_LENGTH, size);
            let body = if head || size == 0 {
                empty()
            } else {
                make_body(vec![Segment::File {
                    offset: 0,
                    len: size,
                }])
            };
            finish(builder, body)
        }
        RangeSpec::Ranges(ranges) if ranges.len() == 1 => {
            let (start, end) = ranges[0];
            let len = end - start + 1;
            let builder = base
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, served.content_type)
                .header(header::CONTENT_LENGTH, len)
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
            let body = if head {
                empty()
            } else {
                make_body(vec![Segment::File { offset: start, len }])
            };
            finish(builder, body)
        }
        RangeSpec::Ranges(ranges) => {
            let boundary = format!("RANGE_{}", &etag[1..17]);
            let mut segments = Vec::with_capacity(ranges.len() * 3 + 1);
            let mut total = 0u64;
            for (start, end) in &ranges {
                let part_head = format!(
                    "--{boundary}\r\nContent-Type: {}\r\nContent-Range: bytes {start}-{end}/{size}\r\n\r\n",
                    served.content_type
                );
                let len = end - start + 1;
                total += part_head.len() as u64 + len + 2;
                segments.push(Segment::Bytes(Bytes::from(part_head)));
                segments.push(Segment::File {
                    offset: *start,
                    len,
                });
                segments.push(Segment::Bytes(Bytes::from_static(b"\r\n")));
            }
            let closing = format!("--{boundary}--\r\n");
            total += closing.len() as u64;
            segments.push(Segment::Bytes(Bytes::from(closing)));
            let builder = base
                .status(StatusCode::PARTIAL_CONTENT)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/byteranges; boundary={boundary}"),
                )
                .header(header::CONTENT_LENGTH, total);
            let body = if head { empty() } else { make_body(segments) };
            finish(builder, body)
        }
    }
}

enum Segment {
    Bytes(Bytes),
    File { offset: u64, len: u64 },
    Zeros(u64),
}

enum Cursor {
    File { offset: u64, remaining: u64 },
    Zeros { remaining: u64 },
}

/// Produces a response body one bounded frame at a time. Memory per transfer is one
/// frame, independent of file size; nothing here holds a lock across an await.
struct Pump {
    state: Arc<AppState>,
    file: Option<Arc<std::fs::File>>,
    segments: VecDeque<Segment>,
    cursor: Option<Cursor>,
    frame: usize,
    zeros: Bytes,
    limiter: Option<Arc<TokenBucket>>,
    failed: bool,
}

#[cfg(unix)]
fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

#[cfg(windows)]
fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

async fn read_chunk(file: &Arc<std::fs::File>, offset: u64, want: usize) -> io::Result<Bytes> {
    let file = Arc::clone(file);
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; want];
        let mut filled = 0;
        while filled < want {
            match read_at(&file, &mut buf[filled..], offset + filled as u64) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        buf.truncate(filled);
        Ok(Bytes::from(buf))
    })
    .await
    .map_err(io::Error::other)?
}

impl Pump {
    fn into_body(self) -> Body {
        let frames = stream::unfold(self, |mut pump| async move {
            let item = pump.next().await?;
            Some((item.map(Frame::data), pump))
        });
        StreamBody::new(frames).boxed()
    }

    async fn permit(&self, want: usize) -> usize {
        match &self.limiter {
            Some(limiter) => limiter.take(want).await,
            None => want,
        }
    }

    fn fail(&mut self, err: io::Error) -> Option<io::Result<Bytes>> {
        self.failed = true;
        self.state.metrics.add_error();
        Some(Err(err))
    }

    async fn next(&mut self) -> Option<io::Result<Bytes>> {
        if self.failed {
            return None;
        }
        loop {
            match self.cursor.take() {
                Some(Cursor::File { offset, remaining }) => {
                    let want = self.permit(remaining.min(self.frame as u64) as usize).await;
                    let file = self.file.clone()?;
                    return match read_chunk(&file, offset, want).await {
                        Ok(chunk) if chunk.is_empty() => self.fail(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "file shrank during transfer",
                        )),
                        Ok(chunk) => {
                            let n = chunk.len() as u64;
                            if remaining > n {
                                self.cursor = Some(Cursor::File {
                                    offset: offset + n,
                                    remaining: remaining - n,
                                });
                            }
                            self.state.metrics.add_bytes_sent(n);
                            Some(Ok(chunk))
                        }
                        Err(e) => self.fail(e),
                    };
                }
                Some(Cursor::Zeros { remaining }) => {
                    let want = self
                        .permit(remaining.min(self.zeros.len() as u64) as usize)
                        .await;
                    if remaining > want as u64 {
                        self.cursor = Some(Cursor::Zeros {
                            remaining: remaining - want as u64,
                        });
                    }
                    self.state.metrics.add_bytes_sent(want as u64);
                    return Some(Ok(self.zeros.slice(..want)));
                }
                None => match self.segments.pop_front()? {
                    Segment::Bytes(bytes) => {
                        self.state.metrics.add_bytes_sent(bytes.len() as u64);
                        return Some(Ok(bytes));
                    }
                    Segment::File { offset, len } if len > 0 => {
                        self.cursor = Some(Cursor::File {
                            offset,
                            remaining: len,
                        });
                    }
                    Segment::Zeros(len) if len > 0 => {
                        self.cursor = Some(Cursor::Zeros { remaining: len });
                    }
                    Segment::File { .. } | Segment::Zeros(_) => {}
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comps(raw: &str) -> Result<Vec<String>, PathError> {
        decode_components(raw)
    }

    #[test]
    fn path_is_decoded_once_and_traversal_rejected() {
        assert_eq!(comps("/a/b.txt").ok().unwrap(), ["a", "b.txt"]);
        assert_eq!(comps("//a/./b").ok().unwrap(), ["a", "b"]);
        assert!(matches!(comps("/a/../b"), Err(PathError::Traversal)));
        assert!(matches!(comps("/%2e%2e/secret"), Err(PathError::Traversal)));
        assert!(matches!(comps("/a%2F..%2Fb"), Err(PathError::Traversal)));
        assert_eq!(comps("/%252e%252e/x").ok().unwrap(), ["%2e%2e", "x"]);
        assert!(matches!(comps("/a%00b"), Err(PathError::Bad)));
        assert!(matches!(comps("/a%5Cb"), Err(PathError::Bad)));
        assert!(matches!(comps("/%ff"), Err(PathError::Bad)));
    }

    #[test]
    fn accept_encoding_honours_q_zero() {
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip;q=0, br"),
        );
        let e = accepted_encodings(&h);
        assert!(e.br && !e.gzip);
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("deflate, GZIP;q=0.5"),
        );
        let e = accepted_encodings(&h);
        assert!(e.gzip && !e.br);
    }

    #[test]
    fn content_disposition_sanitises_names() {
        let v = content_disposition("a\"b;c\r\n.txt");
        assert!(!v.contains('\r') && !v.contains('\n'));
        assert!(v.starts_with("attachment; filename=\"a_b_c__.txt\""));
        assert!(HeaderValue::from_str(&v).is_ok());
    }

    #[test]
    fn query_param_decodes_values() {
        assert_eq!(
            query_param(Some("a=1&bytes=42"), "bytes").as_deref(),
            Some("42")
        );
        assert_eq!(
            query_param(Some("download"), "download").as_deref(),
            Some("")
        );
        assert_eq!(query_param(None, "x"), None);
    }

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
