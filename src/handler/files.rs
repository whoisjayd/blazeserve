use std::sync::Arc;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName};
use hyper::{Request, Response, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::json;

use super::hash::hash_response;
use super::ops::{limiter_for, query_param};
use super::pump::{Pump, Segment};
use super::resolve::{PathError, Resolved, Served, accepted_encodings, decode_components, resolve};
use super::response::{empty, error, finish, full};
use crate::range::{MAX_RANGES, RangeSpec, parse_range_header};
use crate::{AppState, Body, PeerInfo, cache, ui};

pub(super) fn header_str(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    headers.get(name)?.to_str().ok()
}

pub(super) fn wants_json(headers: &HeaderMap) -> bool {
    header_str(headers, header::ACCEPT)
        .is_some_and(|a| a.contains("application/json") && !a.contains("text/html"))
}

pub(super) async fn static_response(
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

    let wants_hash = query_param(req.uri().query(), "hash").is_some();
    let display_path = format!("/{}", components.join("/"));
    let task_state = Arc::clone(state);
    let resolved =
        tokio::task::spawn_blocking(move || resolve(&task_state.config, &components, encodings))
            .await;
    match resolved {
        Ok(Resolved::File(served)) if wants_hash => {
            hash_response(state, *served, display_path).await
        }
        Ok(Resolved::Listing { .. }) if wants_hash => error(StatusCode::BAD_REQUEST),
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

pub(super) fn listing_response(
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

pub(super) fn content_disposition(name: &str) -> String {
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

pub(super) fn file_response(
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn content_disposition_sanitises_names() {
        let v = content_disposition("a\"b;c\r\n.txt");
        assert!(!v.contains('\r') && !v.contains('\n'));
        assert!(v.starts_with("attachment; filename=\"a_b_c__.txt\""));
        assert!(HeaderValue::from_str(&v).is_ok());
    }
}
