//! Streaming ZIP of a file or directory under the served root.
//!
//! The archive is produced on a blocking thread and handed to the response through a
//! small bounded channel, so a slow client throttles the producer and memory stays
//! flat. A failure mid-archive is propagated as a body error: ending the chunked body
//! cleanly would hand the client a valid-looking but truncated archive.
//!
//! Entries are STORED with data descriptors so the archive can be written to a socket
//! without seeking back; see `writer`.

mod archive;
mod crc32;
mod writer;

use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::Frame;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use tokio::sync::{Semaphore, mpsc};

use crate::security::{self, ResolveError};
use crate::{AppState, Body};
use archive::{Item, write_archive};

const CHANNEL_FRAMES: usize = 8;
const MAX_CONCURRENT_ZIPS: usize = 32;
const FILENAME_STAR: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.');

fn slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_ZIPS)))
}

fn plain(status: StatusCode, msg: &str) -> Response<Body> {
    let body = Bytes::from(msg.to_owned());
    let mut resp = Response::new(
        Full::new(body.clone())
            .map_err(|never| match never {})
            .boxed(),
    );
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn query_path(query: Option<&str>) -> Option<String> {
    let raw = query?.split('&').find_map(|kv| kv.strip_prefix("path="))?;
    let spaced = raw.replace('+', " ");
    percent_decode_str(&spaced)
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}

fn sanitize_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '"' | ';' | ':' | '\\' | '/'))
        .collect();
    let kept = kept.trim().to_owned();
    if kept.is_empty() {
        "archive".to_owned()
    } else {
        kept
    }
}

fn content_disposition(name: &str) -> String {
    let clean = sanitize_name(name);
    let ascii: String = clean
        .chars()
        .map(|c| if c.is_ascii() { c } else { '_' })
        .collect();
    if clean.is_ascii() {
        return format!("attachment; filename=\"{ascii}.zip\"");
    }
    let full = format!("{clean}.zip");
    let encoded = utf8_percent_encode(&full, FILENAME_STAR);
    format!("attachment; filename=\"{ascii}.zip\"; filename*=UTF-8''{encoded}")
}

/// Responses close the connection because the archive length is unknown.
pub async fn handle_zip(state: &Arc<AppState>, query: Option<&str>, head: bool) -> Response<Body> {
    let Some(raw) = query_path(query).filter(|p| !p.is_empty()) else {
        return plain(StatusCode::BAD_REQUEST, "Missing path");
    };
    let Ok(base) = state.config.base.canonicalize() else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "Archive failed");
    };
    let target = match security::resolve_under(&base, &raw) {
        Ok(p) => p,
        Err(ResolveError::Invalid) => return plain(StatusCode::BAD_REQUEST, "Invalid path"),
        Err(ResolveError::Escape) => return plain(StatusCode::FORBIDDEN, "Forbidden"),
    };
    if state.config.hide.hides_path(&base, &target) {
        return plain(StatusCode::NOT_FOUND, "Not found");
    }
    if !target.exists() {
        return plain(StatusCode::NOT_FOUND, "Not found");
    }
    let name = target
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONNECTION, "close");
    if let Ok(v) = HeaderValue::from_str(&content_disposition(&name)) {
        builder = builder.header(header::CONTENT_DISPOSITION, v);
    }
    let failed = || plain(StatusCode::INTERNAL_SERVER_ERROR, "Archive failed");

    if head {
        let body = Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed();
        return builder.body(body).unwrap_or_else(|_| failed());
    }

    let Ok(permit) = slots().clone().try_acquire_owned() else {
        let mut resp = plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many archives in progress",
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    };

    let hide = state.config.hide.clone();
    let (tx, mut rx) = mpsc::channel::<Item>(CHANNEL_FRAMES);
    let err_tx = tx.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if let Err(e) = write_archive(&base, &target, &hide, tx) {
            let _ = err_tx.try_send(Err(e));
        }
    });

    let state = state.clone();
    let stream = futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx)).inspect(move |item| {
        if let Some(data) = item.as_ref().ok().and_then(Frame::data_ref) {
            state.metrics.add_bytes_sent(data.len() as u64);
        }
    });
    builder
        .body(BodyExt::boxed(StreamBody::new(stream)))
        .unwrap_or_else(|_| failed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_strips_injection_characters() {
        let d = content_disposition("a\"b;c:d\r\ne");
        assert_eq!(d, "attachment; filename=\"abcde.zip\"");
    }

    #[test]
    fn filename_falls_back_to_archive() {
        assert_eq!(
            content_disposition("\";:"),
            "attachment; filename=\"archive.zip\""
        );
        assert_eq!(
            content_disposition(""),
            "attachment; filename=\"archive.zip\""
        );
    }

    #[test]
    fn non_ascii_name_gets_encoded_extension() {
        let d = content_disposition("caf\u{e9}");
        assert!(d.contains("filename=\"caf_.zip\""));
        assert!(d.contains("filename*=UTF-8''caf%C3%A9.zip"));
    }

    #[test]
    fn query_path_decodes_once() {
        assert_eq!(query_path(Some("path=a%20b")).as_deref(), Some("a b"));
        assert_eq!(query_path(Some("x=1&path=a+b")).as_deref(), Some("a b"));
        assert_eq!(query_path(Some("path=%252e")).as_deref(), Some("%2e"));
        assert!(query_path(Some("other=1")).is_none());
        assert!(query_path(None).is_none());
    }
}
