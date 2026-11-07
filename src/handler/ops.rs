use std::collections::VecDeque;
use std::sync::Arc;

use bytes::Bytes;
use hyper::header::{self};
use hyper::{Response, StatusCode};
use percent_encoding::percent_decode_str;
use serde_json::json;

use super::pump::{Pump, Segment};
use super::response::{empty, error, finish, full, json_response};
use crate::config::Config;
use crate::limiter::TokenBucket;
use crate::{AppState, Body, PeerInfo, VERSION};

pub(super) const MAX_SPEED_BYTES: u64 = 1000 * 1024 * 1024;
pub(super) const SPEED_DEFAULT_BYTES: u64 = 100_000_000;
pub(super) const ZERO_FRAME: usize = 1024 * 1024;
pub(super) const MIB: usize = 1024 * 1024;

pub(super) fn health(state: &Arc<AppState>) -> Response<Body> {
    json_response(
        StatusCode::OK,
        &json!({
            "status": "ok",
            "version": VERSION,
            "uptime_seconds": state.metrics.stats().uptime_seconds,
        }),
    )
}

pub(super) async fn ready(cfg: &Config) -> Response<Body> {
    if tokio::fs::read_dir(&cfg.base).await.is_ok() {
        json_response(StatusCode::OK, &json!({ "status": "ready" }))
    } else {
        json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({ "status": "not_ready", "reason": "served directory is not accessible" }),
        )
    }
}

pub(super) fn metrics_response(state: &Arc<AppState>) -> Response<Body> {
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

pub(super) fn perf(state: &Arc<AppState>) -> Response<Body> {
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

pub(super) fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == key).then(|| percent_decode_str(v).decode_utf8_lossy().into_owned())
    })
}

pub(super) fn speed(
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

pub(super) fn limiter_for(state: &Arc<AppState>, peer: &PeerInfo) -> Option<Arc<TokenBucket>> {
    state
        .config
        .rate_bps()
        .map(|bps| state.limiters.get(peer.client_ip, Some(bps)))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
