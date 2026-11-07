use std::convert::Infallible;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde_json::json;

use self::auth::{auth_ok, unauthorized};
use self::files::static_response;
use self::ops::{health, metrics_response, perf, ready, speed};
use self::response::{closing, finalize, json_response, method_not_allowed, no_content};
use self::scope::RequestScope;
use crate::{AppState, Body, PeerInfo, VERSION, security, upload, zip_stream};

mod auth;
mod files;
mod hash;
mod ops;
mod pump;
mod resolve;
mod response;
mod scope;

pub use hash::HashCache;

const UPLOAD_PREFIX: &str = "/__upload__/";

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
