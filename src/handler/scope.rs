use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Frame, Incoming, SizeHint};
use hyper::header::{self};
use hyper::{Method, Request};

use crate::logging::{self, RequestLog};
use crate::metrics::RequestGuard;
use crate::telemetry::{Outcome, RequestInfo, RequestSpan};
use crate::{AppState, Body, PeerInfo};

pub(super) struct LogMeta {
    pub(super) method: String,
    pub(super) target: String,
    pub(super) request_id: String,
}

/// Everything that must end exactly once per request: the in-flight gauge, the trace span
/// and the access-log record. It lives in the response body, so all three finish when the
/// body completes or is dropped, not merely when the headers are produced.
pub(super) struct RequestScope {
    pub(super) _guard: RequestGuard,
    pub(super) state: Arc<AppState>,
    pub(super) span: Option<RequestSpan>,
    pub(super) log: Option<LogMeta>,
    pub(super) client_ip: IpAddr,
    pub(super) peer_ip: IpAddr,
    pub(super) upload: bool,
    pub(super) declared_bytes: Option<u64>,
    pub(super) status: u16,
    pub(super) response_bytes: u64,
    pub(super) ended: bool,
}

impl RequestScope {
    pub(super) fn begin(
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

pub(super) struct Tracked {
    pub(super) inner: Body,
    pub(super) scope: RequestScope,
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
