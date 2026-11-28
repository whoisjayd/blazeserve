use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::Request;
use hyper::body::{Frame, Incoming, SizeHint};

use crate::logging::{self, RequestLog};
use crate::metrics::RequestGuard;
use crate::{AppState, Body, PeerInfo};

pub(super) struct LogMeta {
    pub(super) method: String,
    pub(super) target: String,
    pub(super) request_id: String,
}

/// Everything that must end exactly once per request: the in-flight gauge and the
/// access-log record. It lives in the response body, so both finish when the body completes
/// or is dropped, not merely when the headers are produced.
pub(super) struct RequestScope {
    pub(super) _guard: RequestGuard,
    pub(super) state: Arc<AppState>,
    pub(super) log: Option<LogMeta>,
    pub(super) client_ip: IpAddr,
    pub(super) peer_ip: IpAddr,
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
        let log = (cfg.log_json || cfg.verbose).then(|| LogMeta {
            method: req.method().as_str().to_owned(),
            target: req.uri().path().to_owned(),
            request_id: request_id.to_owned(),
        });
        Self {
            _guard: state.metrics.request_guard(),
            state: Arc::clone(state),
            log,
            client_ip: peer.client_ip,
            peer_ip: peer.socket_addr.ip(),
            status: 0,
            response_bytes: 0,
            ended: false,
        }
    }
}

impl Drop for RequestScope {
    fn drop(&mut self) {
        // Status stays 0 only if `finalize` never ran.
        if self.status == 0 {
            return;
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
