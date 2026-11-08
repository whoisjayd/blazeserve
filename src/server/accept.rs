//! Accept loop with admission control, 503 rejection and graceful drain.

use super::bind::tune_stream;
use super::connection::{ConnCtx, serve_connection};
use super::stopped;
use crate::AppState;
use hyper::server::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const REJECT_SLOTS: usize = 256;
const MAX_H2_STREAMS: u32 = 64;
const REJECT_IO_BUDGET: Duration = Duration::from_millis(250);
const SERVICE_UNAVAILABLE: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

pub(super) async fn accept_loop(
    listener: TcpListener,
    state: Arc<AppState>,
    tls: Option<TlsAcceptor>,
    mut stop: watch::Receiver<bool>,
) {
    let admission = Arc::new(Semaphore::new(state.config.max_connections));
    let reject_slots = Arc::new(Semaphore::new(REJECT_SLOTS));
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(state.config.header_timeout_secs))
        .keep_alive(true)
        .pipeline_flush(true)
        .max_buf_size(64 * 1024)
        .max_headers(64);
    let h2 = state.config.http2.then(h2_builder);
    let mut conns: JoinSet<()> = JoinSet::new();

    loop {
        let accepted = tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            r = listener.accept() => r,
        };
        while let Some(done) = conns.try_join_next() {
            if done.is_err_and(|e| e.is_panic()) {
                state.metrics.add_error();
            }
        }
        let (stream, peer) = match accepted {
            Ok(v) => v,
            Err(e) => {
                if !matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::Interrupted
                ) {
                    // Descriptor exhaustion and similar: back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                continue;
            }
        };
        let Ok(permit) = admission.clone().try_acquire_owned() else {
            state.metrics.add_connection_rejected();
            state.telemetry.connection_rejected();
            reject(stream, tls.is_none(), &reject_slots);
            continue;
        };
        tune_stream(&stream, &state.config);
        let ctx = ConnCtx {
            state: state.clone(),
            tls: tls.clone(),
            h1: builder.clone(),
            h2: h2.clone(),
            stop: stop.clone(),
            peer,
        };
        let owner = state.clone();
        conns.spawn(async move {
            let _permit = permit;
            let _gauge = owner.metrics.connection_guard();
            serve_connection(stream, ctx).await;
        });
    }

    drop(listener);
    let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        conns.abort_all();
        while conns.join_next().await.is_some() {}
    }
}

/// Limits that bound per-connection memory and work. No keep-alive pings are sent because
/// pings would count as progress and defeat the idle timeout.
fn h2_builder() -> http2::Builder<TokioExecutor> {
    let mut b = http2::Builder::new(TokioExecutor::new());
    b.timer(TokioTimer::new())
        .max_concurrent_streams(MAX_H2_STREAMS)
        // Rapid-reset (CVE-2023-44487): cap streams reset before accept and error resets we send.
        .max_pending_accept_reset_streams(32)
        .max_local_error_reset_streams(64)
        .initial_stream_window_size(1024 * 1024)
        .initial_connection_window_size(4 * 1024 * 1024)
        .max_frame_size(64 * 1024)
        .max_send_buf_size(256 * 1024)
        .max_header_list_size(64 * 1024);
    b
}

/// Best-effort 503. Draining briefly before close avoids a reset discarding the response.
fn reject(mut stream: TcpStream, plaintext: bool, slots: &Arc<Semaphore>) {
    if !plaintext {
        return;
    }
    let Ok(slot) = slots.clone().try_acquire_owned() else {
        return;
    };
    tokio::spawn(async move {
        let _slot = slot;
        let _ = tokio::time::timeout(REJECT_IO_BUDGET, async {
            let _ = stream.write_all(SERVICE_UNAVAILABLE).await;
            let _ = stream.shutdown().await;
            let mut sink = [0u8; 4096];
            while matches!(tokio::io::AsyncReadExt::read(&mut stream, &mut sink).await, Ok(n) if n > 0) {}
        })
        .await;
    });
}
