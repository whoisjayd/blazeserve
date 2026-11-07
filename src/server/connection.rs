//! Serves one accepted connection over plaintext or TLS through hyper, as HTTP/1.1 or HTTP/2.

use super::idle::IdleIo;
use super::prefixed::sniff;
use super::proxy::client_ip_for;
use super::stopped;
use crate::{AppState, PeerInfo, handler};
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::error::Error;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

pub(super) struct ConnCtx {
    pub(super) state: Arc<AppState>,
    pub(super) tls: Option<TlsAcceptor>,
    pub(super) h1: http1::Builder,
    /// `None` when HTTP/2 is disabled.
    pub(super) h2: Option<http2::Builder<TokioExecutor>>,
    pub(super) stop: watch::Receiver<bool>,
    pub(super) peer: SocketAddr,
}

pub(super) async fn serve_connection(stream: TcpStream, ctx: ConnCtx) {
    let idle = Duration::from_secs(ctx.state.config.timeout_secs);
    let wait = Duration::from_secs(ctx.state.config.header_timeout_secs);
    let mut stop = ctx.stop.clone();
    match ctx.tls.clone() {
        Some(acceptor) => {
            let Ok(Ok(tls)) = tokio::time::timeout(wait, acceptor.accept(stream)).await else {
                return;
            };
            if ctx.h2.is_some() && tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                // The client preface is read under the handshake bound; anything else is dropped.
                if let Some((io, true)) = until_stopped(sniff(tls, wait), &mut stop).await.flatten()
                {
                    serve_io(IdleIo::new(io, idle), ctx, true, true).await;
                }
            } else {
                serve_io(IdleIo::new(tls, idle), ctx, true, false).await;
            }
        }
        None if ctx.h2.is_some() => {
            if let Some((io, h2)) = until_stopped(sniff(stream, wait), &mut stop)
                .await
                .flatten()
            {
                serve_io(IdleIo::new(io, idle), ctx, false, h2).await;
            }
        }
        None => serve_io(IdleIo::new(stream, idle), ctx, false, false).await,
    }
}

async fn serve_io<S>(io: IdleIo<S>, mut ctx: ConnCtx, tls: bool, h2: bool)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = ctx.state.clone();
    let peer = ctx.peer;
    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move {
            let client_ip = client_ip_for(&state.config, peer.ip(), req.headers());
            handler::handle(
                state,
                PeerInfo {
                    socket_addr: peer,
                    client_ip,
                    tls,
                },
                req,
            )
            .await
        }
    });
    let io = TokioIo::new(io);
    let result = match ctx.h2.as_ref().filter(|_| h2) {
        Some(builder) => {
            drive(
                builder.serve_connection(io, service),
                &mut ctx.stop,
                http2::Connection::graceful_shutdown,
            )
            .await
        }
        None => {
            drive(
                ctx.h1.serve_connection(io, service),
                &mut ctx.stop,
                http1::Connection::graceful_shutdown,
            )
            .await
        }
    };
    if let Err(e) = result
        && !is_expected(&e)
    {
        ctx.state.metrics.add_error();
    }
}

async fn drive<C>(
    conn: C,
    stop: &mut watch::Receiver<bool>,
    graceful: fn(Pin<&mut C>),
) -> hyper::Result<()>
where
    C: Future<Output = hyper::Result<()>>,
{
    let mut conn = pin!(conn);
    tokio::select! {
        r = conn.as_mut() => r,
        () = stopped(stop) => {
            graceful(conn.as_mut());
            conn.await
        }
    }
}

fn is_expected(e: &hyper::Error) -> bool {
    if e.is_parse()
        || e.is_parse_too_large()
        || e.is_timeout()
        || e.is_incomplete_message()
        || e.is_canceled()
        || e.is_closed()
    {
        return true;
    }
    let mut source = e.source();
    while let Some(s) = source {
        if let Some(io) = s.downcast_ref::<io::Error>() {
            use io::ErrorKind::*;
            return matches!(
                io.kind(),
                BrokenPipe
                    | ConnectionReset
                    | ConnectionAborted
                    | TimedOut
                    | UnexpectedEof
                    | NotConnected
                    | WriteZero
            );
        }
        source = s.source();
    }
    false
}

/// Gives up on a pre-protocol read when shutdown starts, so idle new connections drain at once.
async fn until_stopped<T>(
    fut: impl Future<Output = T>,
    stop: &mut watch::Receiver<bool>,
) -> Option<T> {
    tokio::select! {
        v = fut => Some(v),
        () = stopped(stop) => None,
    }
}
