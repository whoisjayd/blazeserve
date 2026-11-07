//! Serves one accepted connection over plaintext or TLS through hyper.

use super::idle::IdleIo;
use super::proxy::client_ip_for;
use super::stopped;
use crate::{AppState, PeerInfo, handler};
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

pub(super) struct ConnCtx {
    pub(super) state: Arc<AppState>,
    pub(super) tls: Option<TlsAcceptor>,
    pub(super) builder: http1::Builder,
    pub(super) stop: watch::Receiver<bool>,
    pub(super) peer: SocketAddr,
}

pub(super) async fn serve_connection(stream: TcpStream, ctx: ConnCtx) {
    let idle = Duration::from_secs(ctx.state.config.timeout_secs);
    match ctx.tls.clone() {
        Some(acceptor) => {
            let handshake = Duration::from_secs(ctx.state.config.header_timeout_secs);
            if let Ok(Ok(tls)) = tokio::time::timeout(handshake, acceptor.accept(stream)).await {
                serve_io(IdleIo::new(tls, idle), ctx, true).await;
            }
        }
        None => serve_io(IdleIo::new(stream, idle), ctx, false).await,
    }
}

async fn serve_io<S>(io: IdleIo<S>, mut ctx: ConnCtx, tls: bool)
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
    let mut conn = std::pin::pin!(ctx.builder.serve_connection(TokioIo::new(io), service));
    let result = tokio::select! {
        r = conn.as_mut() => r,
        () = stopped(&mut ctx.stop) => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    if let Err(e) = result
        && !is_expected(&e)
    {
        ctx.state.metrics.add_error();
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
