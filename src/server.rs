//! Sockets, TLS, admission control, proxy identity, graceful shutdown.

use crate::config::{Config, TlsConfig, TrustedProxy, normalize};
use crate::telemetry::{FLUSH_TIMEOUT, Telemetry};
use crate::{AppState, PeerInfo, handler};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request};
use hyper_util::rt::{TokioIo, TokioTimer};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::{self, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{self, ServerConfig};

type BoxError = Box<dyn Error + Send + Sync>;

const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const REJECT_SLOTS: usize = 256;
const REJECT_IO_BUDGET: Duration = Duration::from_millis(250);
const RECV_BUFFER: usize = 4 * 1024 * 1024;
const MAX_FORWARDED_HEADER: usize = 2048;
const SERVICE_UNAVAILABLE: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

pub struct ServerHandle {
    addr: SocketAddr,
    state: Arc<AppState>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl ServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    pub async fn shutdown(mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        self.state.telemetry.shutdown(FLUSH_TIMEOUT).await;
    }

    pub async fn wait(&mut self) {
        if let Some(task) = self.task.as_mut() {
            let _ = task.await;
        }
        self.task = None;
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            // Dropping the accept task drops its JoinSet, which aborts every connection task.
            task.abort();
        }
    }
}

/// Binding is complete when this returns, so callers may connect immediately.
pub async fn start(config: Config) -> Result<ServerHandle, BoxError> {
    config.validate()?;
    let telemetry = Telemetry::init(&config)?;
    start_with(config, telemetry).await
}

/// Like [`start`], with telemetry already built (embedders and tests).
pub async fn start_with(config: Config, telemetry: Telemetry) -> Result<ServerHandle, BoxError> {
    config.validate()?;
    // Load TLS before binding so a bad pair never leaves a listener behind.
    let acceptor = config.tls.as_ref().map(load_tls).transpose()?;
    let addr = resolve_bind_addr(&config.host, config.port).await?;
    let listener = bind_listener(addr, &config)
        .map_err(|e| BoxError::from(format!("cannot bind {addr}: {e}")))?;
    let local = listener.local_addr()?;
    let state = AppState::with_telemetry(config, telemetry);
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(accept_loop(listener, state.clone(), acceptor, rx));
    Ok(ServerHandle {
        addr: local,
        state,
        stop,
        task: Some(task),
    })
}

pub fn run(config: Config, on_bound: impl FnOnce(&ServerHandle)) -> Result<(), BoxError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut handle = start(config).await?;
        let callback = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| on_bound(&handle)));
        if let Err(panic) = callback {
            handle.shutdown().await;
            std::panic::resume_unwind(panic);
        }
        tokio::select! {
            () = shutdown_signal() => {}
            () = handle.wait() => {}
        }
        handle.shutdown().await;
        Ok::<(), BoxError>(())
    });
    // Blocking-pool threads (file I/O) must not delay process exit.
    rt.shutdown_timeout(Duration::from_secs(1));
    result
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            () = async {
                match term.as_mut() {
                    Some(t) => { t.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn load_tls(tls: &TlsConfig) -> Result<TlsAcceptor, BoxError> {
    let open = |what: &str, path: &std::path::Path| {
        File::open(path)
            .map(BufReader::new)
            .map_err(|e| BoxError::from(format!("cannot open TLS {what} {}: {e}", path.display())))
    };
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut open("certificate", &tls.cert)?)
            .collect::<Result<_, _>>()
            .map_err(|e| {
                BoxError::from(format!(
                    "invalid TLS certificate {}: {e}",
                    tls.cert.display()
                ))
            })?;
    if certs.is_empty() {
        return Err(format!("no certificate found in {}", tls.cert.display()).into());
    }
    let key = rustls_pemfile::private_key(&mut open("key", &tls.key)?)
        .map_err(|e| BoxError::from(format!("invalid TLS key {}: {e}", tls.key.display())))?
        .ok_or_else(|| BoxError::from(format!("no private key found in {}", tls.key.display())))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| BoxError::from(format!("TLS protocol setup failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            BoxError::from(format!(
                "TLS certificate {} does not match key {}: {e}",
                tls.cert.display(),
                tls.key.display()
            ))
        })?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Prefer IPv4 when a name resolves to both families; IPv6-only hosts still work.
async fn resolve_bind_addr(host: &str, port: u16) -> Result<SocketAddr, BoxError> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    match tokio::net::lookup_host((bare, port)).await {
        Ok(found) => {
            let all: Vec<SocketAddr> = found.collect();
            all.iter()
                .find(|a| a.is_ipv4())
                .or(all.first())
                .copied()
                .ok_or_else(|| BoxError::from(format!("host {host:?} resolved to no addresses")))
        }
        Err(_) if bare.eq_ignore_ascii_case("localhost") => {
            Ok(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))
        }
        Err(e) => Err(format!("cannot resolve host {host:?}: {e}").into()),
    }
}

fn bind_listener(addr: SocketAddr, config: &Config) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // On Windows SO_REUSEADDR lets another process bind the same port and steal traffic.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        let _ = socket.set_only_v6(false);
    }
    let _ = socket.set_send_buffer_size(config.sndbuf_bytes);
    let _ = socket.set_recv_buffer_size(RECV_BUFFER);
    let _ = socket.set_keepalive(true);
    let _ = socket.set_tcp_nodelay(true);
    socket.bind(&addr.into())?;
    socket.listen(i32::try_from(config.backlog).unwrap_or(i32::MAX))?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

fn tune_stream(stream: &TcpStream, config: &Config) {
    let _ = stream.set_nodelay(true);
    let sock = SockRef::from(stream);
    let _ = sock.set_keepalive(true);
    let _ = sock.set_send_buffer_size(config.sndbuf_bytes);
}

async fn accept_loop(
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
            builder: builder.clone(),
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

struct ConnCtx {
    state: Arc<AppState>,
    tls: Option<TlsAcceptor>,
    builder: http1::Builder,
    stop: watch::Receiver<bool>,
    peer: SocketAddr,
}

async fn serve_connection(stream: TcpStream, ctx: ConnCtx) {
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

/// Resolves once shutdown is requested; the watch guard must not live across awaits.
async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await;
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

/// Closes a connection that makes no read or write progress for `timeout`. Progress in
/// either direction counts, so a slow-but-moving large transfer survives while a stalled
/// reader, stalled uploader or idle keep-alive connection does not.
struct IdleIo<T> {
    inner: T,
    timeout: Duration,
    last_progress: StdInstant,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<T> IdleIo<T> {
    fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            last_progress: StdInstant::now(),
            sleep: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    fn progressed(&mut self) {
        self.last_progress = StdInstant::now();
    }

    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        let target = tokio::time::Instant::from_std(self.last_progress + self.timeout);
        if self.sleep.deadline() != target {
            self.sleep.as_mut().reset(target);
        }
        self.sleep.as_mut().poll(cx).is_ready()
    }

    fn settle<R>(
        &mut self,
        polled: Poll<io::Result<R>>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<R>> {
        match polled {
            Poll::Ready(r) => {
                self.progressed();
                Poll::Ready(r)
            }
            Poll::Pending if self.expired(cx) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection idle timeout",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        this.settle(polled, cx)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, data);
        this.settle(polled, cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.settle(polled, cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_flush(cx);
        this.settle(polled, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.settle(polled, cx)
    }
}

fn client_ip_for(config: &Config, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let peer = normalize(peer);
    if config.trusted_proxies.is_empty() || !is_trusted(&config.trusted_proxies, peer) {
        return peer;
    }
    let joined = |name: &str| -> Result<Option<String>, ()> {
        let mut parts = Vec::new();
        for v in headers.get_all(name) {
            parts.push(v.to_str().map_err(|_| ())?);
        }
        Ok((!parts.is_empty()).then(|| parts.join(", ")))
    };
    match (joined("forwarded"), joined("x-forwarded-for")) {
        (Ok(fwd), Ok(xff)) => resolve_client_ip(config, peer, xff.as_deref(), fwd.as_deref()),
        _ => peer,
    }
}

fn is_trusted(proxies: &[TrustedProxy], ip: IpAddr) -> bool {
    proxies.iter().any(|p| p.contains(ip))
}

/// A trusted peer's `Forwarded` header wins over `X-Forwarded-For`. The chain is walked
/// right to left, skipping trusted hops; the first untrusted address is the client. Any
/// malformed, overlong or excessive chain falls back to the socket peer.
pub fn resolve_client_ip(
    config: &Config,
    peer: IpAddr,
    forwarded_for: Option<&str>,
    forwarded: Option<&str>,
) -> IpAddr {
    let peer = normalize(peer);
    if config.trusted_proxies.is_empty() || !is_trusted(&config.trusted_proxies, peer) {
        return peer;
    }
    let chain = match forwarded.map(parse_forwarded) {
        Some(Err(())) => return peer,
        Some(Ok(Some(chain))) => chain,
        Some(Ok(None)) | None => match forwarded_for.map(parse_x_forwarded_for) {
            Some(Ok(chain)) => chain,
            _ => return peer,
        },
    };
    if chain.is_empty() || chain.len() > config.max_proxy_hops.saturating_add(1) {
        return peer;
    }
    let mut skipped = 0usize;
    for ip in chain.into_iter().rev() {
        if !is_trusted(&config.trusted_proxies, ip) {
            return ip;
        }
        skipped += 1;
        if skipped > config.max_proxy_hops {
            return peer;
        }
    }
    peer
}

fn parse_x_forwarded_for(value: &str) -> Result<Vec<IpAddr>, ()> {
    if value.len() > MAX_FORWARDED_HEADER {
        return Err(());
    }
    value.split(',').map(parse_node).collect()
}

/// `Ok(None)` means no element carries `for=`; a mix of present and absent is malformed
/// because positions in the chain would no longer line up with proxies.
fn parse_forwarded(value: &str) -> Result<Option<Vec<IpAddr>>, ()> {
    if value.len() > MAX_FORWARDED_HEADER {
        return Err(());
    }
    let mut chain = Vec::new();
    let mut elements = 0usize;
    for element in value.split(',') {
        elements += 1;
        let mut found = None;
        for pair in element.split(';') {
            let Some((key, val)) = pair.split_once('=') else {
                return Err(());
            };
            if key.trim().eq_ignore_ascii_case("for") {
                if found.is_some() {
                    return Err(());
                }
                found = Some(parse_node(val)?);
            }
        }
        if let Some(ip) = found {
            chain.push(ip);
        }
    }
    match chain.len() {
        0 => Ok(None),
        n if n == elements => Ok(Some(chain)),
        _ => Err(()),
    }
}

/// Zone ids, `unknown` and obfuscated identifiers are rejected.
fn parse_node(raw: &str) -> Result<IpAddr, ()> {
    let s = raw.trim().trim_matches('"');
    if s.is_empty() || s.contains('%') {
        return Err(());
    }
    let port_ok = |p: &str| {
        !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| n <= 65535)
    };
    let ip = if let Some(rest) = s.strip_prefix('[') {
        let (inner, tail) = rest.split_once(']').ok_or(())?;
        if !tail.is_empty() && !tail.strip_prefix(':').is_some_and(port_ok) {
            return Err(());
        }
        inner.parse::<std::net::Ipv6Addr>().map_err(|_| ())?.into()
    } else if s.matches(':').count() == 1 {
        let (host, port) = s.split_once(':').ok_or(())?;
        if !port_ok(port) {
            return Err(());
        }
        host.parse::<Ipv4Addr>().map_err(|_| ())?.into()
    } else {
        s.parse::<IpAddr>().map_err(|_| ())?
    };
    Ok(normalize(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(proxies: &[&str]) -> Config {
        Config {
            trusted_proxies: proxies
                .iter()
                .map(|p| TrustedProxy::parse(p).unwrap())
                .collect(),
            ..Config::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn untrusted_peer_cannot_choose_identity() {
        let c = cfg(&["10.0.0.1"]);
        assert_eq!(
            resolve_client_ip(&c, ip("203.0.113.9"), Some("1.1.1.1"), Some("for=2.2.2.2")),
            ip("203.0.113.9")
        );
        assert_eq!(
            resolve_client_ip(&Config::default(), ip("10.0.0.1"), Some("1.1.1.1"), None),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn trusted_peer_resolves_chain_right_to_left() {
        let c = cfg(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(&c, ip("10.0.0.1"), Some("198.51.100.7, 10.0.0.2"), None),
            ip("198.51.100.7")
        );
        assert_eq!(
            resolve_client_ip(
                &c,
                ip("10.0.0.1"),
                Some("6.6.6.6, 198.51.100.7, 10.0.0.2"),
                None
            ),
            ip("198.51.100.7")
        );
        assert_eq!(
            resolve_client_ip(&c, ip("10.0.0.1"), Some("10.0.0.3"), None),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn forwarded_header_wins_over_x_forwarded_for() {
        let c = cfg(&["10.0.0.1"]);
        let got = resolve_client_ip(
            &c,
            ip("10.0.0.1"),
            Some("9.9.9.9"),
            Some("for=198.51.100.1;proto=https"),
        );
        assert_eq!(got, ip("198.51.100.1"));
        let v6 = resolve_client_ip(&c, ip("10.0.0.1"), None, Some("for=\"[2001:db8::1]:4711\""));
        assert_eq!(v6, ip("2001:db8::1"));
    }

    #[test]
    fn mapped_ipv6_is_normalized() {
        let c = cfg(&["10.0.0.1"]);
        assert_eq!(
            resolve_client_ip(&c, ip("::ffff:10.0.0.1"), Some("::ffff:198.51.100.2"), None),
            ip("198.51.100.2")
        );
    }

    #[test]
    fn malformed_or_oversized_chains_fall_back_to_peer() {
        let c = cfg(&["10.0.0.1"]);
        for bad in [
            "unknown",
            "1.2.3.4, bogus",
            "fe80::1%eth0",
            "1.2.3.4:99999",
            "[::1",
            "",
            "1.2.3.4:",
        ] {
            assert_eq!(
                resolve_client_ip(&c, ip("10.0.0.1"), Some(bad), None),
                ip("10.0.0.1"),
                "{bad:?}"
            );
        }
        assert_eq!(
            resolve_client_ip(&c, ip("10.0.0.1"), None, Some("for=1.1.1.1, proto=https")),
            ip("10.0.0.1")
        );
        let long = vec!["1.1.1.1"; 400].join(",");
        assert_eq!(
            resolve_client_ip(&c, ip("10.0.0.1"), Some(&long), None),
            ip("10.0.0.1")
        );
        let mut bounded = cfg(&["10.0.0.0/8"]);
        bounded.max_proxy_hops = 2;
        assert_eq!(
            resolve_client_ip(
                &bounded,
                ip("10.0.0.1"),
                Some("1.1.1.1, 10.0.0.2, 10.0.0.3, 10.0.0.4"),
                None
            ),
            ip("10.0.0.1")
        );
    }
}
