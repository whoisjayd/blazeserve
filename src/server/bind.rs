//! Bind address resolution, listener creation and per-connection socket tuning.

use super::BoxError;
use crate::config::Config;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};

const RECV_BUFFER: usize = 4 * 1024 * 1024;

/// Prefer IPv4 when a name resolves to both families; IPv6-only hosts still work.
pub(super) async fn resolve_bind_addr(host: &str, port: u16) -> Result<SocketAddr, BoxError> {
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

pub(super) fn bind_listener(addr: SocketAddr, config: &Config) -> io::Result<TcpListener> {
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

pub(super) fn tune_stream(stream: &TcpStream, config: &Config) {
    let _ = stream.set_nodelay(true);
    let sock = SockRef::from(stream);
    let _ = sock.set_keepalive(true);
    let _ = sock.set_send_buffer_size(config.sndbuf_bytes);
}
