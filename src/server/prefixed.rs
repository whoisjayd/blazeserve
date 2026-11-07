//! Detects the HTTP/2 prior-knowledge preface without losing the bytes it consumed.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Replays bytes read ahead of the protocol decision before reading from `inner`.
pub(super) struct Prefixed<T> {
    head: [u8; 24],
    pos: usize,
    len: usize,
    inner: T,
}

/// Reads until the client preface is complete or the bytes stop matching it, so an
/// HTTP/1 request is decided on its first byte. `None` means no decision within `limit`.
pub(super) async fn sniff<T>(mut io: T, limit: Duration) -> Option<(Prefixed<T>, bool)>
where
    T: AsyncRead + Unpin,
{
    let mut head = [0u8; 24];
    let mut len = 0;
    let read = async {
        while len < PREFACE.len() {
            let n = io.read(&mut head[len..]).await?;
            if n == 0 {
                break;
            }
            len += n;
            if head[..len] != PREFACE[..len] {
                break;
            }
        }
        Ok::<(), io::Error>(())
    };
    tokio::time::timeout(limit, read).await.ok()?.ok()?;
    let h2 = len == PREFACE.len() && head == *PREFACE;
    Some((
        Prefixed {
            head,
            pos: 0,
            len,
            inner: io,
        },
        h2,
    ))
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.len {
            let n = (this.len - this.pos).min(buf.remaining());
            buf.put_slice(&this.head[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn feed(bytes: &'static [u8]) -> (Vec<u8>, bool) {
        let (mut client, server) = tokio::io::duplex(256);
        client.write_all(bytes).await.unwrap();
        drop(client);
        let (mut io, h2) = sniff(server, Duration::from_secs(5)).await.unwrap();
        let mut all = Vec::new();
        io.read_to_end(&mut all).await.unwrap();
        (all, h2)
    }

    #[tokio::test]
    async fn preface_selects_h2_and_is_replayed() {
        let (all, h2) = feed(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nrest").await;
        assert!(h2);
        assert_eq!(all, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nrest");
    }

    #[tokio::test]
    async fn http1_and_broken_preface_stay_http1_without_losing_bytes() {
        for raw in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\nmore",
            b"PO",
        ] {
            let (all, h2) = feed(Box::leak(raw.to_vec().into_boxed_slice())).await;
            assert!(!h2);
            assert_eq!(all, raw);
        }
    }

    #[tokio::test]
    async fn silent_peer_times_out() {
        let (_client, server) = tokio::io::duplex(8);
        assert!(sniff(server, Duration::from_millis(30)).await.is_none());
    }
}
