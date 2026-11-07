//! Closes connections that make no I/O progress within the idle timeout.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Closes a connection that makes no read or write progress for `timeout`. Progress in
/// either direction counts, so a slow-but-moving large transfer survives while a stalled
/// reader, stalled uploader or idle keep-alive connection does not.
pub(super) struct IdleIo<T> {
    inner: T,
    timeout: Duration,
    last_progress: StdInstant,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<T> IdleIo<T> {
    pub(super) fn new(inner: T, timeout: Duration) -> Self {
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
