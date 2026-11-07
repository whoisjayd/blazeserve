use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;

use crate::limiter::TokenBucket;
use crate::{AppState, Body};

pub(super) enum Segment {
    Bytes(Bytes),
    File { offset: u64, len: u64 },
    Zeros(u64),
}

pub(super) enum Cursor {
    File { offset: u64, remaining: u64 },
    Zeros { remaining: u64 },
}

/// Produces a response body one bounded frame at a time. Memory per transfer is one
/// frame, independent of file size; nothing here holds a lock across an await.
pub(super) struct Pump {
    pub(super) state: Arc<AppState>,
    pub(super) file: Option<Arc<std::fs::File>>,
    pub(super) segments: VecDeque<Segment>,
    pub(super) cursor: Option<Cursor>,
    pub(super) frame: usize,
    pub(super) zeros: Bytes,
    pub(super) limiter: Option<Arc<TokenBucket>>,
    pub(super) failed: bool,
}

#[cfg(unix)]
pub(super) fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

#[cfg(windows)]
pub(super) fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

pub(super) async fn read_chunk(
    file: &Arc<std::fs::File>,
    offset: u64,
    want: usize,
) -> io::Result<Bytes> {
    let file = Arc::clone(file);
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; want];
        let mut filled = 0;
        while filled < want {
            match read_at(&file, &mut buf[filled..], offset + filled as u64) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        buf.truncate(filled);
        Ok(Bytes::from(buf))
    })
    .await
    .map_err(io::Error::other)?
}

impl Pump {
    pub(super) fn into_body(self) -> Body {
        let frames = stream::unfold(self, |mut pump| async move {
            let item = pump.next().await?;
            Some((item.map(Frame::data), pump))
        });
        StreamBody::new(frames).boxed()
    }

    pub(super) async fn permit(&self, want: usize) -> usize {
        match &self.limiter {
            Some(limiter) => limiter.take(want).await,
            None => want,
        }
    }

    pub(super) fn fail(&mut self, err: io::Error) -> Option<io::Result<Bytes>> {
        self.failed = true;
        self.state.metrics.add_error();
        Some(Err(err))
    }

    pub(super) async fn next(&mut self) -> Option<io::Result<Bytes>> {
        if self.failed {
            return None;
        }
        loop {
            match self.cursor.take() {
                Some(Cursor::File { offset, remaining }) => {
                    let want = self.permit(remaining.min(self.frame as u64) as usize).await;
                    let file = self.file.clone()?;
                    return match read_chunk(&file, offset, want).await {
                        Ok(chunk) if chunk.is_empty() => self.fail(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "file shrank during transfer",
                        )),
                        Ok(chunk) => {
                            let n = chunk.len() as u64;
                            if remaining > n {
                                self.cursor = Some(Cursor::File {
                                    offset: offset + n,
                                    remaining: remaining - n,
                                });
                            }
                            self.state.metrics.add_bytes_sent(n);
                            Some(Ok(chunk))
                        }
                        Err(e) => self.fail(e),
                    };
                }
                Some(Cursor::Zeros { remaining }) => {
                    let want = self
                        .permit(remaining.min(self.zeros.len() as u64) as usize)
                        .await;
                    if remaining > want as u64 {
                        self.cursor = Some(Cursor::Zeros {
                            remaining: remaining - want as u64,
                        });
                    }
                    self.state.metrics.add_bytes_sent(want as u64);
                    return Some(Ok(self.zeros.slice(..want)));
                }
                None => match self.segments.pop_front()? {
                    Segment::Bytes(bytes) => {
                        self.state.metrics.add_bytes_sent(bytes.len() as u64);
                        return Some(Ok(bytes));
                    }
                    Segment::File { offset, len } if len > 0 => {
                        self.cursor = Some(Cursor::File {
                            offset,
                            remaining: len,
                        });
                    }
                    Segment::Zeros(len) if len > 0 => {
                        self.cursor = Some(Cursor::Zeros { remaining: len });
                    }
                    Segment::File { .. } | Segment::Zeros(_) => {}
                },
            }
        }
    }
}
