//! Streaming a request body into a staging file, with the guards that clean it up.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWriteExt, BufWriter};

use super::response::{io_status, reject};
use super::target::Target;
use crate::metrics::Metrics;
use crate::security;
use crate::{AppState, Body};

fn active_set() -> &'static Mutex<HashSet<PathBuf>> {
    static SET: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

pub(super) struct ActiveGuard(PathBuf);

impl ActiveGuard {
    pub(super) fn acquire(path: &Path) -> Option<Self> {
        let mut set = active_set().lock().unwrap_or_else(|e| e.into_inner());
        set.insert(path.to_path_buf())
            .then(|| Self(path.to_path_buf()))
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        active_set()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

/// Removes the staging file on drop, including when the request future is cancelled.
pub(super) struct StagingGuard {
    pub(super) path: PathBuf,
    pub(super) armed: bool,
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(super) enum StreamError {
    Timeout,
    Body,
    Io(io::Error),
}

pub(super) async fn pump(
    mut body: Incoming,
    out: &mut BufWriter<tokio::fs::File>,
    hasher: &mut Sha256,
    idle: Duration,
    expected: u64,
    metrics: &Metrics,
    accepted: &mut u64,
) -> Result<(), StreamError> {
    loop {
        let frame = match tokio::time::timeout(idle, body.frame()).await {
            Err(_) => return Err(StreamError::Timeout),
            Ok(None) => return Ok(()),
            Ok(Some(Err(_))) => return Err(StreamError::Body),
            Ok(Some(Ok(f))) => f,
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let n = data.len() as u64;
        if *accepted + n > expected {
            return Err(StreamError::Body);
        }
        out.write_all(&data).await.map_err(StreamError::Io)?;
        hasher.update(&data);
        *accepted += n;
        metrics.add_bytes_received(n);
    }
}

pub(super) fn stream_failure(e: StreamError) -> Response<Body> {
    match e {
        StreamError::Timeout => reject(StatusCode::REQUEST_TIMEOUT, "Request body timed out"),
        StreamError::Body => reject(
            StatusCode::BAD_REQUEST,
            "Request body ended before Content-Length",
        ),
        StreamError::Io(e) => {
            let (status, msg) = io_status(&e);
            reject(status, msg)
        }
    }
}

pub(super) fn buf_capacity(state: &AppState) -> usize {
    state.config.chunk_bytes.clamp(64 * 1024, 1024 * 1024)
}

pub(super) fn idle(state: &AppState) -> Duration {
    Duration::from_secs(state.config.timeout_secs.max(1))
}

pub(super) async fn create_staging(t: &Target, path: PathBuf) -> io::Result<std::fs::File> {
    let base = t.base.clone();
    tokio::task::spawn_blocking(move || security::create_upload_file(&base, &path))
        .await
        .unwrap_or_else(|e| Err(io::Error::other(e)))
}

pub(super) fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buf[..n]);
    }
}
