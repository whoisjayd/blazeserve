//! Streaming a request body into a staging file, with the guards that clean it up.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWriteExt, BufWriter};

use super::response::{io_status, reject};
use super::target::{Target, is_part_staging_name};
use crate::metrics::Metrics;
use crate::security;
use crate::{AppState, Body};

const MAX_SWEPT_DIRS: usize = 4096;
const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// A part file written to more recently than this may belong to a live upload that
/// `active` cannot see: another server on the same root, or the same folder reached by a
/// different spelling (letter case, a link).
const ORPHAN_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Upload bookkeeping owned by one server.
#[derive(Debug, Default)]
pub struct UploadState {
    active: Mutex<HashSet<PathBuf>>,
    swept: Mutex<HashMap<PathBuf, Instant>>,
    /// Serializes check-then-publish so two in-process writers cannot interleave.
    pub(super) commit: Mutex<()>,
}

pub(super) struct ActiveGuard {
    state: Arc<AppState>,
    path: PathBuf,
}

impl ActiveGuard {
    pub(super) fn acquire(state: &Arc<AppState>, path: &Path) -> Option<Self> {
        let mut set = state
            .uploads
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set.insert(path.to_path_buf()).then(|| Self {
            state: state.clone(),
            path: path.to_path_buf(),
        })
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.state
            .uploads
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.path);
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
    tokio::task::spawn_blocking(move || {
        let file = security::create_upload_file(&base, &path)?;
        crate::testknobs::crash_point("upload-after-create");
        Ok(file)
    })
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

/// Remove `Staging::Part` files that a crash left in `t.dir()`, once they are older than
/// `ORPHAN_AGE`. Scans a directory at most once per `SWEEP_INTERVAL` and skips paths
/// active in this server, symlinks, directories and `Staging::Resume` files.
pub(super) async fn sweep_orphaned_parts(state: &Arc<AppState>, t: &Target) {
    let dir = t.dir().to_path_buf();
    {
        let swept = state
            .uploads
            .swept
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if swept
            .get(&dir)
            .is_some_and(|at| at.elapsed() < SWEEP_INTERVAL)
        {
            return;
        }
    }
    let state_in = state.clone();
    let base = t.base.clone();
    let dir_in = dir.clone();
    let existed = tokio::task::spawn_blocking(move || sweep_dir(&state_in, &base, &dir_in))
        .await
        .unwrap_or(false);
    if existed {
        let mut swept = state
            .uploads
            .swept
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if swept.len() >= MAX_SWEPT_DIRS {
            swept.clear();
        }
        swept.insert(dir, Instant::now());
    }
}

fn sweep_dir(state: &AppState, base: &Path, dir: &Path) -> bool {
    if !security::is_safe_path(base, dir) {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if !ft.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if is_part_staging_name(name) && is_abandoned(&entry.path()) {
            candidates.push(entry.path());
        }
    }
    if candidates.is_empty() {
        return true;
    }
    let to_remove: Vec<PathBuf> = {
        let active = state
            .uploads
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        candidates
            .into_iter()
            .filter(|p| !active.contains(p))
            .collect()
    };
    for path in to_remove {
        if security::is_safe_path(base, &path) {
            let _ = std::fs::remove_file(&path);
        }
    }
    true
}

/// Asks the file itself: Windows updates the times in a directory listing lazily.
fn is_abandoned(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|at| SystemTime::now().duration_since(at).ok())
        .is_some_and(|age| age >= ORPHAN_AGE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn age(path: &Path) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - ORPHAN_AGE * 2)
            .unwrap();
    }

    #[test]
    fn sweep_drops_only_old_inactive_part_files() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().canonicalize().unwrap();
        let part_orphan = base.join(".a.bin.blaze-part-000000000001");
        let part_long = base.join(".blaze-part-000000000002");
        let part_active = base.join(".b.bin.blaze-part-000000000003");
        let resume_short = base.join(".a.bin.blaze-resume");
        let resume_long = base.join(".blaze-resume-0123456789abcdef");
        let finished = base.join("a.bin");
        let hidden = base.join(".env");
        let part_dir = base.join(".dir.blaze-part-000000000004");
        let part_fresh = base.join(".c.bin.blaze-part-000000000005");

        for f in [
            &part_orphan,
            &part_long,
            &part_active,
            &resume_short,
            &resume_long,
            &finished,
            &hidden,
        ] {
            std::fs::write(f, b"data").unwrap();
            age(f);
        }
        std::fs::write(&part_fresh, b"data").unwrap();
        std::fs::create_dir(&part_dir).unwrap();

        let state = AppState::new(Config {
            base: base.clone(),
            ..Config::default()
        });
        let _guard = ActiveGuard::acquire(&state, &part_active).unwrap();

        assert!(sweep_dir(&state, &base, &base));
        assert!(!part_orphan.exists());
        assert!(!part_long.exists());
        assert!(part_active.exists());
        assert!(part_fresh.exists());
        assert!(resume_short.exists());
        assert!(resume_long.exists());
        assert!(finished.exists());
        assert!(hidden.exists());
        assert!(part_dir.is_dir());
    }
}
