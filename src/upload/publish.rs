//! Publishing a staged file into the served tree, with the preconditions that guard it.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use bytes::Bytes;
use hyper::{Response, StatusCode};

use super::response::{build, io_status, reject, text};
use super::target::Target;
use crate::security;
use crate::{AppState, Body};

/// Validator for `If-Match`; also returned as `ETag` after a publish.
pub fn etag_for_metadata(meta: &std::fs::Metadata) -> String {
    crate::cache::etag_for(meta)
}

fn b64(digest: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(digest)
}

pub(super) enum PublishError {
    Exists,
    Stale,
    NotRegular,
    Unsupported,
    Io(io::Error),
}

fn publish_create(
    commit: &Mutex<()>,
    base: &Path,
    staging: &Path,
    target: &Path,
) -> Result<(), PublishError> {
    publish_create_with(commit, base, staging, target, |s, t| {
        std::fs::hard_link(s, t)
    })
}

/// A hard link is the only no-replace publication that exposes the whole file at once.
/// Without it the upload is refused, because filling the final name would let readers
/// see partial bytes.
fn publish_create_with(
    commit: &Mutex<()>,
    base: &Path,
    staging: &Path,
    target: &Path,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<(), PublishError> {
    let _lock = commit.lock().unwrap_or_else(|e| e.into_inner());
    if !security::is_safe_path(base, target) {
        return Err(PublishError::Io(security::unsafe_io(
            "publish path escapes the root",
        )));
    }
    match link(staging, target) {
        Ok(()) => {
            crate::testknobs::crash_point("upload-after-link");
            let _ = std::fs::remove_file(staging);
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(PublishError::Exists),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(PublishError::Io(e)),
        Err(_) => Err(PublishError::Unsupported),
    }
}

fn publish_replace(
    commit: &Mutex<()>,
    base: &Path,
    staging: &Path,
    target: &Path,
    etags: &[String],
) -> Result<(), PublishError> {
    let _lock = commit.lock().unwrap_or_else(|e| e.into_inner());
    let meta = match std::fs::symlink_metadata(target) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(PublishError::Stale),
        Err(e) => return Err(PublishError::Io(e)),
    };
    if !meta.file_type().is_file() {
        return Err(PublishError::NotRegular);
    }
    if !etags.contains(&etag_for_metadata(&meta)) {
        return Err(PublishError::Stale);
    }
    if !security::is_safe_path(base, target) {
        return Err(PublishError::Io(security::unsafe_io(
            "publish path escapes the root",
        )));
    }
    crate::testknobs::crash_point("upload-before-rename");
    let rename = || std::fs::rename(staging, target);
    // Elsewhere a refusal is final, and waiting would only hold up other publishes.
    let renamed = if crate::platform::IS_WINDOWS {
        security::retry_sharing(rename)
    } else {
        rename()
    };
    renamed.map_err(PublishError::Io)
}

pub(super) async fn publish(
    state: &Arc<AppState>,
    t: &Target,
    staging: PathBuf,
    etags: Option<Vec<String>>,
) -> Result<(), PublishError> {
    let (base, target) = (t.base.clone(), t.path.clone());
    let state = state.clone();
    let joined = tokio::task::spawn_blocking(move || match etags {
        Some(tags) => publish_replace(&state.uploads.commit, &base, &staging, &target, &tags),
        None => publish_create(&state.uploads.commit, &base, &staging, &target),
    })
    .await;
    joined.unwrap_or_else(|e| Err(PublishError::Io(io::Error::other(e))))
}

pub(super) fn publish_failure(e: PublishError) -> Response<Body> {
    match e {
        PublishError::Exists => text(StatusCode::CONFLICT, "Already exists"),
        PublishError::Stale => text(
            StatusCode::PRECONDITION_FAILED,
            "If-Match precondition failed",
        ),
        PublishError::NotRegular => text(StatusCode::CONFLICT, "Target is not a regular file"),
        PublishError::Unsupported => text(
            StatusCode::NOT_IMPLEMENTED,
            "Filesystem cannot publish uploads atomically",
        ),
        PublishError::Io(e) => {
            let (status, msg) = io_status(&e);
            text(status, msg)
        }
    }
}

pub(super) fn success(t: &Target, replaced: bool, digest: &[u8; 32]) -> Response<Body> {
    let mut extra = vec![
        ("content-digest", format!("sha-256=:{}:", b64(digest))),
        ("location", t.location()),
    ];
    if let Ok(meta) = std::fs::metadata(&t.path) {
        extra.push(("etag", etag_for_metadata(&meta)));
    }
    let status = if replaced {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    build(status, &extra, Bytes::new())
}

enum Existing {
    Absent,
    Regular,
    Other,
}

async fn probe(path: &Path) -> io::Result<Existing> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(m) if m.file_type().is_file() => Ok(Existing::Regular),
        Ok(_) => Ok(Existing::Other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Existing::Absent),
        Err(e) => Err(e),
    }
}

#[allow(clippy::result_large_err)]
pub(super) async fn precheck(t: &Target, tags: &Option<Vec<String>>) -> Result<(), Response<Body>> {
    let existing = probe(&t.path).await.map_err(|e| {
        let (status, msg) = io_status(&e);
        reject(status, msg)
    })?;
    match (existing, tags) {
        (Existing::Absent, None) => Ok(()),
        (Existing::Absent, Some(_)) => Err(reject(
            StatusCode::PRECONDITION_FAILED,
            "Target does not exist",
        )),
        (Existing::Other, _) => Err(reject(StatusCode::CONFLICT, "Target is not a regular file")),
        (Existing::Regular, None) => Err(reject(StatusCode::CONFLICT, "Already exists")),
        (Existing::Regular, Some(tags)) => {
            let meta = tokio::fs::symlink_metadata(&t.path)
                .await
                .map_err(|_| reject(StatusCode::PRECONDITION_FAILED, "Target does not exist"))?;
            if tags.contains(&etag_for_metadata(&meta)) {
                Ok(())
            } else {
                Err(reject(
                    StatusCode::PRECONDITION_FAILED,
                    "If-Match precondition failed",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_changes_with_content_size() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, b"a").unwrap();
        let a = etag_for_metadata(&std::fs::metadata(&p).unwrap());
        std::fs::write(&p, b"abcdef").unwrap();
        let b = etag_for_metadata(&std::fs::metadata(&p).unwrap());
        assert_ne!(a, b);
        assert!(a.starts_with('"') && a.ends_with('"') && a.len() == 22);
    }

    #[test]
    fn publish_create_never_overwrites() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().canonicalize().unwrap();
        let target = base.join("t");
        let (s1, s2) = (base.join("s1"), base.join("s2"));
        std::fs::write(&s1, b"one").unwrap();
        std::fs::write(&s2, b"two").unwrap();
        assert!(publish_create(&Mutex::new(()), &base, &s1, &target).is_ok());
        assert!(matches!(
            publish_create(&Mutex::new(()), &base, &s2, &target),
            Err(PublishError::Exists)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"one");
    }

    #[test]
    fn publish_create_refuses_without_hard_links_and_exposes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().canonicalize().unwrap();
        let target = base.join("t");
        let staging = base.join("s");
        std::fs::write(&staging, b"staged").unwrap();
        let r = publish_create_with(&Mutex::new(()), &base, &staging, &target, |_, _| {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        });
        assert!(matches!(r, Err(PublishError::Unsupported)));
        assert!(!target.exists());
        assert_eq!(std::fs::read(&staging).unwrap(), b"staged");
    }

    #[test]
    fn publish_create_without_hard_links_keeps_existing_destination() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().canonicalize().unwrap();
        let target = base.join("t");
        let staging = base.join("s");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&staging, b"new").unwrap();
        let r = publish_create_with(&Mutex::new(()), &base, &staging, &target, |_, _| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        });
        assert!(matches!(r, Err(PublishError::Unsupported)));
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
    }

    #[test]
    fn publish_replace_requires_current_etag() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().canonicalize().unwrap();
        let target = base.join("t");
        let staging = base.join("s");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&staging, b"new").unwrap();
        assert!(matches!(
            publish_replace(
                &Mutex::new(()),
                &base,
                &staging,
                &target,
                &["\"stale\"".into()]
            ),
            Err(PublishError::Stale)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        let current = etag_for_metadata(&std::fs::metadata(&target).unwrap());
        assert!(publish_replace(&Mutex::new(()), &base, &staging, &target, &[current]).is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    /// Security software opens files without delete sharing, which refuses a rename.
    #[cfg(windows)]
    #[test]
    fn publish_replace_waits_out_a_briefly_held_destination() {
        use std::os::windows::fs::OpenOptionsExt;
        const SHARE_READ_AND_WRITE: u32 = 0x1 | 0x2;
        let d = tempfile::tempdir().unwrap();
        let base = d.path().canonicalize().unwrap();
        let target = base.join("t");
        let staging = base.join("s");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&staging, b"new").unwrap();
        let current = etag_for_metadata(&std::fs::metadata(&target).unwrap());
        let held = std::fs::File::options()
            .read(true)
            .share_mode(SHARE_READ_AND_WRITE)
            .open(&target)
            .unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            drop(held);
        });
        let published = publish_replace(&Mutex::new(()), &base, &staging, &target, &[current]);
        release.join().unwrap();
        assert!(published.is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }
}
