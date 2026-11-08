//! Publishing a staged file into the served tree, with the preconditions that guard it.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use bytes::Bytes;
use hyper::{Response, StatusCode};

use super::response::{build, io_status, reject, text};
use super::target::Target;
use crate::Body;
use crate::security;

/// Serializes check-then-publish so two in-process writers cannot interleave.
static COMMIT_LOCK: Mutex<()> = Mutex::new(());

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
    Io(io::Error),
}

fn publish_create(base: &Path, staging: &Path, target: &Path) -> Result<(), PublishError> {
    let _lock = COMMIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !security::is_safe_path(base, target) {
        return Err(PublishError::Io(security::unsafe_io(
            "publish path escapes the root",
        )));
    }
    match std::fs::hard_link(staging, target) {
        Ok(()) => {
            let _ = std::fs::remove_file(staging);
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(PublishError::Exists),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(PublishError::Io(e)),
        // Filesystems without hard links: reserve the name exclusively, then copy.
        // Readers can observe the file while it is being filled.
        Err(_) => {
            let mut dst = match security::create_upload_file(base, target) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(PublishError::Exists);
                }
                Err(e) => return Err(PublishError::Io(e)),
            };
            let copied =
                std::fs::File::open(staging).and_then(|mut src| io::copy(&mut src, &mut dst));
            if let Err(e) = copied {
                drop(dst);
                let _ = std::fs::remove_file(target);
                return Err(PublishError::Io(e));
            }
            let _ = std::fs::remove_file(staging);
            Ok(())
        }
    }
}

fn publish_replace(
    base: &Path,
    staging: &Path,
    target: &Path,
    etags: &[String],
) -> Result<(), PublishError> {
    let _lock = COMMIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    std::fs::rename(staging, target).map_err(PublishError::Io)
}

pub(super) async fn publish(
    t: &Target,
    staging: PathBuf,
    etags: Option<Vec<String>>,
) -> Result<(), PublishError> {
    let (base, target) = (t.base.clone(), t.path.clone());
    let joined = tokio::task::spawn_blocking(move || match etags {
        Some(tags) => publish_replace(&base, &staging, &target, &tags),
        None => publish_create(&base, &staging, &target),
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
        assert!(publish_create(&base, &s1, &target).is_ok());
        assert!(matches!(
            publish_create(&base, &s2, &target),
            Err(PublishError::Exists)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"one");
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
            publish_replace(&base, &staging, &target, &["\"stale\"".into()]),
            Err(PublishError::Stale)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        let current = etag_for_metadata(&std::fs::metadata(&target).unwrap());
        assert!(publish_replace(&base, &staging, &target, &[current]).is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }
}
