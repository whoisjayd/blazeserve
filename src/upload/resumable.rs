//! Resumable uploads: chunks appended by offset to a staged file, published when complete.

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncSeekExt, AsyncWriteExt, BufWriter};

use super::publish::{precheck, publish, publish_failure, success};
use super::request::{ContentRange, Digests};
use super::response::{build, finish_io, io_status, reject, reject_with, text};
use super::stream::{ActiveGuard, buf_capacity, hash_file, idle, pump, stream_failure};
use super::target::{Staging, Target};
use crate::security;
use crate::{AppState, Body};

pub(super) async fn resumable(
    state: &Arc<AppState>,
    req: Request<Incoming>,
    t: Target,
    len: u64,
    range: ContentRange,
    digests: Digests,
    tags: Option<Vec<String>>,
) -> Response<Body> {
    if len != range.end - range.start + 1 {
        return reject(
            StatusCode::BAD_REQUEST,
            "Content-Length does not match Content-Range",
        );
    }
    if let Some(tags) = &tags {
        if let Err(resp) = precheck(&t, &Some(tags.clone())).await {
            return resp;
        }
    } else if let Err(resp) = precheck(&t, &None).await {
        return resp;
    }
    let resume = t.staging_path(Staging::Resume);
    let Some(_active) = ActiveGuard::acquire(&resume) else {
        return reject(StatusCode::CONFLICT, "Upload in progress");
    };
    let base = t.base.clone();
    let path = resume.clone();
    let opened = tokio::task::spawn_blocking(move || match std::fs::symlink_metadata(&path) {
        Ok(_) => security::open_existing_for_append(&base, &path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            security::create_upload_file(&base, &path).map(|f| (f, 0))
        }
        Err(e) => Err(e),
    })
    .await
    .unwrap_or_else(|e| Err(io::Error::other(e)));
    let (file, staged) = match opened {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = io_status(&e);
            return reject(status, msg);
        }
    };
    if staged != range.start {
        return reject_with(
            StatusCode::CONFLICT,
            "Upload offset mismatch",
            &[("upload-offset", staged.to_string())],
        );
    }

    let mut file = tokio::fs::File::from_std(file);
    let mut out = BufWriter::with_capacity(buf_capacity(state), {
        if file.seek(io::SeekFrom::Start(staged)).await.is_err() {
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "Upload failed");
        }
        file
    });
    let mut hasher = Sha256::new();
    let mut accepted = 0u64;
    let streamed = pump(
        req.into_body(),
        &mut out,
        &mut hasher,
        idle(state),
        len,
        &state.metrics,
        &mut accepted,
    )
    .await;
    let flushed = out.flush().await;
    if let Err(e) = streamed {
        return stream_failure(e);
    }
    if let Err(e) = flushed {
        return finish_io(&e);
    }
    if accepted != len {
        return reject(
            StatusCode::BAD_REQUEST,
            "Request body ended before Content-Length",
        );
    }
    let chunk_digest: [u8; 32] = hasher.finalize().into();
    if digests.body.is_some_and(|d| d != chunk_digest) {
        let rolled_back = out.get_ref().set_len(range.start).await;
        return match rolled_back {
            Ok(()) => text(StatusCode::UNPROCESSABLE_ENTITY, "Chunk digest mismatch"),
            Err(e) => finish_io(&e),
        };
    }
    if let Err(e) = out.get_ref().sync_data().await {
        return finish_io(&e);
    }
    drop(out);

    let new_len = range.start + accepted;
    if new_len < range.total {
        return build(
            StatusCode::ACCEPTED,
            &[
                ("upload-offset", new_len.to_string()),
                ("upload-length", range.total.to_string()),
            ],
            Bytes::new(),
        );
    }

    let whole = {
        let path = resume.clone();
        tokio::task::spawn_blocking(move || hash_file(&path))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)))
    };
    let whole = match whole {
        Ok(d) => d,
        Err(e) => return finish_io(&e),
    };
    if digests.repr.is_some_and(|d| d != whole) {
        let _ = tokio::fs::remove_file(&resume).await;
        return text(StatusCode::UNPROCESSABLE_ENTITY, "Digest mismatch");
    }
    let replaced = tags.is_some();
    match publish(&t, resume, tags).await {
        Ok(()) => success(&t, replaced, &whole),
        Err(e) => publish_failure(e),
    }
}
