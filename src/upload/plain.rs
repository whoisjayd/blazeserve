//! Single-request uploads: stream, verify and publish in one exchange.

use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWriteExt, BufWriter};

use super::publish::{publish, publish_failure, success};
use super::request::Digests;
use super::response::{finish_io, io_status, reject, text};
use super::stream::{StagingGuard, buf_capacity, create_staging, idle, pump, stream_failure};
use super::target::{Staging, Target};
use crate::{AppState, Body};

pub(super) async fn plain(
    state: &Arc<AppState>,
    req: Request<Incoming>,
    t: Target,
    len: u64,
    digests: Digests,
    tags: Option<Vec<String>>,
) -> Response<Body> {
    let staging = t.staging_path(Staging::Part);
    let file = match create_staging(&t, staging.clone()).await {
        Ok(f) => f,
        Err(e) => {
            let (status, msg) = io_status(&e);
            return reject(status, msg);
        }
    };
    let mut guard = StagingGuard {
        path: staging.clone(),
        armed: true,
    };
    let mut out = BufWriter::with_capacity(buf_capacity(state), tokio::fs::File::from_std(file));
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
    if let Err(e) = streamed {
        return stream_failure(e);
    }
    if accepted != len {
        return reject(
            StatusCode::BAD_REQUEST,
            "Request body ended before Content-Length",
        );
    }
    if let Err(e) = out.flush().await {
        return finish_io(&e);
    }
    if let Err(e) = out.get_ref().sync_data().await {
        return finish_io(&e);
    }
    drop(out);
    let digest: [u8; 32] = hasher.finalize().into();
    if [digests.body, digests.repr]
        .into_iter()
        .flatten()
        .any(|d| d != digest)
    {
        return text(StatusCode::UNPROCESSABLE_ENTITY, "Digest mismatch");
    }
    let replaced = tags.is_some();
    match publish(&t, staging, tags).await {
        Ok(()) => {
            guard.armed = false;
            success(&t, replaced, &digest)
        }
        Err(e) => publish_failure(e),
    }
}
