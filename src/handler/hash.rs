use std::io::Read;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hyper::header::HeaderValue;
use hyper::{Response, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use super::resolve::Served;
use super::response::{error, json_response};
use crate::{AppState, Body};

const MAX_CONCURRENT: usize = 4;
const CACHE_ENTRIES: usize = 1024;
const CHUNK: usize = 256 * 1024;

type Key = (PathBuf, u64, Option<SystemTime>);

/// Bounds concurrent hashing and remembers digests per (path, size, mtime).
#[derive(Debug)]
pub struct HashCache {
    permits: Arc<Semaphore>,
    digests: Mutex<lru::LruCache<Key, [u8; 32]>>,
}

impl HashCache {
    pub fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT)),
            digests: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(CACHE_ENTRIES).unwrap_or(NonZeroUsize::MIN),
            )),
        }
    }

    fn lookup(&self, key: &Key) -> Option<[u8; 32]> {
        self.digests.lock().ok()?.get(key).copied()
    }

    fn store(&self, key: Key, digest: [u8; 32]) {
        if let Ok(mut cache) = self.digests.lock() {
            cache.put(key, digest);
        }
    }
}

impl Default for HashCache {
    fn default() -> Self {
        Self::new()
    }
}

fn digest_file(file: &std::fs::File) -> std::io::Result<[u8; 32]> {
    let mut reader = file;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buf[..n]);
    }
}

pub(super) async fn hash_response(
    state: &Arc<AppState>,
    served: Served,
    display_path: String,
) -> Response<Body> {
    let size = served.meta.len();
    let modified = served.meta.modified().ok();
    let cache = &state.hashes;
    // The permit moves into the closure: a cancelled await must not free a slot
    // while the blocking hash is still running.
    let Ok(permit) = Arc::clone(&cache.permits).acquire_owned().await else {
        state.metrics.add_error();
        return error(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let task_state = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let key_path = std::fs::canonicalize(&served.path).unwrap_or(served.path.clone());
        let key = (key_path, size, modified);
        if let Some(hit) = task_state.hashes.lookup(&key) {
            return Ok(hit);
        }
        let digest = digest_file(&served.file)?;
        task_state.hashes.store(key, digest);
        Ok::<_, std::io::Error>(digest)
    })
    .await;
    match result {
        Ok(Ok(digest)) => {
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            let mut resp = json_response(
                StatusCode::OK,
                &json!({ "path": display_path, "size": size, "sha256": hex }),
            );
            let repr = format!("sha-256=:{}:", STANDARD.encode(digest));
            if let Ok(v) = HeaderValue::from_str(&repr) {
                resp.headers_mut().insert("repr-digest", v);
            }
            resp
        }
        _ => {
            state.metrics.add_error();
            error(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
