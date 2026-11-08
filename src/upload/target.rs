//! Upload target resolution under the served root and the staging file naming.

use std::path::{Path, PathBuf};

use hyper::{Response, StatusCode};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use sha2::{Digest, Sha256};

use super::response::reject;
use crate::security::{self, ResolveError};
use crate::{AppState, Body};

const PREFIX: &str = "/__upload__/";
const PART_MARK: &str = ".blaze-part-";
const RESUME_SUFFIX: &str = ".blaze-resume";
const RESUME_PREFIX: &str = ".blaze-resume-";
const MAX_STAGED_NAME: usize = 180;
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub(super) struct Target {
    pub(super) base: PathBuf,
    pub(super) path: PathBuf,
    pub(super) rel: String,
}

impl Target {
    pub(super) fn name(&self) -> String {
        self.path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
    }

    pub(super) fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(&self.base)
    }

    pub(super) fn staging_path(&self, kind: Staging) -> PathBuf {
        let name = self.name();
        let file = match kind {
            Staging::Part => {
                let id = security::generate_request_id(None);
                if name.len() <= MAX_STAGED_NAME {
                    format!(".{name}{PART_MARK}{id}")
                } else {
                    format!("{PART_MARK}{id}")
                }
            }
            Staging::Resume => {
                if name.len() <= MAX_STAGED_NAME {
                    format!(".{name}{RESUME_SUFFIX}")
                } else {
                    let h = Sha256::digest(name.as_bytes());
                    let hex: String = h[..8].iter().map(|b| format!("{b:02x}")).collect();
                    format!("{RESUME_PREFIX}{hex}")
                }
            }
        };
        self.dir().join(file)
    }

    pub(super) fn location(&self) -> String {
        let mut out = String::new();
        for seg in self.rel.split('/').filter(|s| !s.is_empty() && *s != ".") {
            out.push('/');
            out.push_str(&utf8_percent_encode(seg, PATH_SEGMENT).to_string());
        }
        out
    }
}

#[derive(Clone, Copy)]
pub(super) enum Staging {
    Part,
    Resume,
}

pub fn is_reserved_name(name: &str) -> bool {
    name.contains(PART_MARK)
        || name.ends_with(RESUME_SUFFIX)
        || name.starts_with(PART_MARK)
        || name.starts_with(RESUME_PREFIX)
}

#[allow(clippy::result_large_err)]
pub(super) fn parse_target(state: &AppState, req_path: &str) -> Result<Target, Response<Body>> {
    let raw = req_path
        .strip_prefix(PREFIX)
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "Not found"))?;
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "Invalid path encoding"))?;
    let rel = decoded.trim_matches(|c| c == '/' || c == '\\').to_owned();
    if rel.is_empty() {
        return Err(reject(StatusCode::BAD_REQUEST, "Missing file name"));
    }
    let base = state
        .config
        .base
        .canonicalize()
        .map_err(|_| reject(StatusCode::INTERNAL_SERVER_ERROR, "Upload failed"))?;
    let path = match security::resolve_under(&base, &rel) {
        Ok(p) => p,
        Err(ResolveError::Invalid) => {
            return Err(reject(StatusCode::BAD_REQUEST, "Invalid file name"));
        }
        Err(ResolveError::Escape) => return Err(reject(StatusCode::FORBIDDEN, "Forbidden")),
    };
    if path == base {
        return Err(reject(StatusCode::BAD_REQUEST, "Missing file name"));
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if is_reserved_name(&name) {
        return Err(reject(StatusCode::BAD_REQUEST, "Reserved file name"));
    }
    Ok(Target { base, path, rel })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_names_are_blocked() {
        assert!(is_reserved_name(".x.blaze-resume"));
        assert!(is_reserved_name(".x.blaze-part-abc"));
        assert!(is_reserved_name(".blaze-resume-0011"));
        assert!(!is_reserved_name("report.txt"));
    }
}
