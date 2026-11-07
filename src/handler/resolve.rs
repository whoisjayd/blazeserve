use std::ffi::OsString;
use std::fs::Metadata;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hyper::header::{self, HeaderMap};
use percent_encoding::percent_decode_str;

use crate::config::Config;
use crate::{security, ui, upload};

pub(super) enum PathError {
    Bad,
    Traversal,
    NotFound,
}

/// Decode exactly once, then split: a `%2F` or `%2e%2e` must never be decoded a
/// second time or smuggled past the component checks.
pub(super) fn decode_components(raw: &str) -> Result<Vec<String>, PathError> {
    let decoded =
        String::from_utf8(percent_decode_str(raw).collect()).map_err(|_| PathError::Bad)?;
    if decoded.contains('\0') || decoded.contains('\\') {
        return Err(PathError::Bad);
    }
    let mut out = Vec::new();
    for part in decoded.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(PathError::Traversal),
            p => {
                if cfg!(windows) {
                    windows_component_ok(p)?;
                }
                out.push(p.to_owned());
            }
        }
    }
    Ok(out)
}

pub(super) fn windows_component_ok(part: &str) -> Result<(), PathError> {
    if part.contains([':', '<', '>', '"', '|', '?', '*']) {
        return Err(PathError::Bad);
    }
    let stem = part
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        Err(PathError::NotFound)
    } else {
        Ok(())
    }
}

pub(super) struct Served {
    pub(super) file: Arc<std::fs::File>,
    pub(super) meta: Metadata,
    pub(super) name: String,
    pub(super) content_type: &'static str,
    pub(super) encoding: Option<&'static str>,
}

pub(super) enum Resolved {
    NotFound,
    Forbidden,
    Listing {
        rel: String,
        entries: Vec<ui::Entry>,
    },
    File(Box<Served>),
}

#[derive(Clone, Copy)]
pub(super) struct Encodings {
    pub(super) br: bool,
    pub(super) gzip: bool,
}

pub(super) fn accepted_encodings(headers: &HeaderMap) -> Encodings {
    let mut enc = Encodings {
        br: false,
        gzip: false,
    };
    for value in headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        for item in value.split(',') {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            let acceptable = parts.all(|p| {
                match p
                    .trim()
                    .strip_prefix("q=")
                    .or_else(|| p.trim().strip_prefix("Q="))
                {
                    Some(q) => q.trim().parse::<f32>().map(|q| q > 0.0).unwrap_or(false),
                    None => true,
                }
            });
            if !acceptable {
                continue;
            }
            match coding.as_str() {
                "br" => enc.br = true,
                "gzip" | "x-gzip" => enc.gzip = true,
                _ => {}
            }
        }
    }
    enc
}

pub(super) fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

pub(super) fn is_safe_file(cfg: &Config, path: &Path) -> bool {
    path.is_file() && security::is_safe_path(&cfg.base, path)
}

pub(super) fn resolve(
    cfg: &Config,
    components: &[String],
    encodings: Option<Encodings>,
) -> Resolved {
    let mut path = match &cfg.single {
        Some(single) => single.clone(),
        None => components.iter().fold(cfg.base.clone(), |p, c| p.join(c)),
    };
    if !security::is_safe_path(&cfg.base, &path) {
        return Resolved::Forbidden;
    }
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Resolved::Forbidden,
        Err(_) => return Resolved::NotFound,
    };

    if meta.is_dir() {
        if !cfg.listing {
            return Resolved::Forbidden;
        }
        let index = ["index.html", "index.htm"]
            .into_iter()
            .chain(cfg.index.iter().map(String::as_str))
            .map(|name| path.join(name))
            .find(|candidate| is_safe_file(cfg, candidate));
        match index {
            Some(found) => path = found,
            None => return list_dir(cfg, &path, components.join("/")),
        }
    } else if !meta.is_file() {
        return Resolved::Forbidden;
    }

    let mut served_path = path.clone();
    let mut encoding = None;
    if let Some(enc) = encodings.filter(|_| cfg.precompress) {
        for (suffix, token, wanted) in [(".br", "br", enc.br), (".gz", "gzip", enc.gzip)] {
            if !wanted {
                continue;
            }
            let candidate = with_suffix(&path, suffix);
            if is_safe_file(cfg, &candidate) {
                served_path = candidate;
                encoding = Some(token);
                break;
            }
        }
    }

    let file = match std::fs::File::open(&served_path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Resolved::NotFound,
        Err(_) => return Resolved::Forbidden,
    };
    let meta = match file.metadata() {
        Ok(m) if m.is_file() => m,
        _ => return Resolved::Forbidden,
    };
    Resolved::File(Box::new(Served {
        file: Arc::new(file),
        meta,
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        content_type: mime_guess::from_path(&path)
            .first_raw()
            .unwrap_or("application/octet-stream"),
        encoding,
    }))
}

pub(super) fn list_dir(cfg: &Config, dir: &Path, rel: String) -> Resolved {
    let Ok(read) = std::fs::read_dir(dir) else {
        return Resolved::Forbidden;
    };
    let mut entries = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if upload::is_reserved_name(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let is_link = entry.file_type().map(|t| t.is_symlink()).unwrap_or(false);
        // A listed symlink must not reveal that something outside the root exists.
        if is_link && !security::is_safe_path(&cfg.base, &path) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        entries.push(ui::Entry {
            name: entry.file_name().to_string_lossy().into_owned(),
            is_dir: meta.is_dir(),
            size: meta.len(),
            modified: meta.modified().ok(),
        });
    }
    Resolved::Listing { rel, entries }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{self, HeaderMap, HeaderValue};

    fn comps(raw: &str) -> Result<Vec<String>, PathError> {
        decode_components(raw)
    }

    #[test]
    fn path_is_decoded_once_and_traversal_rejected() {
        assert_eq!(comps("/a/b.txt").ok().unwrap(), ["a", "b.txt"]);
        assert_eq!(comps("//a/./b").ok().unwrap(), ["a", "b"]);
        assert!(matches!(comps("/a/../b"), Err(PathError::Traversal)));
        assert!(matches!(comps("/%2e%2e/secret"), Err(PathError::Traversal)));
        assert!(matches!(comps("/a%2F..%2Fb"), Err(PathError::Traversal)));
        assert_eq!(comps("/%252e%252e/x").ok().unwrap(), ["%2e%2e", "x"]);
        assert!(matches!(comps("/a%00b"), Err(PathError::Bad)));
        assert!(matches!(comps("/a%5Cb"), Err(PathError::Bad)));
        assert!(matches!(comps("/%ff"), Err(PathError::Bad)));
    }

    #[test]
    fn accept_encoding_honours_q_zero() {
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip;q=0, br"),
        );
        let e = accepted_encodings(&h);
        assert!(e.br && !e.gzip);
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("deflate, GZIP;q=0.5"),
        );
        let e = accepted_encodings(&h);
        assert!(e.gzip && !e.br);
    }
}
