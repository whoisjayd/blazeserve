//! Canonical containment, race-resistant upload creation, request IDs.
//!
//! Trust model: the served root is trusted; client paths, headers and bodies are not.
//! Containment is decided on canonical paths and compared component-wise, so
//! `/root-evil` never matches `/root`, symlinked parents resolve before comparison, and a
//! different drive or verbatim prefix fails closed.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Marker error carried inside an [`io::Error`] when a path would escape the root.
#[derive(Debug)]
pub struct UnsafePath(pub &'static str);

impl std::fmt::Display for UnsafePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for UnsafePath {}

pub fn unsafe_io(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, UnsafePath(msg))
}

pub fn is_unsafe_path_error(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<UnsafePath>())
}

/// `realpath` that tolerates a missing tail. A dangling symlink, an unreadable component or
/// a `..` in the missing tail fails closed (`None`).
fn canonical_lenient(path: &Path) -> Option<PathBuf> {
    if let Ok(p) = path.canonicalize() {
        return Some(p);
    }
    let mut tail: Vec<OsString> = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        match fs::symlink_metadata(&cur) {
            // Exists yet cannot be canonicalized: dangling link or no permission.
            Ok(_) => return None,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
        tail.push(cur.file_name()?.to_owned());
        if !cur.pop() {
            return None;
        }
        if let Ok(mut real) = cur.canonicalize() {
            for name in tail.iter().rev() {
                real.push(name);
            }
            return Some(real);
        }
    }
}

/// True when `target` resolves inside `base`; `target` may not exist yet.
pub fn is_safe_path(base: &Path, target: &Path) -> bool {
    let Ok(real_base) = base.canonicalize() else {
        return false;
    };
    match canonical_lenient(target) {
        Some(real_target) => real_target.starts_with(&real_base),
        None => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    /// Malformed input (NUL, empty, reserved/illegal name): answer 400.
    Invalid,
    /// Traversal or escape attempt: answer 403.
    Escape,
}

#[cfg(windows)]
fn is_windows_reserved(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0')
}

/// Join a percent-decoded relative path onto `base`, rejecting NUL, `..`, backslashes and,
/// on Windows, drive/stream syntax and reserved device names. `.` and empty segments are
/// ignored, so `"."` resolves to the root. The result must pass [`is_safe_path`].
pub fn resolve_under(base: &Path, rel: &str) -> Result<PathBuf, ResolveError> {
    if rel.is_empty() || rel.contains('\0') {
        return Err(ResolveError::Invalid);
    }
    if rel.contains('\\') {
        return Err(ResolveError::Escape);
    }
    let mut out = base.to_path_buf();
    for segment in rel.split('/') {
        match segment {
            "" | "." => {}
            ".." => return Err(ResolveError::Escape),
            s => {
                #[cfg(windows)]
                if s.contains(':') || s.ends_with('.') || s.ends_with(' ') || is_windows_reserved(s)
                {
                    return Err(ResolveError::Invalid);
                }
                out.push(s);
            }
        }
    }
    if is_safe_path(base, &out) {
        Ok(out)
    } else {
        Err(ResolveError::Escape)
    }
}

/// Accept `incoming` only when it is 1-64 characters and alphanumeric once hyphens
/// are removed; otherwise generate 12 hex characters.
pub fn generate_request_id(incoming: Option<&str>) -> String {
    if let Some(id) = incoming {
        let ok = (1..=64).contains(&id.len())
            && id.bytes().all(|b| b == b'-' || b.is_ascii_alphanumeric())
            && id.bytes().any(|b| b != b'-');
        if ok {
            return id.to_owned();
        }
    }
    let mut raw = [0u8; 6];
    if getrandom::fill(&mut raw).is_err() {
        // An RNG failure must not fail the request; fall back to the clock.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        raw.copy_from_slice(&nanos.to_le_bytes()[..6]);
    }
    let mut s = String::with_capacity(12);
    for b in raw {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
    }
    s
}

fn parent_contained(real_base: &Path, parent: &Path) -> bool {
    parent
        .canonicalize()
        .is_ok_and(|p| p.starts_with(real_base))
}

/// Create a new file without overwriting or following a final symlink: `create_new` fails
/// with `AlreadyExists` even on a dangling link. The parent is re-resolved after
/// `create_dir_all` and after the open to catch a swapped symlink. Unix mode is `0600`.
pub fn create_upload_file(base: &Path, target: &Path) -> io::Result<File> {
    let real_base = base.canonicalize()?;
    let parent = target
        .parent()
        .ok_or_else(|| unsafe_io("upload path has no parent"))?;
    if !is_safe_path(&real_base, target) || !is_safe_path(&real_base, parent) {
        return Err(unsafe_io("upload path escapes the configured root"));
    }
    fs::create_dir_all(parent)?;
    if !parent_contained(&real_base, parent) {
        return Err(unsafe_io("upload parent escapes the configured root"));
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = match opts.open(target) {
        Ok(f) => f,
        Err(e) => {
            if !parent_contained(&real_base, parent) {
                return Err(unsafe_io("upload parent changed during creation"));
            }
            return Err(e);
        }
    };
    if !parent_contained(&real_base, parent) {
        drop(file);
        let _ = fs::remove_file(target);
        return Err(unsafe_io("upload parent changed during creation"));
    }
    Ok(file)
}

/// Open an existing regular file for writing at its end (resumable uploads).
/// Refuses symlinks and checks (unix) that the handle is the file `lstat` saw.
pub fn open_existing_for_append(base: &Path, path: &Path) -> io::Result<(File, u64)> {
    use std::io::{Seek, SeekFrom};
    let real_base = base.canonicalize()?;
    let parent = path
        .parent()
        .ok_or_else(|| unsafe_io("path has no parent"))?;
    if !parent_contained(&real_base, parent) {
        return Err(unsafe_io("parent escapes the configured root"));
    }
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(unsafe_io("not a regular file"));
    }
    let mut file = OpenOptions::new().write(true).open(path)?;
    let after = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(unsafe_io("file changed during open"));
        }
    }
    if !after.is_file() || !parent_contained(&real_base, parent) {
        return Err(unsafe_io("not a regular file"));
    }
    let len = file.seek(SeekFrom::End(0))?;
    Ok((file, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[cfg(unix)]
    fn symlink_dir(src: &Path, dst: &Path) -> bool {
        std::os::unix::fs::symlink(src, dst).is_ok()
    }
    #[cfg(windows)]
    fn symlink_dir(src: &Path, dst: &Path) -> bool {
        std::os::windows::fs::symlink_dir(src, dst).is_ok()
    }

    #[test]
    fn safe_inside_and_missing_tail() {
        let d = tmp();
        let root = d.path().join("root");
        fs::create_dir_all(root.join("a")).unwrap();
        assert!(is_safe_path(&root, &root));
        assert!(is_safe_path(&root, &root.join("a")));
        assert!(is_safe_path(
            &root,
            &root.join("a").join("new").join("deep.txt")
        ));
    }

    #[test]
    fn rejects_parent_traversal_and_outside() {
        let d = tmp();
        let root = d.path().join("root");
        fs::create_dir_all(&root).unwrap();
        fs::write(d.path().join("secret"), b"x").unwrap();
        assert!(!is_safe_path(&root, &root.join("..").join("secret")));
        assert!(!is_safe_path(
            &root,
            &root.join("nope").join("..").join("..").join("x")
        ));
        assert!(!is_safe_path(&root, d.path()));
    }

    #[test]
    fn sibling_prefix_is_not_inside() {
        let d = tmp();
        let root = d.path().join("root");
        let evil = d.path().join("root-evil");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&evil).unwrap();
        fs::write(evil.join("f"), b"x").unwrap();
        assert!(!is_safe_path(&root, &evil));
        assert!(!is_safe_path(&root, &evil.join("f")));
    }

    #[test]
    fn missing_base_fails_closed() {
        let d = tmp();
        assert!(!is_safe_path(
            &d.path().join("gone"),
            &d.path().join("gone").join("x")
        ));
    }

    #[test]
    fn symlinked_parent_escape_fails_closed() {
        let d = tmp();
        let root = d.path().join("root");
        let outside = d.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        if !symlink_dir(&outside, &root.join("link")) {
            eprintln!("skipped: directory symlink creation unsupported here");
            return;
        }
        assert!(!is_safe_path(&root, &root.join("link").join("new.txt")));
        assert!(resolve_under(&root, "link/new.txt") == Err(ResolveError::Escape));
        let err = create_upload_file(&root, &root.join("link").join("new.txt")).unwrap_err();
        assert!(is_unsafe_path_error(&err));
        assert!(!outside.join("new.txt").exists());
    }

    #[test]
    fn resolve_under_rules() {
        let d = tmp();
        let root = d.path().join("root");
        fs::create_dir_all(&root).unwrap();
        assert_eq!(
            resolve_under(&root, "a/b.txt").unwrap(),
            root.join("a").join("b.txt")
        );
        assert_eq!(
            resolve_under(&root, "/a//./b").unwrap(),
            root.join("a").join("b")
        );
        assert_eq!(resolve_under(&root, ".").unwrap(), root);
        assert_eq!(resolve_under(&root, ""), Err(ResolveError::Invalid));
        assert_eq!(resolve_under(&root, "a\0b"), Err(ResolveError::Invalid));
        assert_eq!(resolve_under(&root, "../x"), Err(ResolveError::Escape));
        assert_eq!(resolve_under(&root, "a/../../x"), Err(ResolveError::Escape));
        assert_eq!(resolve_under(&root, "a\\..\\x"), Err(ResolveError::Escape));
    }

    #[cfg(windows)]
    #[test]
    fn resolve_under_windows_specials() {
        let d = tmp();
        assert_eq!(
            resolve_under(d.path(), "C:evil"),
            Err(ResolveError::Invalid)
        );
        assert_eq!(
            resolve_under(d.path(), "a.txt:stream"),
            Err(ResolveError::Invalid)
        );
        assert_eq!(
            resolve_under(d.path(), "nul.txt"),
            Err(ResolveError::Invalid)
        );
        assert_eq!(
            resolve_under(d.path(), "trailing."),
            Err(ResolveError::Invalid)
        );
    }

    #[test]
    fn request_id_contract() {
        assert_eq!(generate_request_id(Some("abc-123")), "abc-123");
        assert_eq!(generate_request_id(Some(&"a".repeat(64))).len(), 64);
        for bad in ["", "-", "---", "a b", "a_b", "é", &"a".repeat(65)] {
            let id = generate_request_id(Some(bad));
            assert_eq!(id.len(), 12, "{bad:?}");
            assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        let (a, b) = (generate_request_id(None), generate_request_id(None));
        assert_eq!(a.len(), 12);
        assert_ne!(a, b);
    }

    #[test]
    fn create_is_exclusive_and_never_overwrites() {
        let d = tmp();
        let root = d.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let target = root.join("n").join("f.bin");
        let first = create_upload_file(&root, &target).unwrap();
        drop(first);
        let err = create_upload_file(&root, &target).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(!is_unsafe_path_error(&err));
    }

    #[cfg(unix)]
    #[test]
    fn create_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp();
        let target = d.path().join("f");
        create_upload_file(d.path(), &target).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_does_not_follow_dangling_final_symlink() {
        let d = tmp();
        let root = d.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let outside = d.path().join("outside.txt");
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let err = create_upload_file(&root, &root.join("link")).unwrap_err();
        assert!(err.kind() == io::ErrorKind::AlreadyExists || is_unsafe_path_error(&err));
        assert!(!outside.exists());
    }

    #[test]
    fn open_existing_appends_and_refuses_directories() {
        let d = tmp();
        let f = d.path().join("p");
        fs::write(&f, b"abc").unwrap();
        let (_h, len) = open_existing_for_append(d.path(), &f).unwrap();
        assert_eq!(len, 3);
        assert!(open_existing_for_append(d.path(), d.path()).is_err());
        assert!(open_existing_for_append(d.path(), &d.path().join("missing")).is_err());
    }
}
