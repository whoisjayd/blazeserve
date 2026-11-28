//! `--nested`: after extracting, unpacks the archives that came out, one level deep. A file
//! is only taken when its name and its first bytes agree, so a `.jar` or a document that is
//! a ZIP inside is left alone.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::error::TransferError;
use super::extract::{Options, extract};
use crate::cli::ansi::announce;

/// A bound on the walk, far above what a real archive of archives holds.
const MOST_FILES: usize = 100_000;

fn starts_with(path: &Path, offset: u64, magic: &[u8]) -> bool {
    let read = || -> std::io::Result<bool> {
        let mut file = std::fs::File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut head = vec![0; magic.len()];
        file.read_exact(&mut head)?;
        Ok(head == magic)
    };
    read().unwrap_or(false)
}

/// Whether a file is an archive by both its name and its signature.
fn is_archive(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let ends = |suffix: &str| name.ends_with(suffix);
    if ends(".zip") {
        starts_with(path, 0, b"PK\x03\x04")
    } else if ends(".7z") {
        starts_with(path, 0, b"7z\xbc\xaf\x27\x1c")
    } else if ends(".tar") {
        starts_with(path, 257, b"ustar")
    } else if ends(".tar.gz") || ends(".tgz") {
        starts_with(path, 0, b"\x1f\x8b")
    } else if ends(".tar.xz") {
        starts_with(path, 0, b"\xfd7zXZ\x00")
    } else {
        false
    }
}

/// Archives below `root`, without following links.
fn find(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut folders = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(folder) = folders.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > MOST_FILES {
                return found;
            }
            // The entry's own type: a link is neither a file nor a folder here.
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                folders.push(entry.path());
            } else if kind.is_file() && is_archive(&entry.path()) {
                found.push(entry.path());
            }
        }
    }
    found.sort();
    found
}

/// Extracts each archive found below `root`. The first failure stops it, saying how far it
/// got; what came out of earlier ones stays.
pub(super) fn extract_all(root: &Path, options: &Options) -> Result<(), TransferError> {
    let archives = find(root);
    if archives.is_empty() {
        return Ok(());
    }
    let inside = match archives.len() {
        1 => "1 archive inside; extracting it".to_owned(),
        n => format!("{n} archives inside; extracting each"),
    };
    announce("Nested", &inside);
    for (done, archive) in archives.iter().enumerate() {
        extract(archive, options).map_err(|e| {
            e.map_message(|why| {
                format!(
                    "{done} of {} inner archives extracted; {} failed: {why}",
                    archives.len(),
                    archive.display()
                )
            })
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_signature_must_agree() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        };
        assert!(is_archive(&write("a.zip", b"PK\x03\x04rest")));
        assert!(!is_archive(&write("lib.jar", b"PK\x03\x04rest")));
        assert!(!is_archive(&write("picture.zip", b"\x89PNG....")));
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        assert!(is_archive(&write("b.tar", &tar)));
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/c.tgz"), b"\x1f\x8bxx").unwrap();
        let found = find(dir.path());
        assert_eq!(found.len(), 3, "{found:?}");
    }
}
