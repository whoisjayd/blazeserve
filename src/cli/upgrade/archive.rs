//! Pulls the one expected binary out of a release archive without trusting its entry names.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};

/// The unpacked binary is a few megabytes; this stops a decompression bomb.
pub const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_TAR_STREAM: u64 = 512 * 1024 * 1024;

/// The normal path parts of an entry, or `None` for an absolute path or one with `..`.
fn safe_parts(path: &Path) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(p) => parts.push(p.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(parts)
}

fn unsafe_entry(path: &Path) -> String {
    format!("the archive holds an unsafe path ({})", path.display())
}

/// Copies at most [`MAX_BINARY_BYTES`] and fails if the entry is longer.
fn copy_limited(from: &mut dyn Read, to: &mut dyn Write) -> Result<u64, String> {
    let copied = std::io::copy(&mut from.take(MAX_BINARY_BYTES + 1), to)
        .map_err(|e| format!("cannot unpack the archive: {e}"))?;
    if copied > MAX_BINARY_BYTES {
        return Err("the binary in the archive is unreasonably large".to_owned());
    }
    Ok(copied)
}

/// Extracts the regular file at `expected` (for example `blazeserve-v1.0.0-<target>/blaze`)
/// from a `.tar.gz` or `.zip` archive. Every entry path is checked, and only the expected
/// one is ever written, to `dest`.
pub fn extract_binary(archive: &Path, expected: &str, dest: &mut dyn Write) -> Result<(), String> {
    let want: Vec<String> = expected.split('/').map(str::to_owned).collect();
    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let file = File::open(archive).map_err(|e| format!("cannot open the archive: {e}"))?;
    let found = if name.ends_with(".zip") {
        from_zip(file, &want, dest)?
    } else {
        from_tar_gz(file, &want, dest)?
    };
    found.ok_or_else(|| format!("the archive does not contain {expected}"))
}

fn from_tar_gz(file: File, want: &[String], dest: &mut dyn Write) -> Result<Option<()>, String> {
    let corrupt = |e: std::io::Error| format!("the archive is corrupt: {e}");
    let decoder = flate2::read::GzDecoder::new(BufReader::new(file)).take(MAX_TAR_STREAM);
    let mut archive = tar::Archive::new(decoder);
    let mut found = None;
    for (index, entry) in archive.entries().map_err(corrupt)?.enumerate() {
        if index >= MAX_ENTRIES {
            return Err("the archive holds too many entries".to_owned());
        }
        let mut entry = entry.map_err(corrupt)?;
        let path = entry.path().map_err(corrupt)?.into_owned();
        let parts = safe_parts(&path).ok_or_else(|| unsafe_entry(&path))?;
        if parts == want && entry.header().entry_type().is_file() {
            if found.is_some() {
                return Err("the archive holds the binary more than once".to_owned());
            }
            copy_limited(&mut entry, dest)?;
            found = Some(());
        }
    }
    Ok(found)
}

fn from_zip(file: File, want: &[String], dest: &mut dyn Write) -> Result<Option<()>, String> {
    let corrupt = |e: zip::result::ZipError| format!("the archive is corrupt: {e}");
    let mut archive = zip::ZipArchive::new(BufReader::new(file)).map_err(corrupt)?;
    if archive.len() > MAX_ENTRIES {
        return Err("the archive holds too many entries".to_owned());
    }
    let mut found = None;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(corrupt)?;
        let raw = PathBuf::from(
            entry
                .name()
                .map_or_else(|_| String::new(), |n| n.into_owned()),
        );
        let path = entry.enclosed_name().ok_or_else(|| unsafe_entry(&raw))?;
        let parts = safe_parts(&path).ok_or_else(|| unsafe_entry(&path))?;
        if parts == want && entry.is_file() {
            if found.is_some() {
                return Err("the archive holds the binary more than once".to_owned());
            }
            copy_limited(&mut entry, dest)?;
            found = Some(());
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "blazeserve-v1.0.0-x/blaze";

    fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            // The path is written into the raw header so `..` entries can be forged.
            let raw = header.as_old_mut();
            raw.name[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (path, data) in entries {
            writer
                .start_file(*path, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn extract(file_name: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(file_name);
        std::fs::write(&path, bytes).unwrap();
        let mut out = Vec::new();
        extract_binary(&path, NAME, &mut out).map(|()| out)
    }

    #[test]
    fn extracts_only_the_expected_entry_from_tar_gz_and_zip() {
        let entries: &[(&str, &[u8])] = &[
            ("blazeserve-v1.0.0-x/LICENSE", b"license"),
            (NAME, b"BINARY"),
            ("blazeserve-v1.0.0-x/README.md", b"readme"),
        ];
        assert_eq!(extract("a.tar.gz", &tar_gz(entries)).unwrap(), b"BINARY");
        assert_eq!(extract("a.zip", &zip_bytes(entries)).unwrap(), b"BINARY");
    }

    #[test]
    fn a_traversal_entry_fails_the_whole_archive() {
        let bad: &[(&str, &[u8])] = &[(NAME, b"BINARY"), ("../evil", b"x")];
        let err = extract("a.tar.gz", &tar_gz(bad)).unwrap_err();
        assert!(err.contains("unsafe path"), "{err}");
        let err = extract("a.zip", &zip_bytes(bad)).unwrap_err();
        assert!(err.contains("unsafe path"), "{err}");
        let abs: &[(&str, &[u8])] = &[("/etc/passwd", b"x"), (NAME, b"B")];
        assert!(
            extract("a.tar.gz", &tar_gz(abs))
                .unwrap_err()
                .contains("unsafe path")
        );
    }

    #[test]
    fn missing_or_corrupt_archives_are_errors() {
        let none: &[(&str, &[u8])] = &[("blazeserve-v1.0.0-x/README.md", b"r")];
        assert!(
            extract("a.tar.gz", &tar_gz(none))
                .unwrap_err()
                .contains("does not contain")
        );
        assert!(extract("a.tar.gz", b"this is not gzip").is_err());
        assert!(extract("a.zip", b"this is not a zip").is_err());
        let mut cut = tar_gz(&[(NAME, &[7u8; 4096])]);
        cut.truncate(cut.len() / 2);
        assert!(extract("a.tar.gz", &cut).is_err());
    }
}
