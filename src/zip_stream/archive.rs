//! Blocking producer: selects files under the served root and writes them to the body channel.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use bytes::Bytes;
use hyper::body::Frame;
use tokio::sync::mpsc;

use super::writer::StreamZip;
use crate::security;

const FRAME_BYTES: usize = 64 * 1024;

pub(super) type Item = Result<Frame<Bytes>, io::Error>;

struct ChannelWriter {
    tx: mpsc::Sender<Item>,
    buf: Vec<u8>,
}

impl ChannelWriter {
    fn send_buf(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let data = std::mem::replace(&mut self.buf, Vec::with_capacity(FRAME_BYTES));
        // Fails once the response body is dropped, which aborts archive generation.
        self.tx
            .blocking_send(Ok(Frame::data(Bytes::from(data))))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client disconnected"))
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= FRAME_BYTES {
            self.send_buf()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buf()
    }
}

fn entry_name(root: &Path, file: &Path) -> Option<String> {
    let rel = file.strip_prefix(root).ok()?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Regular files only. A symlink is included when it points at a file that still
/// resolves inside the root; symlinked directories are never descended.
fn collect_files(base: &Path, root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = read.filter_map(Result::ok).collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            let is_file = ft.is_file()
                || (ft.is_symlink() && std::fs::metadata(&path).is_ok_and(|m| m.is_file()));
            if ft.is_dir() {
                stack.push(path);
            } else if is_file && security::is_safe_path(base, &path) {
                files.push(path);
            }
        }
    }
    files
}

pub(super) fn write_archive(base: &Path, target: &Path, tx: mpsc::Sender<Item>) -> io::Result<()> {
    let mut zip = StreamZip::new(ChannelWriter {
        tx,
        buf: Vec::with_capacity(FRAME_BYTES),
    });
    let files: Vec<(PathBuf, String)> = if std::fs::metadata(target)?.is_dir() {
        collect_files(base, target)
            .into_iter()
            .filter_map(|p| entry_name(target, &p).map(|n| (p, n)))
            .collect()
    } else {
        let name = target
            .file_name()
            .map_or_else(|| "file".to_owned(), |n| n.to_string_lossy().into_owned());
        vec![(target.to_path_buf(), name)]
    };
    let mut buf = vec![0u8; 256 * 1024];
    for (path, name) in files {
        let Ok(mut file) = std::fs::File::open(&path) else {
            continue;
        };
        let Ok(meta) = file.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        zip.add_file(&name, meta.modified().ok(), meta.len(), &mut file, &mut buf)?;
    }
    zip.finish().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_names_use_forward_slashes() {
        let root = Path::new("root");
        let file = root.join("a").join("b.txt");
        assert_eq!(entry_name(root, &file).as_deref(), Some("a/b.txt"));
        assert!(entry_name(root, root).is_none());
    }
}
