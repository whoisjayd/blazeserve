//! Streaming ZIP of a file or directory under the served root.
//!
//! The archive is produced on a blocking thread and handed to the response through a
//! small bounded channel, so a slow client throttles the producer and memory stays
//! flat. A failure mid-archive is propagated as a body error: ending the chunked body
//! cleanly would hand the client a valid-looking but truncated archive.
//!
//! The `zip` crate only writes to seekable sinks, so entries are written here as
//! STORED with data descriptors (CRC and sizes follow the data), which a socket can
//! carry without seeking back.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::Frame;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use tokio::sync::{Semaphore, mpsc};

use crate::security::{self, ResolveError};
use crate::{AppState, Body};

const FRAME_BYTES: usize = 64 * 1024;
const CHANNEL_FRAMES: usize = 8;
const MAX_CONCURRENT_ZIPS: usize = 32;
const ZIP64_LIMIT: u64 = 0xFFFF_FFFF;
const FILENAME_STAR: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.');

type Item = Result<Frame<Bytes>, io::Error>;

const fn crc_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    i = 0;
    while i < 256 {
        let mut c = t[0][i];
        let mut j = 1;
        while j < 8 {
            c = t[0][(c & 0xFF) as usize] ^ (c >> 8);
            t[j][i] = c;
            j += 1;
        }
        i += 1;
    }
    t
}

static CRC: [[u32; 256]; 8] = crc_tables();

/// Slice-by-8 CRC-32 (IEEE).
fn crc32_update(state: u32, data: &[u8]) -> u32 {
    let mut crc = !state;
    let (chunks, remainder) = data.as_chunks::<8>();
    for c in chunks {
        let lo = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ crc;
        let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        crc = CRC[7][(lo & 0xFF) as usize]
            ^ CRC[6][((lo >> 8) & 0xFF) as usize]
            ^ CRC[5][((lo >> 16) & 0xFF) as usize]
            ^ CRC[4][(lo >> 24) as usize]
            ^ CRC[3][(hi & 0xFF) as usize]
            ^ CRC[2][((hi >> 8) & 0xFF) as usize]
            ^ CRC[1][((hi >> 16) & 0xFF) as usize]
            ^ CRC[0][(hi >> 24) as usize];
    }
    for &b in remainder {
        crc = CRC[0][((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

/// MS-DOS date/time in UTC; anything outside 1980..=2107 becomes 1980-01-01.
fn dos_datetime(t: Option<SystemTime>) -> (u16, u16) {
    const FALLBACK: (u16, u16) = (0, 0x0021);
    let secs = t
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if !(1980..=2107).contains(&year) {
        return FALLBACK;
    }
    let time = ((rem / 3600) << 11) | (((rem % 3600) / 60) << 5) | ((rem % 60) / 2);
    let date = ((year - 1980) << 9) | (month << 5) | day;
    (time as u16, date as u16)
}

struct CentralEntry {
    name: Vec<u8>,
    crc: u32,
    size: u64,
    offset: u64,
    descriptor_z64: bool,
    time: u16,
    date: u16,
}

struct StreamZip<W: Write> {
    out: W,
    pos: u64,
    entries: Vec<CentralEntry>,
    limit: u64,
}

impl<W: Write> StreamZip<W> {
    fn new(out: W) -> Self {
        Self {
            out,
            pos: 0,
            entries: Vec::new(),
            limit: ZIP64_LIMIT,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.out.write_all(bytes)?;
        self.pos += bytes.len() as u64;
        Ok(())
    }

    /// Writes exactly `size` bytes from `src`; a file that shrinks mid-read is an error
    /// rather than a silently corrupt entry.
    fn add_file(
        &mut self,
        name: &str,
        modified: Option<SystemTime>,
        size: u64,
        src: &mut impl Read,
        buf: &mut [u8],
    ) -> io::Result<()> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > usize::from(u16::MAX) {
            return Ok(());
        }
        let z64 = size >= self.limit;
        let (time, date) = dos_datetime(modified);
        let offset = self.pos;

        let mut h = Vec::with_capacity(30 + name_bytes.len() + 20);
        h.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        h.extend_from_slice(&(if z64 { 45u16 } else { 20 }).to_le_bytes());
        h.extend_from_slice(&0x0808u16.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&time.to_le_bytes());
        h.extend_from_slice(&date.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        let sizes = if z64 { u32::MAX } else { 0 };
        h.extend_from_slice(&sizes.to_le_bytes());
        h.extend_from_slice(&sizes.to_le_bytes());
        h.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        h.extend_from_slice(&(if z64 { 20u16 } else { 0 }).to_le_bytes());
        h.extend_from_slice(name_bytes);
        if z64 {
            h.extend_from_slice(&1u16.to_le_bytes());
            h.extend_from_slice(&16u16.to_le_bytes());
            h.extend_from_slice(&[0u8; 16]);
        }
        self.put(&h)?;

        let mut crc = 0u32;
        let mut remaining = size;
        while remaining > 0 {
            let want = buf
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            let n = src.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "file shrank while archiving",
                ));
            }
            crc = crc32_update(crc, &buf[..n]);
            self.put(&buf[..n])?;
            remaining -= n as u64;
        }

        let mut d = Vec::with_capacity(24);
        d.extend_from_slice(&0x0807_4B50u32.to_le_bytes());
        d.extend_from_slice(&crc.to_le_bytes());
        if z64 {
            d.extend_from_slice(&size.to_le_bytes());
            d.extend_from_slice(&size.to_le_bytes());
        } else {
            d.extend_from_slice(&(size as u32).to_le_bytes());
            d.extend_from_slice(&(size as u32).to_le_bytes());
        }
        self.put(&d)?;

        self.entries.push(CentralEntry {
            name: name_bytes.to_vec(),
            crc,
            size,
            offset,
            descriptor_z64: z64,
            time,
            date,
        });
        Ok(())
    }

    fn finish(mut self) -> io::Result<W> {
        let cd_start = self.pos;
        let entries = std::mem::take(&mut self.entries);
        for e in &entries {
            let z64 = e.descriptor_z64 || e.offset >= self.limit;
            let mut c = Vec::with_capacity(46 + e.name.len() + 28);
            c.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
            c.extend_from_slice(&((3u16 << 8) | 45).to_le_bytes());
            c.extend_from_slice(&(if z64 { 45u16 } else { 20 }).to_le_bytes());
            c.extend_from_slice(&0x0808u16.to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes());
            c.extend_from_slice(&e.time.to_le_bytes());
            c.extend_from_slice(&e.date.to_le_bytes());
            c.extend_from_slice(&e.crc.to_le_bytes());
            let field = |v: u64| if z64 { u32::MAX } else { v as u32 };
            c.extend_from_slice(&field(e.size).to_le_bytes());
            c.extend_from_slice(&field(e.size).to_le_bytes());
            c.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            c.extend_from_slice(&(if z64 { 28u16 } else { 0 }).to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes());
            c.extend_from_slice(&(0o100_644u32 << 16).to_le_bytes());
            c.extend_from_slice(&field(e.offset).to_le_bytes());
            c.extend_from_slice(&e.name);
            if z64 {
                c.extend_from_slice(&1u16.to_le_bytes());
                c.extend_from_slice(&24u16.to_le_bytes());
                c.extend_from_slice(&e.size.to_le_bytes());
                c.extend_from_slice(&e.size.to_le_bytes());
                c.extend_from_slice(&e.offset.to_le_bytes());
            }
            self.put(&c)?;
        }
        let cd_size = self.pos - cd_start;
        let count = entries.len() as u64;
        let z64 = count >= 0xFFFF || cd_start >= self.limit || cd_size >= self.limit;
        if z64 {
            let eocd64_at = self.pos;
            let mut r = Vec::with_capacity(56 + 20);
            r.extend_from_slice(&0x0606_4B50u32.to_le_bytes());
            r.extend_from_slice(&44u64.to_le_bytes());
            r.extend_from_slice(&45u16.to_le_bytes());
            r.extend_from_slice(&45u16.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&count.to_le_bytes());
            r.extend_from_slice(&count.to_le_bytes());
            r.extend_from_slice(&cd_size.to_le_bytes());
            r.extend_from_slice(&cd_start.to_le_bytes());
            r.extend_from_slice(&0x0706_4B50u32.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&eocd64_at.to_le_bytes());
            r.extend_from_slice(&1u32.to_le_bytes());
            self.put(&r)?;
        }
        let mut e = Vec::with_capacity(22);
        e.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        let n16 = if z64 { u16::MAX } else { count as u16 };
        e.extend_from_slice(&n16.to_le_bytes());
        e.extend_from_slice(&n16.to_le_bytes());
        e.extend_from_slice(&(if z64 { u32::MAX } else { cd_size as u32 }).to_le_bytes());
        e.extend_from_slice(&(if z64 { u32::MAX } else { cd_start as u32 }).to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        self.put(&e)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

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

fn slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_ZIPS)))
}

fn plain(status: StatusCode, msg: &str) -> Response<Body> {
    let body = Bytes::from(msg.to_owned());
    let mut resp = Response::new(
        Full::new(body.clone())
            .map_err(|never| match never {})
            .boxed(),
    );
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn query_path(query: Option<&str>) -> Option<String> {
    let raw = query?.split('&').find_map(|kv| kv.strip_prefix("path="))?;
    let spaced = raw.replace('+', " ");
    percent_decode_str(&spaced)
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}

fn sanitize_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '"' | ';' | ':' | '\\' | '/'))
        .collect();
    let kept = kept.trim().to_owned();
    if kept.is_empty() {
        "archive".to_owned()
    } else {
        kept
    }
}

fn content_disposition(name: &str) -> String {
    let clean = sanitize_name(name);
    let ascii: String = clean
        .chars()
        .map(|c| if c.is_ascii() { c } else { '_' })
        .collect();
    if clean.is_ascii() {
        return format!("attachment; filename=\"{ascii}.zip\"");
    }
    let full = format!("{clean}.zip");
    let encoded = utf8_percent_encode(&full, FILENAME_STAR);
    format!("attachment; filename=\"{ascii}.zip\"; filename*=UTF-8''{encoded}")
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

fn write_archive(base: &Path, target: &Path, tx: mpsc::Sender<Item>) -> io::Result<()> {
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

/// `/__zip__?path=...`. `head` suppresses the body. Responses close the connection.
pub async fn handle_zip(state: &Arc<AppState>, query: Option<&str>, head: bool) -> Response<Body> {
    let Some(raw) = query_path(query).filter(|p| !p.is_empty()) else {
        return plain(StatusCode::BAD_REQUEST, "Missing path");
    };
    let Ok(base) = state.config.base.canonicalize() else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "Archive failed");
    };
    let target = match security::resolve_under(&base, &raw) {
        Ok(p) => p,
        Err(ResolveError::Invalid) => return plain(StatusCode::BAD_REQUEST, "Invalid path"),
        Err(ResolveError::Escape) => return plain(StatusCode::FORBIDDEN, "Forbidden"),
    };
    if !target.exists() {
        return plain(StatusCode::NOT_FOUND, "Not found");
    }
    let name = target
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONNECTION, "close");
    if let Ok(v) = HeaderValue::from_str(&content_disposition(&name)) {
        builder = builder.header(header::CONTENT_DISPOSITION, v);
    }
    let failed = || plain(StatusCode::INTERNAL_SERVER_ERROR, "Archive failed");

    if head {
        let body = Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed();
        return builder.body(body).unwrap_or_else(|_| failed());
    }

    let Ok(permit) = slots().clone().try_acquire_owned() else {
        let mut resp = plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many archives in progress",
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    };

    let (tx, mut rx) = mpsc::channel::<Item>(CHANNEL_FRAMES);
    let err_tx = tx.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if let Err(e) = write_archive(&base, &target, tx) {
            let _ = err_tx.try_send(Err(e));
        }
    });

    let state = state.clone();
    let stream = futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx)).inspect(move |item| {
        if let Some(data) = item.as_ref().ok().and_then(Frame::data_ref) {
            state.metrics.add_bytes_sent(data.len() as u64);
        }
    });
    builder
        .body(BodyExt::boxed(StreamBody::new(stream)))
        .unwrap_or_else(|_| failed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn crc32_matches_reference_vectors() {
        assert_eq!(crc32_update(0, b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_update(0, b""), 0);
        let whole = crc32_update(0, b"hello world, this is a longer test string!");
        let split = crc32_update(
            crc32_update(0, b"hello world, thi"),
            b"s is a longer test string!",
        );
        assert_eq!(whole, split);
    }

    #[test]
    fn dos_datetime_known_values() {
        let y2000 = UNIX_EPOCH + std::time::Duration::from_secs(946_684_800);
        assert_eq!(dos_datetime(Some(y2000)), (0, (20 << 9) | (1 << 5) | 1));
        assert_eq!(dos_datetime(Some(UNIX_EPOCH)), (0, 0x0021));
        assert_eq!(dos_datetime(None), (0, 0x0021));
    }

    fn build_archive(limit: u64, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = StreamZip::new(Vec::new());
        zip.limit = limit;
        let mut buf = vec![0u8; 7];
        for (name, data) in files {
            zip.add_file(
                name,
                Some(UNIX_EPOCH),
                data.len() as u64,
                &mut Cursor::new(*data),
                &mut buf,
            )
            .unwrap();
        }
        zip.finish().unwrap()
    }

    fn assert_roundtrip(bytes: Vec<u8>, files: &[(&str, &[u8])]) {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("valid archive");
        assert_eq!(archive.len(), files.len());
        for (name, data) in files {
            let mut entry = archive.by_name(name).expect("entry");
            let mut got = Vec::new();
            entry.read_to_end(&mut got).expect("crc-checked read");
            assert_eq!(&got, data);
        }
    }

    #[test]
    fn standard_archive_round_trips() {
        let files: &[(&str, &[u8])] = &[
            ("a.txt", b"alpha"),
            ("dir/b.bin", &[0u8, 1, 2, 3, 255]),
            ("empty", b""),
            ("\u{e9}.txt", b"utf8"),
        ];
        assert_roundtrip(build_archive(ZIP64_LIMIT, files), files);
    }

    #[test]
    fn zip64_structures_round_trip() {
        let files: &[(&str, &[u8])] = &[("x", b"some bytes here"), ("y/z", b"more")];
        assert_roundtrip(build_archive(1, files), files);
    }

    #[test]
    fn empty_archive_is_valid() {
        assert_roundtrip(build_archive(ZIP64_LIMIT, &[]), &[]);
    }

    #[test]
    fn shrinking_file_is_an_error() {
        let mut zip = StreamZip::new(Vec::new());
        let err = zip
            .add_file("f", None, 10, &mut Cursor::new(&b"abc"[..]), &mut [0u8; 4])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn filename_strips_injection_characters() {
        let d = content_disposition("a\"b;c:d\r\ne");
        assert_eq!(d, "attachment; filename=\"abcde.zip\"");
    }

    #[test]
    fn filename_falls_back_to_archive() {
        assert_eq!(
            content_disposition("\";:"),
            "attachment; filename=\"archive.zip\""
        );
        assert_eq!(
            content_disposition(""),
            "attachment; filename=\"archive.zip\""
        );
    }

    #[test]
    fn non_ascii_name_gets_encoded_extension() {
        let d = content_disposition("caf\u{e9}");
        assert!(d.contains("filename=\"caf_.zip\""));
        assert!(d.contains("filename*=UTF-8''caf%C3%A9.zip"));
    }

    #[test]
    fn query_path_decodes_once() {
        assert_eq!(query_path(Some("path=a%20b")).as_deref(), Some("a b"));
        assert_eq!(query_path(Some("x=1&path=a+b")).as_deref(), Some("a b"));
        assert_eq!(query_path(Some("path=%252e")).as_deref(), Some("%2e"));
        assert!(query_path(Some("other=1")).is_none());
        assert!(query_path(None).is_none());
    }

    #[test]
    fn entry_names_use_forward_slashes() {
        let root = Path::new("root");
        let file = root.join("a").join("b.txt");
        assert_eq!(entry_name(root, &file).as_deref(), Some("a/b.txt"));
        assert!(entry_name(root, root).is_none());
    }
}
