//! Parallel `blaze get`: fixed-size segments pulled by worker threads and written in place.

use super::READ_BUF;
use super::download::{
    Download, MAX_RESTARTS, Meta, parse_content_range, rename_with_retry, sibling,
};
use super::http::{describe_error, header, http_failure, transient_error, transient_status};
use crate::cli::ansi::announce;
use crate::cli::util::{Progress, backoff, human_size};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const SEGMENT: u64 = 8 * 1024 * 1024;
const MIN_SEGMENTED: u64 = 8 * 1024 * 1024;
const SIDECAR_VERSION: u32 = 1;
const SAVE_INTERVAL: Duration = Duration::from_secs(1);

/// Completed segment indexes as half-open `[start, end)` runs.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(super) struct SegMeta {
    version: u32,
    size: u64,
    done: Vec<[u64; 2]>,
}

struct Probe {
    total: u64,
    etag: Option<String>,
    last_modified: Option<String>,
    validator: String,
}

fn segment_count(total: u64) -> u64 {
    total.div_ceil(SEGMENT)
}

/// Inclusive byte range of segment `index`.
fn segment_bounds(index: u64, total: u64) -> (u64, u64) {
    let start = index * SEGMENT;
    (start, (start + SEGMENT).min(total) - 1)
}

fn segments_len(done: &BTreeSet<u64>, total: u64) -> u64 {
    done.iter()
        .map(|&i| {
            let (s, e) = segment_bounds(i, total);
            e - s + 1
        })
        .sum()
}

fn encode_runs(done: &BTreeSet<u64>) -> Vec<[u64; 2]> {
    let mut runs: Vec<[u64; 2]> = Vec::new();
    for &i in done {
        match runs.last_mut() {
            Some(run) if run[1] == i => run[1] = i + 1,
            _ => runs.push([i, i + 1]),
        }
    }
    runs
}

/// `None` when a run is malformed or reaches past the last segment.
fn decode_runs(runs: &[[u64; 2]], count: u64) -> Option<BTreeSet<u64>> {
    let mut done = BTreeSet::new();
    for &[start, end] in runs {
        if start >= end || end > count {
            return None;
        }
        done.extend(start..end);
    }
    Some(done)
}

fn probe(d: &Download<'_>) -> Option<Probe> {
    let mut req = d.agent.head(d.url);
    if let Some(a) = &d.auth {
        req = req.header("Authorization", a);
    }
    let resp = req.call().ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    let total = header(&resp, "content-length")?.parse::<u64>().ok()?;
    if total < MIN_SEGMENTED {
        return None;
    }
    if !header(&resp, "accept-ranges")?
        .to_ascii_lowercase()
        .contains("bytes")
    {
        return None;
    }
    let etag = header(&resp, "etag");
    let last_modified = header(&resp, "last-modified");
    let validator = etag
        .clone()
        .filter(|e| !e.starts_with("W/"))
        .or_else(|| last_modified.clone())?;
    Some(Probe {
        total,
        etag,
        last_modified,
        validator,
    })
}

fn write_at(file: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_all_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut buf, mut offset) = (buf, offset);
        while !buf.is_empty() {
            let n = file.seek_write(buf, offset)?;
            if n == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            buf = &buf[n..];
            offset += n as u64;
        }
        Ok(())
    }
}

/// Written to a temporary file first so an interrupt never leaves a torn sidecar.
fn save_sidecar(d: &Download<'_>, probe: &Probe, file: &File, done: &BTreeSet<u64>) {
    let meta = Meta {
        url: d.url.to_owned(),
        etag: probe.etag.clone(),
        last_modified: probe.last_modified.clone(),
        total: Some(probe.total),
        seg: Some(SegMeta {
            version: SIDECAR_VERSION,
            size: SEGMENT,
            done: encode_runs(done),
        }),
    };
    let Ok(raw) = serde_json::to_vec(&meta) else {
        return;
    };
    let tmp = sibling(&d.meta_path, ".tmp");
    // The data must be on disk before the sidecar claims it is.
    if file.sync_data().is_ok()
        && std::fs::write(&tmp, raw).is_ok()
        && rename_with_retry(&tmp, &d.meta_path).is_err()
    {
        let _ = std::fs::remove_file(&tmp);
    }
}

enum SegError {
    /// The remote file no longer matches the validator.
    Changed,
    Transient {
        msg: String,
        progressed: bool,
    },
    Fatal(String),
}

struct Shared<'a> {
    d: &'a Download<'a>,
    probe: &'a Probe,
    file: File,
    pending: Vec<u64>,
    next: AtomicUsize,
    stop: AtomicBool,
    changed: AtomicBool,
    error: Mutex<Option<String>>,
    done: Mutex<(BTreeSet<u64>, Instant)>,
    progress: Progress,
    retries: u32,
}

impl Shared<'_> {
    fn complete(&self, index: u64) {
        let Ok(mut guard) = self.done.lock() else {
            return;
        };
        guard.0.insert(index);
        if guard.1.elapsed() >= SAVE_INTERVAL {
            guard.1 = Instant::now();
            save_sidecar(self.d, self.probe, &self.file, &guard.0);
        }
    }

    fn fail(&self, msg: String) {
        if let Ok(mut e) = self.error.lock() {
            e.get_or_insert(msg);
        }
        self.stop.store(true, Ordering::SeqCst);
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn sleep(&self, wait: Duration) {
        let end = Instant::now() + wait;
        while !self.stopped() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn fetch(&self, index: u64) -> Result<(), SegError> {
        let (start, end) = segment_bounds(index, self.probe.total);
        let mut req = self
            .d
            .agent
            .get(self.d.url)
            .header("Range", format!("bytes={start}-{end}"))
            .header("If-Range", &self.probe.validator);
        if let Some(a) = &self.d.auth {
            req = req.header("Authorization", a);
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(e) if transient_error(&e) => {
                return Err(SegError::Transient {
                    msg: describe_error(&e),
                    progressed: false,
                });
            }
            Err(e) => return Err(SegError::Fatal(describe_error(&e))),
        };
        match resp.status().as_u16() {
            206 => {}
            200 | 416 => return Err(SegError::Changed),
            code if transient_status(code) => {
                return Err(SegError::Transient {
                    msg: format!("server returned HTTP {code}"),
                    progressed: false,
                });
            }
            code => return Err(SegError::Fatal(http_failure(code, false))),
        }
        let exact = header(&resp, "content-range")
            .and_then(|v| parse_content_range(&v))
            .is_some_and(|(s, e, total)| {
                s == start && e == end && total.is_none_or(|t| t == self.probe.total)
            });
        if !exact {
            return Err(SegError::Changed);
        }

        let mut reader = resp.into_body().into_reader().take(end - start + 1);
        let mut buf = vec![0u8; READ_BUF];
        let mut pos = start;
        let mut counted = 0u64;
        while !self.stopped() {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = write_at(&self.file, &buf[..n], pos) {
                        self.progress.dec(counted);
                        return Err(SegError::Fatal(format!("write failed: {e}")));
                    }
                    pos += n as u64;
                    counted += n as u64;
                    self.progress.inc(n as u64);
                }
                Err(e) => {
                    self.progress.dec(counted);
                    return Err(SegError::Transient {
                        msg: e.to_string(),
                        progressed: counted > 0,
                    });
                }
            }
        }
        if pos != end + 1 {
            self.progress.dec(counted);
            if self.stopped() {
                return Err(SegError::Fatal("stopped".to_owned()));
            }
            return Err(SegError::Transient {
                msg: format!(
                    "connection closed after {} of {}",
                    human_size(pos - start),
                    human_size(end - start + 1)
                ),
                progressed: counted > 0,
            });
        }
        Ok(())
    }

    fn fetch_with_retries(&self, index: u64) {
        let mut fails = 0u32;
        loop {
            match self.fetch(index) {
                Ok(()) => return self.complete(index),
                Err(SegError::Changed) => {
                    self.changed.store(true, Ordering::SeqCst);
                    self.stop.store(true, Ordering::SeqCst);
                    return;
                }
                Err(SegError::Fatal(msg)) => {
                    // A worker interrupted by another's failure reports nothing of its own.
                    if !self.stopped() {
                        self.fail(msg);
                    }
                    return;
                }
                Err(SegError::Transient { msg, progressed }) => {
                    fails = if progressed { 1 } else { fails + 1 };
                    if fails > self.retries {
                        return self.fail(format!(
                            "download failed after {} retries: {msg}",
                            self.retries
                        ));
                    }
                    self.sleep(backoff(fails));
                    if self.stopped() {
                        return;
                    }
                }
            }
        }
    }

    fn worker(&self) {
        while !self.stopped() {
            let slot = self.next.fetch_add(1, Ordering::SeqCst);
            let Some(&index) = self.pending.get(slot) else {
                return;
            };
            self.fetch_with_retries(index);
        }
    }
}

enum Outcome {
    Done,
    Changed,
}

/// Completed segments from a sidecar written by this mode for the same remote file.
fn trusted_progress(d: &Download<'_>, probe: &Probe, count: u64) -> Option<BTreeSet<u64>> {
    if !d.resume || d.part_len() != probe.total {
        return None;
    }
    let meta = d.load_meta()?;
    let seg = meta.seg?;
    let same = meta.url == d.url
        && meta.total == Some(probe.total)
        && meta.etag == probe.etag
        && meta.last_modified == probe.last_modified
        && seg.version == SIDECAR_VERSION
        && seg.size == SEGMENT;
    if same {
        decode_runs(&seg.done, count)
    } else {
        None
    }
}

fn attempt(d: &Download<'_>, probe: &Probe, conns: usize, retries: u32) -> Result<Outcome, String> {
    let count = segment_count(probe.total);
    let done = trusted_progress(d, probe, count).unwrap_or_else(|| {
        d.reset();
        BTreeSet::new()
    });
    let write_err = |e: std::io::Error| format!("cannot write {}: {e}", d.part.display());
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&d.part)
        .map_err(write_err)?;
    file.set_len(probe.total).map_err(write_err)?;
    save_sidecar(d, probe, &file, &done);

    let base = segments_len(&done, probe.total);
    let pending: Vec<u64> = (0..count).filter(|i| !done.contains(i)).collect();
    if base > 0 {
        announce("Resuming", &format!("at {}", human_size(base)));
    }
    let workers = conns.min(pending.len()).max(1);
    let name = d.part.file_name().map_or_else(String::new, |n| {
        let n = n.to_string_lossy();
        n.strip_suffix(".part").unwrap_or(&n).to_owned()
    });
    announce(
        "Downloading",
        &format!("{name} in {workers} parts ({})", human_size(probe.total)),
    );

    let shared = Shared {
        d,
        probe,
        file,
        next: AtomicUsize::new(0),
        stop: AtomicBool::new(false),
        changed: AtomicBool::new(false),
        error: Mutex::new(None),
        done: Mutex::new((done, Instant::now())),
        progress: Progress::new(Some(probe.total), base),
        retries,
        pending,
    };
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| shared.worker());
        }
    });

    let Shared {
        file,
        error,
        changed,
        done,
        mut progress,
        ..
    } = shared;
    let done = done.into_inner().map_or_else(|e| e.into_inner().0, |g| g.0);
    progress.finish(segments_len(&done, probe.total));

    if changed.load(Ordering::SeqCst) {
        d.reset();
        return Ok(Outcome::Changed);
    }
    let failure = error.into_inner().ok().flatten();
    if failure.is_some() || done.len() as u64 != count {
        save_sidecar(d, probe, &file, &done);
        return Err(failure.unwrap_or_else(|| "download interrupted".to_owned()));
    }
    file.sync_data().map_err(|e| format!("write failed: {e}"))?;
    drop(file);
    if d.part_len() != probe.total {
        return Err(format!(
            "downloaded file is {} but the server announced {}",
            human_size(d.part_len()),
            human_size(probe.total)
        ));
    }
    Ok(Outcome::Done)
}

/// Runs the segmented download when the origin qualifies. `Ok(false)` means the caller
/// should use the single-stream path.
pub(super) fn run(d: &Download<'_>, conns: usize, retries: u32) -> Result<bool, String> {
    // A partial from the single-stream path is finished there, never mixed with segments.
    if d.resume
        && d.part_len() > 0
        && d.load_meta()
            .is_some_and(|m| m.url == d.url && m.seg.is_none())
    {
        return Ok(false);
    }
    let mut restarts = 0u32;
    loop {
        let Some(probe) = probe(d) else {
            return Ok(false);
        };
        match attempt(d, &probe, conns, retries)? {
            Outcome::Done => return Ok(true),
            Outcome::Changed => {
                restarts += 1;
                if restarts > MAX_RESTARTS {
                    return Err("server keeps changing the file; giving up".to_owned());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_cover_the_file_exactly() {
        let total = 2 * SEGMENT + 5;
        assert_eq!(segment_count(total), 3);
        assert_eq!(segment_count(2 * SEGMENT), 2);
        assert_eq!(segment_bounds(0, total), (0, SEGMENT - 1));
        assert_eq!(segment_bounds(1, total), (SEGMENT, 2 * SEGMENT - 1));
        assert_eq!(segment_bounds(2, total), (2 * SEGMENT, total - 1));
        let done: BTreeSet<u64> = (0..3).collect();
        assert_eq!(segments_len(&done, total), total);
    }

    #[test]
    fn runs_round_trip() {
        let done: BTreeSet<u64> = [0, 1, 2, 5, 7, 8].into_iter().collect();
        let runs = encode_runs(&done);
        assert_eq!(runs, vec![[0, 3], [5, 6], [7, 9]]);
        assert_eq!(decode_runs(&runs, 9), Some(done));
        assert_eq!(encode_runs(&BTreeSet::new()), Vec::<[u64; 2]>::new());
    }

    #[test]
    fn malformed_runs_are_rejected() {
        assert_eq!(decode_runs(&[[3, 3]], 9), None);
        assert_eq!(decode_runs(&[[4, 2]], 9), None);
        assert_eq!(decode_runs(&[[0, 10]], 9), None);
        assert_eq!(decode_runs(&[], 9), Some(BTreeSet::new()));
    }
}
