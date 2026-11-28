//! Parallel `blaze get`: fixed-size segments pulled by worker threads and written in place.

use super::READ_BUF;
use super::download::{
    Download, MAX_RESTARTS, Meta, allocated, check_free_space, parse_content_range,
    write_atomic_with,
};
use super::error::TransferError;
use super::http::{
    cannot_write, describe_error, describe_io, header, http_failure, retry_hint, transient_error,
    transient_status, write_failure,
};
use super::limits;
use super::pace::Pace;
use super::retry::{jitter, plan_wait, retry_note};
use crate::cli::ansi::announce;
use crate::cli::blocks::{BlockMap, Part};
use crate::cli::runlog;
use crate::cli::util::{Progress, backoff, human_size, transfer_title};
use crate::platform::write_all_at;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
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

pub(super) struct Probe {
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

/// Whether a file of this size is downloaded in parts.
pub(super) fn worth_splitting(total: u64) -> bool {
    total >= MIN_SEGMENTED
}

/// Why a file cannot come in parts. `None` is a file too small to be worth it.
pub(super) type Refusal = Option<&'static str>;

fn probe(d: &Download<'_>) -> Result<Probe, Refusal> {
    let mut req = d.agent.head(d.url);
    if let Some(a) = &d.auth {
        req = req.header("Authorization", a);
    }
    let no_head = Some("the server does not answer a size check (HEAD)");
    let resp = limits::bound(req).call().map_err(|_| no_head)?;
    assess(&resp)
}

/// What the answer to a `HEAD` allows.
pub(super) fn assess(resp: &ureq::http::Response<ureq::Body>) -> Result<Probe, Refusal> {
    if resp.status().as_u16() != 200 {
        return Err(Some("the server does not answer a size check (HEAD)"));
    }
    let total = header(resp, "content-length")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or(Some("the server does not say how big the file is"))?;
    if total < MIN_SEGMENTED {
        return Err(None);
    }
    if !header(resp, "accept-ranges").is_some_and(|v| v.to_ascii_lowercase().contains("bytes")) {
        return Err(Some(
            "the server does not offer parts of a file (no Accept-Ranges)",
        ));
    }
    let etag = header(resp, "etag");
    let last_modified = header(resp, "last-modified");
    let validator = etag
        .clone()
        .filter(|e| !e.starts_with("W/"))
        .or_else(|| last_modified.clone())
        .ok_or(Some(
            "the server sends no ETag or Last-Modified, so parts could not be matched safely",
        ))?;
    Ok(Probe {
        total,
        etag,
        last_modified,
        validator,
    })
}

/// Says why a download that asked for several connections uses one.
fn one_connection(why: &str) {
    announce("Note", &format!("one connection: {why}"));
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
    // The data must be on disk before the sidecar claims it is. A save that fails only
    // costs the segments finished since the previous one.
    if file.sync_data().is_ok() {
        let _ = write_atomic_with(&d.meta_path, |f| f.write_all(&raw));
    }
}

enum SegError {
    /// The remote file no longer matches the validator.
    Changed,
    Transient {
        msg: String,
        progressed: bool,
        retry_after: Option<Duration>,
    },
    Fatal(TransferError),
}

struct Shared<'a> {
    d: &'a Download<'a>,
    probe: &'a Probe,
    file: File,
    pending: Mutex<VecDeque<u64>>,
    /// Parts being fetched, which may yet come back to the queue.
    in_flight: AtomicUsize,
    pace: Mutex<Pace>,
    stop: AtomicBool,
    changed: AtomicBool,
    error: Mutex<Option<TransferError>>,
    /// Set when a worker gave up on a transient failure, which fewer connections may avoid.
    retry_fewer: AtomicBool,
    done: Mutex<(BTreeSet<u64>, Instant)>,
    progress: Progress,
    map: std::sync::Arc<BlockMap>,
    retries: u32,
    /// No worker starts a request before this instant. Set by a server-directed wait.
    cooldown: Mutex<Option<Instant>>,
}

impl Shared<'_> {
    fn extend_cooldown(&self, until: Instant) {
        let mut guard = self
            .cooldown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none_or(|c| c < until) {
            *guard = Some(until);
        }
    }

    /// Holds the worker back while the shared cooldown runs, then adds its own jitter so
    /// the workers do not resume in one burst.
    fn await_cooldown(&self) {
        let until = *self
            .cooldown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(until) = until.filter(|u| *u > Instant::now()) {
            self.sleep(until.saturating_duration_since(Instant::now()));
            self.sleep(jitter());
        }
    }

    fn mark(&self, index: u64, part: Part) {
        self.map
            .set(usize::try_from(index).unwrap_or(usize::MAX), part);
    }

    fn pace(&self) -> std::sync::MutexGuard<'_, Pace> {
        self.pace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The live count, under the bar and in the run log.
    fn show_connections(&self, limit: usize) {
        self.progress.set_note(&format!(
            "{limit} connection{}",
            if limit == 1 { "" } else { "s" }
        ));
        runlog::note(&format!("connections now {limit}"));
    }

    fn complete(&self, index: u64) {
        let grown = self.pace().succeeded();
        if let Some(limit) = grown {
            announce("More connections", &format!("trying {limit}"));
            self.show_connections(limit);
        }
        self.mark(index, Part::Done);
        let Ok(mut guard) = self.done.lock() else {
            return;
        };
        guard.0.insert(index);
        if guard.1.elapsed() >= SAVE_INTERVAL {
            guard.1 = Instant::now();
            save_sidecar(self.d, self.probe, &self.file, &guard.0);
        }
    }

    fn fail(&self, err: TransferError) {
        if let Ok(mut e) = self.error.lock() {
            e.get_or_insert(err);
        }
        self.stop.store(true, Ordering::SeqCst);
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst) || crate::cli::jobs::tracker::cancelled()
    }

    fn sleep(&self, wait: Duration) {
        let end = Instant::now() + wait;
        while !self.stopped() && Instant::now() < end && limits::check().is_ok() {
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
        let resp = match limits::bound(req).call() {
            Ok(r) => r,
            Err(e) if transient_error(&e) => {
                return Err(SegError::Transient {
                    msg: describe_error(&e),
                    progressed: false,
                    retry_after: None,
                });
            }
            Err(e) => return Err(SegError::Fatal(TransferError::Network(describe_error(&e)))),
        };
        match resp.status().as_u16() {
            206 => {}
            200 | 416 => return Err(SegError::Changed),
            code if transient_status(code) => {
                return Err(SegError::Transient {
                    msg: format!("server returned HTTP {code}"),
                    progressed: false,
                    retry_after: retry_hint(&resp, code),
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
            match reader.read(&mut buf[..self.d.read_len()]) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(why) = self.d.pace(n) {
                        self.progress.dec(counted);
                        return Err(SegError::Fatal(why));
                    }
                    if let Err(e) = write_all_at(&self.file, &buf[..n], pos) {
                        self.progress.dec(counted);
                        return Err(SegError::Fatal(write_failure(&e)));
                    }
                    pos += n as u64;
                    counted += n as u64;
                    self.progress.inc(n as u64);
                }
                Err(e) => {
                    self.progress.dec(counted);
                    if let Err(why) = limits::check() {
                        return Err(SegError::Fatal(why));
                    }
                    return Err(SegError::Transient {
                        msg: describe_io(&e),
                        progressed: counted > 0,
                        retry_after: None,
                    });
                }
            }
        }
        if pos != end + 1 {
            self.progress.dec(counted);
            if self.stopped() {
                return Err(SegError::Fatal(TransferError::Interrupted(
                    "stopped".to_owned(),
                )));
            }
            return Err(SegError::Transient {
                msg: format!(
                    "connection closed after {} of {}",
                    human_size(pos - start),
                    human_size(end - start + 1)
                ),
                progressed: counted > 0,
                retry_after: None,
            });
        }
        Ok(())
    }

    fn fetch_with_retries(&self, index: u64) {
        let mut fails = 0u32;
        loop {
            self.await_cooldown();
            if self.stopped() {
                return;
            }
            if let Err(why) = limits::check() {
                return self.fail(why);
            }
            self.mark(index, Part::Arriving);
            let fetched = self.fetch(index);
            if fetched.is_err() {
                self.mark(index, Part::Waiting);
            }
            match fetched {
                Ok(()) => return self.complete(index),
                Err(SegError::Changed) => {
                    self.changed.store(true, Ordering::SeqCst);
                    self.stop.store(true, Ordering::SeqCst);
                    return;
                }
                Err(SegError::Fatal(err)) => {
                    // A worker interrupted by another's failure reports nothing of its own.
                    if !self.stopped() {
                        self.fail(err);
                    }
                    return;
                }
                Err(SegError::Transient {
                    msg,
                    progressed,
                    retry_after,
                }) => {
                    runlog::note(&format!("part {index}: {msg}"));
                    // The connection just added did not fit: give it up and requeue the part.
                    let without = self.pace().failed();
                    if let Some(limit) = without {
                        announce("Fewer connections", &format!("{msg}; back to {limit}"));
                        self.show_connections(limit);
                        if let Ok(mut pending) = self.pending.lock() {
                            pending.push_front(index);
                        }
                        return;
                    }
                    fails = if progressed { 1 } else { fails + 1 };
                    if fails > self.retries {
                        self.retry_fewer.store(true, Ordering::SeqCst);
                        return self.fail(TransferError::Network(format!(
                            "download failed after {} retries: {msg}",
                            self.retries
                        )));
                    }
                    let wait = match plan_wait(fails, retry_after, jitter()) {
                        Ok(w) => w,
                        Err(why) => {
                            return self.fail(TransferError::Network(format!(
                                "download failed: {msg}; {why}"
                            )));
                        }
                    };
                    if let Err(why) = limits::fits(wait) {
                        return self.fail(why);
                    }
                    if let Some(h) = retry_after {
                        announce(
                            "Retrying",
                            &format!("{}: {msg}", retry_note(wait, Some(h), fails, self.retries)),
                        );
                        self.extend_cooldown(Instant::now() + backoff(fails).max(h));
                    }
                    crate::cli::jobs::tracker::set_phase(crate::cli::jobs::Phase::Retrying);
                    self.sleep(wait);
                    if self.stopped() {
                        return;
                    }
                }
            }
        }
    }

    fn worker(&self, id: usize) {
        while !self.stopped() {
            let allowed = id < self.pace().limit();
            let next = {
                let Ok(mut pending) = self.pending.lock() else {
                    return;
                };
                if pending.is_empty() && self.in_flight.load(Ordering::SeqCst) == 0 {
                    return;
                }
                let next = if allowed { pending.pop_front() } else { None };
                if next.is_some() {
                    self.in_flight.fetch_add(1, Ordering::SeqCst);
                }
                next
            };
            match next {
                Some(index) => {
                    self.fetch_with_retries(index);
                    self.in_flight.fetch_sub(1, Ordering::SeqCst);
                }
                // Waiting for room, or for a part that may come back.
                None => std::thread::sleep(Duration::from_millis(50)),
            }
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

fn attempt(
    d: &Download<'_>,
    probe: &Probe,
    pace: Pace,
    requested_workers: usize,
    retries: u32,
    first: bool,
) -> Result<Outcome, Failure> {
    let count = segment_count(probe.total);
    let done = trusted_progress(d, probe, count).unwrap_or_else(|| {
        d.reset();
        BTreeSet::new()
    });
    check_free_space(&d.part, probe.total.saturating_sub(allocated(&d.part)))?;
    let write_err = |e: std::io::Error| cannot_write(&d.part, &e);
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
    if first && base > 0 {
        crate::usage::trace::note("resumed", true);
        announce("Resuming", &format!("at {}", human_size(base)));
    }
    let conns = pace.limit();
    // Idle workers wait for the limit to grow towards what was asked.
    let workers = requested_workers.min(pending.len()).max(1);
    let name = d.part.file_name().map_or_else(String::new, |n| {
        let n = n.to_string_lossy();
        n.strip_suffix(".part").unwrap_or(&n).to_owned()
    });
    if first {
        announce(
            "Downloading",
            &format!(
                "{name} in {} parts ({})",
                conns.min(workers),
                human_size(probe.total)
            ),
        );
    }

    let map = std::sync::Arc::new(BlockMap::new(
        usize::try_from(count).unwrap_or(0),
        done.iter().filter_map(|&i| usize::try_from(i).ok()),
    ));
    let shared = Shared {
        d,
        probe,
        file,
        in_flight: AtomicUsize::new(0),
        pace: Mutex::new(pace),
        stop: AtomicBool::new(false),
        changed: AtomicBool::new(false),
        error: Mutex::new(None),
        retry_fewer: AtomicBool::new(false),
        done: Mutex::new((done, Instant::now())),
        progress: Progress::titled(&transfer_title("↓", &d.part), Some(probe.total), base),
        map: map.clone(),
        retries,
        cooldown: Mutex::new(None),
        pending: Mutex::new(pending.into_iter().collect()),
    };
    shared.progress.show_map(&map);
    shared.show_connections(conns.min(workers));
    std::thread::scope(|scope| {
        let shared = &shared;
        for id in 0..workers {
            scope.spawn(move || shared.worker(id));
        }
    });

    let (reached, patience) = {
        let pace = shared.pace();
        (pace.limit(), pace.patience())
    };
    let Shared {
        file,
        error,
        retry_fewer,
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
        return Err(Failure {
            retry_fewer: retry_fewer.load(Ordering::SeqCst),
            reached,
            patience,
            err: failure
                .unwrap_or_else(|| TransferError::Interrupted("download interrupted".to_owned())),
        });
    }
    file.sync_data().map_err(|e| write_failure(&e))?;
    drop(file);
    if d.part_len() != probe.total {
        return Err(TransferError::Unstable(format!(
            "downloaded file is {} but the server announced {}",
            human_size(d.part_len()),
            human_size(probe.total)
        ))
        .into());
    }
    Ok(Outcome::Done)
}

/// Why an attempt ended. `retry_fewer` marks a transient failure that a smaller number of
/// connections may get past, such as a server capping connections per client.
struct Failure {
    err: TransferError,
    retry_fewer: bool,
    /// The connection count and patience reached, to continue from.
    reached: usize,
    patience: usize,
}

impl From<TransferError> for Failure {
    fn from(err: TransferError) -> Self {
        Self {
            err,
            retry_fewer: false,
            reached: 1,
            patience: 0,
        }
    }
}

/// 32, 16, 8, 4, 2, 1.
fn fewer(conns: usize) -> usize {
    (conns / 2).max(1)
}

/// Runs the segmented download when the origin qualifies. `Ok(false)` means the caller
/// should use the single-stream path.
pub(super) fn run(d: &Download<'_>, conns: usize, retries: u32) -> Result<bool, TransferError> {
    // A partial from the single-stream path is finished there, never mixed with segments.
    if d.resume
        && d.part_len() > 0
        && d.load_meta()
            .is_some_and(|m| m.url == d.url && m.seg.is_none())
    {
        one_connection("finishing a partial file that was started that way");
        return Ok(false);
    }
    let requested = conns;
    let mut restarts = 0u32;
    let mut conns = conns;
    let mut patience = 0;
    loop {
        limits::check()?;
        let probe = match probe(d) {
            Ok(probe) => probe,
            Err(why) => {
                if let Some(why) = why {
                    one_connection(why);
                }
                return Ok(false);
            }
        };
        let pace = Pace::new(conns, requested).with_patience(patience);
        let outcome = match attempt(d, &probe, pace, requested, retries, restarts == 0) {
            Ok(outcome) => outcome,
            // Finished segments are kept in the sidecar, so the next attempt carries on.
            Err(f) if f.retry_fewer && f.reached > 1 => {
                let next = fewer(f.reached);
                announce(
                    "Fewer connections",
                    &format!("{}; trying {next} instead of {}", f.err, f.reached),
                );
                conns = next;
                patience = f.patience * 2;
                continue;
            }
            Err(f) => return Err(f.err),
        };
        match outcome {
            Outcome::Done => return Ok(true),
            Outcome::Changed => {
                restarts += 1;
                if restarts > MAX_RESTARTS {
                    // A server that advertises ranges yet answers 200 looks the same as a file that
                    // keeps changing; the single-stream path copes with both.
                    d.reset();
                    return Ok(false);
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
    fn connections_halve_down_to_one() {
        let steps: Vec<usize> =
            std::iter::successors(Some(32), |&n| (n > 1).then(|| fewer(n))).collect();
        assert_eq!(steps, [32, 16, 8, 4, 2, 1]);
        assert_eq!(fewer(1), 1);
        assert_eq!(fewer(7), 3);
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
