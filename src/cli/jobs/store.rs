//! The per-user job registry: a private directory holding `<id>.json` (the record, replaced
//! atomically), `<id>.log` (the worker's output) and `<id>.stop` (a stop request).

use super::record::{Record, SCHEMA_VERSION, valid_id};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Finished jobs stay inspectable this long after their last update.
pub const RETENTION_SECS: u64 = 24 * 60 * 60;
/// At most this many finished jobs are kept; the oldest go first.
pub const MAX_FINISHED: usize = 100;
/// Leftover temporary files and unclaimed logs older than this are removed.
const ORPHAN_SECS: u64 = 60 * 60;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Where the registry lives. `BLAZE_STATE_DIR` wins; otherwise the platform's per-user
/// state location. Taking the lookups as arguments keeps this testable.
pub fn resolve_dir(
    env: impl Fn(&str) -> Option<OsString>,
    windows: bool,
    macos: bool,
) -> Result<PathBuf, String> {
    let set = |name: &str| env(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(dir) = set("BLAZE_STATE_DIR") {
        return Ok(dir.join("jobs"));
    }
    let base = if windows {
        set("LOCALAPPDATA")
            .ok_or("cannot find the per-user data folder: LOCALAPPDATA is not set")?
    } else if macos {
        set("HOME")
            .ok_or("cannot find the home folder: HOME is not set")?
            .join("Library/Application Support")
    } else if let Some(xdg) = set("XDG_STATE_HOME") {
        xdg
    } else {
        set("HOME")
            .ok_or("cannot find the home folder: HOME is not set")?
            .join(".local/state")
    };
    Ok(base.join("blazeserve").join("jobs"))
}

fn private_file(create_new: bool) -> OpenOptions {
    let mut o = OpenOptions::new();
    o.write(true);
    if create_new {
        o.create_new(true);
    } else {
        o.create(true).append(true);
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub struct Listing {
    pub records: Vec<Record>,
    /// Record files that could not be understood and were left out.
    pub skipped: usize,
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open() -> Result<Self, String> {
        let dir = resolve_dir(
            |k| std::env::var_os(k),
            cfg!(windows),
            cfg!(target_os = "macos"),
        )?;
        Self::at(dir)
    }

    pub fn at(dir: PathBuf) -> Result<Self, String> {
        create_private_dir(&dir)
            .map_err(|e| format!("cannot use the job store {}: {e}", dir.display()))?;
        Ok(Self { dir })
    }

    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, id: &str, ext: &str) -> PathBuf {
        self.dir.join(format!("{id}.{ext}"))
    }

    pub fn log_path(&self, id: &str) -> PathBuf {
        self.path(id, "log")
    }

    /// Picks an unused ID by creating its log file, so two launches never share one.
    pub fn reserve(&self) -> Result<(String, std::fs::File), String> {
        for _ in 0..16 {
            let mut raw = [0u8; 4];
            getrandom::fill(&mut raw).map_err(|e| format!("cannot create a job ID: {e}"))?;
            let id = crate::cli::util::hex(&raw);
            if self.path(&id, "json").exists() {
                continue;
            }
            match private_file(true).open(self.log_path(&id)) {
                Ok(file) => return Ok((id, file)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("cannot create a job log: {e}")),
            }
        }
        Err("cannot find a free job ID".to_owned())
    }

    /// Publishes a complete record: written beside the target, then renamed over it, so a
    /// reader sees the old document or the new one and never half of either.
    pub fn write(&self, rec: &Record) -> std::io::Result<()> {
        let raw = serde_json::to_vec(rec).map_err(std::io::Error::other)?;
        let tmp = self
            .dir
            .join(format!(".{}.{}.tmp", rec.id, std::process::id()));
        let result = (|| {
            let mut o = OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let mut f = o.open(&tmp)?;
            f.write_all(&raw)?;
            f.sync_all()?;
            drop(f);
            rename_over(&tmp, &self.path(&rec.id, "json"))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// `Ok(None)` when the job has no record.
    pub fn read(&self, id: &str) -> Result<Option<Record>, String> {
        if !valid_id(id) {
            return Err(format!("'{id}' is not a job ID"));
        }
        match read_record(&self.path(id, "json")) {
            Ok(r) => Ok(Some(r)),
            Err(ReadError::Missing) => Ok(None),
            Err(ReadError::Invalid(why)) => {
                Err(format!("the record of job {id} is unusable: {why}"))
            }
            Err(ReadError::Io(e)) => Err(format!("cannot read the record of job {id}: {e}")),
        }
    }

    pub fn list(&self) -> Result<Listing, String> {
        let entries = std::fs::read_dir(&self.dir)
            .map_err(|e| format!("cannot read the job store {}: {e}", self.dir.display()))?;
        let mut records = Vec::new();
        let mut skipped = 0;
        for entry in entries {
            let entry = entry
                .map_err(|e| format!("cannot read the job store {}: {e}", self.dir.display()))?;
            let path = entry.path();
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if path.extension().is_none_or(|e| e != "json") || !valid_id(stem) {
                continue;
            }
            match read_record(&path) {
                Ok(r) if r.id == stem => records.push(r),
                Ok(_) | Err(ReadError::Invalid(_) | ReadError::Io(_)) => skipped += 1,
                Err(ReadError::Missing) => {}
            }
        }
        records.sort_by(|a, b| b.started_at.cmp(&a.started_at).then(a.id.cmp(&b.id)));
        Ok(Listing { records, skipped })
    }

    pub fn request_stop(&self, id: &str) -> std::io::Result<()> {
        match private_file(true).open(self.path(id, "stop")) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn stop_requested(&self, id: &str) -> bool {
        self.path(id, "stop").exists()
    }

    pub fn remove(&self, id: &str) {
        for ext in ["json", "log", "stop"] {
            let _ = std::fs::remove_file(self.path(id, ext));
        }
    }

    pub fn remove_stop(&self, id: &str) {
        let _ = std::fs::remove_file(self.path(id, "stop"));
    }

    /// Drops expired and surplus finished jobs, unreadable records past retention and
    /// stray temporary files. Best effort: a failure here never blocks a command.
    pub fn sweep(&self, now: u64) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut finished = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let age = file_age(&path, now);
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if name.starts_with('.') && name.ends_with(".tmp") {
                if age > ORPHAN_SECS {
                    let _ = std::fs::remove_file(&path);
                }
            } else if path.extension().is_some_and(|e| e == "json") && valid_id(stem) {
                match read_record(&path) {
                    Ok(r) => {
                        let r = r.effective(now);
                        if !r.state.is_active() {
                            finished.push((r.updated_at, r.id));
                        }
                    }
                    Err(ReadError::Invalid(_)) if age > RETENTION_SECS => self.remove(stem),
                    Err(_) => {}
                }
            } else if path.extension().is_some_and(|e| e == "log" || e == "stop")
                && valid_id(stem)
                && age > ORPHAN_SECS
                && !self.path(stem, "json").exists()
            {
                let _ = std::fs::remove_file(&path);
            }
        }
        finished.sort_unstable_by(|a, b| b.cmp(a));
        for (i, (updated, id)) in finished.iter().enumerate() {
            if now.saturating_sub(*updated) > RETENTION_SECS || i >= MAX_FINISHED {
                self.remove(id);
            }
        }
    }
}

fn file_age(path: &Path, now: u64) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| now.saturating_sub(d.as_secs()))
}

/// Windows can briefly refuse a rename while a scanner or a reader holds the target.
fn rename_over(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut last = None;
    for attempt in 0..8u64 {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(20 * (attempt + 1)));
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("rename failed")))
}

enum ReadError {
    Missing,
    Invalid(String),
    Io(std::io::Error),
}

fn read_record(path: &Path) -> Result<Record, ReadError> {
    let mut last = None;
    for attempt in 0..5u64 {
        match std::fs::read(path) {
            Ok(raw) => {
                let rec: Record =
                    serde_json::from_slice(&raw).map_err(|e| ReadError::Invalid(e.to_string()))?;
                if rec.version != SCHEMA_VERSION {
                    return Err(ReadError::Invalid(format!(
                        "schema version {} is not supported",
                        rec.version
                    )));
                }
                return Ok(rec);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReadError::Missing),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(10 * (attempt + 1)));
            }
            Err(e) => return Err(ReadError::Io(e)),
        }
    }
    Err(ReadError::Io(
        last.unwrap_or_else(|| std::io::Error::other("read failed")),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::record::{Kind, State};
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::at(dir.path().join("jobs")).unwrap();
        (dir, s)
    }

    fn rec(id: &str, state: State, updated: u64) -> Record {
        let mut r = Record::new(id, Kind::Get, 1, updated, "log");
        r.state = state;
        r.updated_at = updated;
        r
    }

    #[test]
    fn directory_follows_the_platform_conventions() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let p = |windows, macos, pairs| resolve_dir(env(pairs), windows, macos).unwrap();
        assert_eq!(
            p(true, false, &[("LOCALAPPDATA", "/l")]),
            PathBuf::from("/l/blazeserve/jobs")
        );
        assert_eq!(
            p(false, true, &[("HOME", "/h")]),
            PathBuf::from("/h/Library/Application Support/blazeserve/jobs")
        );
        assert_eq!(
            p(false, false, &[("HOME", "/h"), ("XDG_STATE_HOME", "/x")]),
            PathBuf::from("/x/blazeserve/jobs")
        );
        assert_eq!(
            p(false, false, &[("HOME", "/h")]),
            PathBuf::from("/h/.local/state/blazeserve/jobs")
        );
        assert_eq!(
            p(
                true,
                false,
                &[("BLAZE_STATE_DIR", "/s"), ("LOCALAPPDATA", "/l")]
            ),
            PathBuf::from("/s/jobs")
        );
        assert!(resolve_dir(env(&[]), false, false).is_err());
    }

    #[test]
    fn written_records_round_trip_and_leave_no_temporary_file() {
        let (_d, s) = store();
        let r = rec("0123abcd", State::Running, 10);
        s.write(&r).unwrap();
        assert_eq!(s.read("0123abcd").unwrap(), Some(r.clone()));
        let mut r2 = r;
        r2.bytes_done = 99;
        s.write(&r2).unwrap();
        assert_eq!(s.read("0123abcd").unwrap().unwrap().bytes_done, 99);
        let names: Vec<_> = std::fs::read_dir(s.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["0123abcd.json"]);
    }

    #[test]
    fn readers_never_see_a_partial_record_while_a_writer_replaces_it() {
        let (_d, s) = store();
        let s = std::sync::Arc::new(s);
        s.write(&rec("0123abcd", State::Running, 1)).unwrap();
        let writer = {
            let s = s.clone();
            std::thread::spawn(move || {
                for i in 0..200 {
                    let mut r = rec("0123abcd", State::Running, i);
                    r.label = "x".repeat(2000);
                    s.write(&r).unwrap();
                }
            })
        };
        for _ in 0..400 {
            assert!(s.read("0123abcd").unwrap().is_some());
        }
        writer.join().unwrap();
    }

    #[test]
    fn missing_job_is_none_and_bad_id_is_an_error() {
        let (_d, s) = store();
        assert_eq!(s.read("0123abcd").unwrap(), None);
        assert!(s.read("../escape").is_err());
    }

    #[test]
    fn invalid_and_future_records_are_skipped_not_fatal() {
        let (_d, s) = store();
        s.write(&rec("aaaaaaaa", State::Running, 5)).unwrap();
        std::fs::write(s.dir().join("bbbbbbbb.json"), b"{ not json").unwrap();
        let mut future = rec("cccccccc", State::Running, 5);
        future.version = SCHEMA_VERSION + 1;
        std::fs::write(
            s.dir().join("cccccccc.json"),
            serde_json::to_vec(&future).unwrap(),
        )
        .unwrap();
        std::fs::write(s.dir().join("notes.json"), b"{}").unwrap();
        let l = s.list().unwrap();
        assert_eq!(l.records.len(), 1);
        assert_eq!(l.skipped, 2);
        assert!(s.read("bbbbbbbb").unwrap_err().contains("unusable"));
    }

    #[test]
    fn an_unreadable_store_is_an_error_not_an_empty_list() {
        let (d, s) = store();
        std::fs::remove_dir_all(s.dir()).unwrap();
        std::fs::write(s.dir(), b"a file where the folder should be").unwrap();
        assert!(s.list().is_err());
        assert!(Store::at(s.dir().join("nested")).is_err());
        drop(d);
    }

    #[test]
    fn reserved_ids_are_unique_and_valid() {
        let (_d, s) = store();
        let a = s.reserve().unwrap().0;
        let b = s.reserve().unwrap().0;
        assert!(valid_id(&a) && valid_id(&b) && a != b);
        assert!(s.log_path(&a).exists());
    }

    #[test]
    fn stop_requests_are_idempotent() {
        let (_d, s) = store();
        assert!(!s.stop_requested("0123abcd"));
        s.request_stop("0123abcd").unwrap();
        s.request_stop("0123abcd").unwrap();
        assert!(s.stop_requested("0123abcd"));
        s.remove_stop("0123abcd");
        assert!(!s.stop_requested("0123abcd"));
    }

    #[test]
    fn sweep_expires_finished_jobs_but_keeps_active_and_recent_ones() {
        let (_d, s) = store();
        let now = 10_000_000;
        s.write(&rec("00000001", State::Completed, now - RETENTION_SECS - 1))
            .unwrap();
        s.write(&rec("00000002", State::Completed, now - RETENTION_SECS))
            .unwrap();
        s.write(&rec("00000003", State::Running, now - 5)).unwrap();
        // Dead for a day: reported failed, then expired like any finished job.
        s.write(&rec("00000004", State::Running, now - RETENTION_SECS - 100))
            .unwrap();
        std::fs::write(s.log_path("00000001"), b"x").unwrap();
        s.sweep(now);
        let ids: Vec<_> = s
            .list()
            .unwrap()
            .records
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"00000002".to_owned()) && ids.contains(&"00000003".to_owned()));
        assert!(!s.log_path("00000001").exists());
    }

    #[test]
    fn sweep_caps_the_number_of_finished_jobs() {
        let (_d, s) = store();
        let now = 10_000_000;
        for i in 0..(MAX_FINISHED + 5) {
            let id = format!("{i:08x}");
            s.write(&rec(
                &id,
                State::Completed,
                now - 10 - (MAX_FINISHED + 5 - i) as u64,
            ))
            .unwrap();
        }
        s.sweep(now);
        let l = s.list().unwrap();
        assert_eq!(l.records.len(), MAX_FINISHED);
        assert!(l.records.iter().all(|r| r.id.as_str() >= "00000005"));
    }

    #[cfg(unix)]
    #[test]
    fn files_and_directory_are_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, s) = store();
        s.write(&rec("0123abcd", State::Running, 1)).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(s.dir()), 0o700);
        assert_eq!(mode(&s.dir().join("0123abcd.json")), 0o600);
        let (id, _) = s.reserve().unwrap();
        assert_eq!(mode(&s.log_path(&id)), 0o600);
    }
}
