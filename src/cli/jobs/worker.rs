//! The detached worker process: runs one command, keeps its record fresh, notices stop
//! requests and records how the job ended.

use super::record::{Direction, Kind, Record, State, label, origin, scrub, valid_id};
use super::store::{Store, now};
use super::tracker::{self, SpeedMeter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const TICK: Duration = Duration::from_millis(250);
const WRITE_EVERY: Duration = Duration::from_secs(1);
/// After a stop request the command gets this long to finish cleanly before the worker
/// records the outcome itself and exits.
pub const GRACE: Duration = Duration::from_secs(10);

pub fn is_worker() -> bool {
    WORKER.get().is_some()
}

struct Worker {
    store: Store,
    id: String,
    kind: Kind,
    rec: Mutex<Record>,
    finished: AtomicBool,
}

static WORKER: OnceLock<Worker> = OnceLock::new();

/// What a command tells the job once its own checks have passed.
pub struct Info {
    pub label: String,
    /// The remote URL of a transfer. Only its origin is ever recorded.
    pub url: Option<String>,
    pub direction: Option<Direction>,
    pub listen: Option<String>,
}

impl Worker {
    fn lock(&self) -> MutexGuard<'_, Record> {
        self.rec.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn publish(&self, rec: &Record) {
        if let Err(e) = self.store.write(rec) {
            // Tracking problems never touch the transfer; say so once and carry on.
            static WARNED: AtomicBool = AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "warning: cannot update the job record: {}",
                    scrub(&e.to_string())
                );
            }
        }
    }

    fn refresh(&self, meter: &mut SpeedMeter, since: &mut Instant) {
        let mut rec = self.lock();
        if !rec.state.is_active() {
            return;
        }
        rec.updated_at = now();
        if !self.kind.is_server() {
            let snap = tracker::snapshot();
            rec.bytes_done = snap.done;
            rec.bytes_total = snap.total;
            if rec.ready_at.is_some() {
                rec.phase = Some(snap.phase);
            }
            rec.speed_bps = meter.sample(snap.epoch, snap.done, since.elapsed());
            *since = Instant::now();
        }
        self.publish(&rec);
    }

    fn reporter(&self) {
        let mut meter = SpeedMeter::new();
        let mut since = Instant::now();
        let mut last_write = Instant::now();
        let mut stopping: Option<Instant> = None;
        while !self.finished.load(Ordering::SeqCst) {
            std::thread::sleep(TICK);
            if stopping.is_none() && self.store.stop_requested(&self.id) {
                stopping = Some(Instant::now());
                tracker::request_cancel();
                let mut rec = self.lock();
                if rec.state.is_active() {
                    rec.state = State::Stopping;
                    rec.updated_at = now();
                    self.publish(&rec);
                }
            }
            if stopping.is_some_and(|at| at.elapsed() > GRACE) {
                self.force_end();
            }
            if last_write.elapsed() >= WRITE_EVERY {
                last_write = Instant::now();
                self.refresh(&mut meter, &mut since);
            }
        }
    }

    /// The command did not wind down in time: record the outcome and end the process. The
    /// partial file and its resume data are left exactly as the last write put them.
    fn force_end(&self) -> ! {
        let (state, text) = if self.kind.is_server() {
            (
                State::Stopped,
                format!(
                    "shutdown did not finish within {}s; the process was ended",
                    GRACE.as_secs()
                ),
            )
        } else {
            (
                State::Interrupted,
                format!(
                    "stopped after {}s; partial data is kept so the same command can resume",
                    GRACE.as_secs()
                ),
            )
        };
        self.conclude(state, text);
        std::process::exit(0);
    }

    fn conclude(&self, state: State, text: String) {
        let mut rec = self.lock();
        if !self.kind.is_server() {
            rec.bytes_done = tracker::snapshot().done;
            rec.bytes_total = tracker::snapshot().total;
        }
        rec.state = state;
        rec.phase = None;
        rec.speed_bps = None;
        rec.updated_at = now();
        rec.result = Some(text.clone());
        self.publish(&rec);
        self.finished.store(true, Ordering::SeqCst);
        eprintln!(
            "{} {}: {text}",
            crate::logging::utc_timestamp(),
            state.name()
        );
    }
}

/// Called by a command when its arguments are valid and, for servers, the socket is bound.
/// Does nothing outside a background worker.
pub fn ready(info: impl FnOnce() -> Info) {
    let Some(w) = WORKER.get() else { return };
    let info = info();
    let mut rec = w.lock();
    rec.label = label(&info.label);
    rec.remote = info.url.as_deref().and_then(origin);
    rec.direction = info.direction;
    rec.listen = info.listen.as_deref().map(super::record::escape_control);
    if rec.state == State::Starting {
        rec.state = State::Running;
    }
    rec.ready_at = Some(now());
    rec.updated_at = now();
    w.publish(&rec);
}

#[cfg(unix)]
fn ignore_hangup() {
    // Registering a handler replaces the default action, which would end the process when
    // the terminal goes away. The handler stays installed after the runtime is dropped.
    if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        rt.block_on(async {
            let _ = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup());
        });
    }
}

#[cfg(not(unix))]
fn ignore_hangup() {}

pub fn run(id: &str, kind: Kind, body: impl FnOnce() -> Result<u8, String>) -> Result<u8, String> {
    if !valid_id(id) {
        return Err(format!("'{id}' is not a job ID"));
    }
    let store = Store::open()?;
    let log = store.log_path(id).display().to_string();
    let rec = Record::new(id, kind, std::process::id(), now(), &log);
    store
        .write(&rec)
        .map_err(|e| format!("cannot write the job record: {e}"))?;
    ignore_hangup();
    let worker = WORKER.get_or_init(|| Worker {
        store,
        id: id.to_owned(),
        kind,
        rec: Mutex::new(rec),
        finished: AtomicBool::new(false),
    });
    let outcome = std::thread::scope(|scope| {
        scope.spawn(|| worker.reporter());
        let outcome = body();
        let cancelled = tracker::cancelled();
        let code = match outcome {
            Ok(0) if kind.is_server() => {
                worker.conclude(State::Stopped, "graceful shutdown completed".to_owned());
                0
            }
            Ok(0) => {
                worker.conclude(State::Completed, "completed".to_owned());
                0
            }
            Ok(n) => {
                worker.conclude(State::Failed, format!("exited with status {n}"));
                n
            }
            Err(_) if cancelled && !kind.is_server() => {
                worker.conclude(
                    State::Interrupted,
                    "interrupted by blaze stop; partial data is kept so the same command can resume"
                        .to_owned(),
                );
                0
            }
            Err(e) => {
                worker.conclude(State::Failed, scrub(&e));
                1
            }
        };
        worker.finished.store(true, Ordering::SeqCst);
        code
    });
    Ok(outcome)
}
