//! `blaze status`: a read-only view of the job registry.

use super::record::{Kind, Record, SCHEMA_VERSION, valid_id};
use super::store::{RETENTION_SECS, Store, now};
use crate::cli::util::human_size;
use clap::Args;
use serde::Serialize;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Show one job in full, including its result and log location
    pub job: Option<String>,
    /// Keep refreshing until Ctrl+C. The jobs keep running
    #[arg(long, conflicts_with = "json")]
    pub watch: bool,
    /// Print one JSON snapshot instead of text
    #[arg(long)]
    pub json: bool,
    /// Include finished jobs that are still kept
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug)]
pub struct Snapshot {
    pub records: Vec<Record>,
    pub skipped: usize,
    /// Finished jobs left out of an active-only list.
    pub hidden: usize,
}

pub fn snapshot(store: &Store, at: u64, job: Option<&str>, all: bool) -> Result<Snapshot, String> {
    if let Some(id) = job {
        if !valid_id(id) {
            return Err(format!(
                "'{id}' is not a job ID (expected 8 characters, 0-9 and a-f)"
            ));
        }
        let rec = store.read(id)?.ok_or_else(|| {
            format!(
                "no job {id}: the ID is wrong, or the job finished more than {} hours ago and was removed",
                RETENTION_SECS / 3600
            )
        })?;
        return Ok(Snapshot {
            records: vec![rec.effective(at)],
            skipped: 0,
            hidden: 0,
        });
    }
    let listing = store.list()?;
    let all_records: Vec<Record> = listing
        .records
        .into_iter()
        .map(|r| r.effective(at))
        .collect();
    let total = all_records.len();
    let records: Vec<Record> = all_records
        .into_iter()
        .filter(|r| all || r.state.is_active())
        .collect();
    Ok(Snapshot {
        hidden: total - records.len(),
        records,
        skipped: listing.skipped,
    })
}

#[derive(Serialize)]
struct JobView<'a> {
    #[serde(flatten)]
    record: &'a Record,
    percent: Option<f64>,
    eta_seconds: Option<u64>,
    uptime_seconds: Option<u64>,
}

#[derive(Serialize)]
struct JsonSnapshot<'a> {
    version: u32,
    generated_at: u64,
    jobs: Vec<JobView<'a>>,
    skipped_records: usize,
}

pub fn to_json(snap: &Snapshot, at: u64) -> Result<String, String> {
    let jobs = snap
        .records
        .iter()
        .map(|r| JobView {
            record: r,
            percent: r.percent().map(|p| (p * 10.0).round() / 10.0),
            eta_seconds: r.eta_secs(),
            uptime_seconds: uptime(r, at),
        })
        .collect();
    serde_json::to_string_pretty(&JsonSnapshot {
        version: SCHEMA_VERSION,
        generated_at: at,
        jobs,
        skipped_records: snap.skipped,
    })
    .map_err(|e| e.to_string())
}

fn uptime(r: &Record, at: u64) -> Option<u64> {
    (r.kind.is_server() && r.state.is_active())
        .then(|| at.saturating_sub(r.ready_at.unwrap_or(r.started_at)))
}

pub fn span(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m {:02}s", secs / 60, secs % 60),
        _ => format!("{}h {:02}m", secs / 3600, secs % 3600 / 60),
    }
}

pub(super) fn describe(r: &Record, at: u64, detail: bool) -> String {
    let mut out = String::new();
    let mut head = format!("{}  {}  {}", r.id, r.kind.name(), r.state.name());
    if let Some(p) = r.phase {
        head.push_str(&format!(" ({})", p.name()));
    }
    out.push_str(&format!("{head}  pid {}\n", r.pid));

    let mut who = if r.label.is_empty() {
        "(starting)".to_owned()
    } else {
        r.label.clone()
    };
    if let Some(d) = r.direction {
        who.push_str(&format!("  {}", d.name()));
    }
    if let Some(remote) = &r.remote {
        let word = if r.kind == Kind::Put { "to" } else { "from" };
        who.push_str(&format!("  {word} {remote}"));
    }
    if let Some(listen) = &r.listen {
        who.push_str(&format!("  listening on {listen}"));
    }
    out.push_str(&format!("  {who}\n"));

    if r.kind.is_server() {
        if let Some(up) = uptime(r, at) {
            out.push_str(&format!("  up {}\n", span(up)));
        }
    } else if r.ready_at.is_some() || r.bytes_done > 0 {
        let size = match r.bytes_total {
            Some(t) => format!("{} of {}", human_size(r.bytes_done), human_size(t)),
            None => format!("{} of unknown size", human_size(r.bytes_done)),
        };
        let mut line = size;
        if let Some(p) = r.percent() {
            line.push_str(&format!(" ({p:.0}%)"));
        }
        if r.state.is_active() {
            match r.speed_bps {
                Some(s) => line.push_str(&format!("  {}/s", human_size(s))),
                None => line.push_str("  speed unknown"),
            }
            match r.eta_secs() {
                Some(e) => line.push_str(&format!("  ETA {}", span(e))),
                None => line.push_str("  ETA unknown"),
            }
        }
        out.push_str(&format!("  {line}\n"));
    }

    let ago = |t: u64| span(at.saturating_sub(t));
    out.push_str(&format!(
        "  started {} ({} ago), updated {} ago\n",
        crate::logging::format_utc(r.started_at),
        ago(r.started_at),
        ago(r.updated_at)
    ));
    if (detail || !r.state.is_active())
        && let Some(result) = &r.result
    {
        out.push_str(&format!("  result: {result}\n"));
    }
    if detail {
        out.push_str(&format!("  log: {}\n", r.log));
    }
    out
}

pub fn render(snap: &Snapshot, at: u64, detail: bool) -> String {
    let mut out = String::new();
    if snap.records.is_empty() {
        out.push_str("No active background jobs.\n");
    }
    for (i, r) in snap.records.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&describe(r, at, detail));
    }
    if snap.hidden > 0 {
        out.push_str(&format!(
            "\n{} finished {} kept; show with --all or by ID.\n",
            snap.hidden,
            if snap.hidden == 1 {
                "job is"
            } else {
                "jobs are"
            }
        ));
    }
    if snap.skipped > 0 {
        out.push_str(&format!(
            "\n{} unreadable job {} ignored.\n",
            snap.skipped,
            if snap.skipped == 1 {
                "record was"
            } else {
                "records were"
            }
        ));
    }
    out
}

pub fn run(args: StatusArgs) -> Result<u8, String> {
    let store = Store::open()?;
    store.sweep(now());
    if args.json {
        let at = now();
        let snap = snapshot(&store, at, args.job.as_deref(), args.all)?;
        anstream::println!("{}", to_json(&snap, at)?);
        return Ok(0);
    }
    if !args.watch {
        let at = now();
        let snap = snapshot(&store, at, args.job.as_deref(), args.all)?;
        anstream::print!("{}", render(&snap, at, args.job.is_some()));
        return Ok(0);
    }
    let tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    loop {
        let at = now();
        let snap = snapshot(&store, at, args.job.as_deref(), args.all)?;
        if tty {
            anstream::print!("\x1b[2J\x1b[H");
        }
        anstream::print!("{}", render(&snap, at, args.job.is_some()));
        if !tty {
            anstream::println!();
        }
        let done = args.job.is_some() && snap.records.iter().all(|r| !r.state.is_active());
        if done {
            return Ok(0);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::super::record::{Direction, Phase, State};
    use super::*;

    fn transfer(state: State) -> Record {
        let mut r = Record::new("0123abcd", Kind::Get, 77, 1_000, "/logs/0123abcd.log");
        r.state = state;
        r.ready_at = Some(1_001);
        r.label = "archive.tar".into();
        r.remote = Some("http://host:5949".into());
        r.direction = Some(Direction::Download);
        r.phase = Some(Phase::Transferring);
        r.updated_at = 1_100;
        r
    }

    fn snap(records: Vec<Record>) -> Snapshot {
        Snapshot {
            records,
            skipped: 0,
            hidden: 0,
        }
    }

    #[test]
    fn unknown_values_are_shown_as_unknown_never_as_zero() {
        let text = render(&snap(vec![transfer(State::Running)]), 1_105, false);
        assert!(text.contains("running (transferring)"), "{text}");
        assert!(text.contains("0 B of unknown size"), "{text}");
        assert!(
            text.contains("speed unknown") && text.contains("ETA unknown"),
            "{text}"
        );
        assert!(!text.contains("0%"), "{text}");
    }

    #[test]
    fn known_progress_shows_percent_speed_and_eta() {
        let mut r = transfer(State::Running);
        r.bytes_total = Some(2048);
        r.bytes_done = 1024;
        r.speed_bps = Some(512);
        let text = render(&snap(vec![r]), 1_105, false);
        assert!(text.contains("1.00 KiB of 2.00 KiB (50%)"), "{text}");
        assert!(
            text.contains("512 B/s") && text.contains("ETA 2s"),
            "{text}"
        );
    }

    #[test]
    fn detail_view_shows_result_and_log_of_a_finished_job() {
        let mut r = transfer(State::Failed);
        r.phase = None;
        r.result = Some("SHA-256 mismatch".into());
        let text = render(&snap(vec![r]), 1_200, true);
        assert!(text.contains("result: SHA-256 mismatch"), "{text}");
        assert!(text.contains("log: /logs/0123abcd.log"), "{text}");
        assert!(!text.contains("ETA"), "{text}");
    }

    #[test]
    fn servers_show_listening_address_and_uptime_not_progress() {
        let mut r = Record::new("0123abcd", Kind::Serve, 5, 1_000, "log");
        r.state = State::Running;
        r.ready_at = Some(1_000);
        r.label = "shared".into();
        r.listen = Some("http://127.0.0.1:5949".into());
        let text = render(&snap(vec![r]), 1_065, false);
        assert!(
            text.contains("listening on http://127.0.0.1:5949"),
            "{text}"
        );
        assert!(text.contains("up 1m 05s"), "{text}");
        assert!(
            !text.contains("ETA") && !text.contains("of unknown size"),
            "{text}"
        );
    }

    #[test]
    fn empty_list_is_a_plain_message() {
        assert_eq!(
            render(&snap(vec![]), 0, false),
            "No active background jobs.\n"
        );
    }

    #[test]
    fn json_is_versioned_and_carries_null_for_unknowns() {
        let s = snap(vec![transfer(State::Running)]);
        let v: serde_json::Value = serde_json::from_str(&to_json(&s, 1_105).unwrap()).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["jobs"][0]["id"], "0123abcd");
        assert_eq!(v["jobs"][0]["state"], "running");
        assert!(v["jobs"][0]["percent"].is_null());
        assert!(v["jobs"][0]["speed_bps"].is_null());
        assert!(v["jobs"][0]["uptime_seconds"].is_null());
        assert_eq!(v["skipped_records"], 0);
    }

    #[test]
    fn spans_are_compact() {
        assert_eq!(span(5), "5s");
        assert_eq!(span(125), "2m 05s");
        assert_eq!(span(3 * 3600 + 7 * 60), "3h 07m");
    }

    #[test]
    fn snapshot_lists_only_active_jobs_unless_asked_and_flags_stale_ones() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path().join("jobs")).unwrap();
        let mut running = transfer(State::Running);
        running.id = "00000001".into();
        running.updated_at = 5_000;
        let mut done = transfer(State::Completed);
        done.id = "00000002".into();
        done.updated_at = 5_000;
        let mut dead = transfer(State::Running);
        dead.id = "00000003".into();
        dead.updated_at = 4_000;
        for r in [&running, &done, &dead] {
            store.write(r).unwrap();
        }
        let active = snapshot(&store, 5_001, None, false).unwrap();
        assert_eq!(active.records.len(), 1);
        assert_eq!(active.hidden, 2);
        let all = snapshot(&store, 5_001, None, true).unwrap();
        assert_eq!(all.records.len(), 3);
        let stale = all.records.iter().find(|r| r.id == "00000003").unwrap();
        assert_eq!(stale.state, State::Failed);
        assert!(
            snapshot(&store, 5_001, Some("00000009"), false)
                .unwrap_err()
                .contains("no job")
        );
        assert!(snapshot(&store, 5_001, Some("../x"), false).is_err());
    }
}
