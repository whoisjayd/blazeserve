//! In-place extraction of a finished download with `hatchzip-core`: the archive shrinks as
//! its files come out, so about the extracted size is enough free space.
//!
//! An interrupted run is safe by design. Its journal lets the same command pick up where it
//! stopped, so this module never needs to cancel one mid-way.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use hatchzip_core::archive::PasswordNeeded;
use hatchzip_core::archive::storage::Reads;
use hatchzip_core::engine::{self, Outcome, Progress as EngineProgress, Run};
use hatchzip_core::session::{self, State};

use crate::cli::ansi::{Style, announce};
use crate::cli::util::{Progress, human_size};

/// Never set; see the module note.
static NEVER: AtomicBool = AtomicBool::new(false);

pub(super) struct Options {
    /// Leave the archive in place instead of consuming it as files come out.
    pub keep_archive: bool,
    /// Read and check the whole archive before consuming it, so a damaged download is never
    /// destroyed. Not needed when the archive is kept.
    pub verify_first: bool,
    /// Free space that must remain untouched, in bytes.
    pub keep_free: u64,
}

fn failure<E: std::fmt::Display>(e: E) -> String {
    format!("{e:#}")
}

/// Extracts `archive` next to itself, into a folder named after it. Returns that folder.
pub(super) fn extract(archive: &Path, opts: &Options) -> Result<PathBuf, String> {
    let (primary, paths) = session::locate(archive).map_err(failure)?;
    let reads = Arc::new(Reads::default());
    let state = session::open(&primary, &paths, None, true, None, &reads).map_err(|e| {
        if e.is::<PasswordNeeded>() {
            "the archive is encrypted; extract it with hatchzip, which can ask for the password"
                .to_owned()
        } else {
            failure(e)
        }
    })?;

    let (job, journal) = match state {
        State::Orphan(mut journal) => {
            // The archive is already gone; only the cleanup of an earlier run remains.
            if let Some(warning) = engine::finish_orphaned(&mut journal, &paths).map_err(failure)? {
                announce("Warning", &warning);
            }
            return Ok(journal.output);
        }
        State::Resume(job, journal) => {
            let keep = session::keeps_archive(&journal, opts.keep_archive).map_err(failure)?;
            ensure_fits(&job, &journal.output, true, opts.keep_free, keep)?;
            session::clear_uncommitted(&job, &journal.output).map_err(failure)?;
            (job, journal)
        }
        State::Fresh(job, out) => {
            if let Some(why) = job.in_place_refusal()
                && !opts.keep_archive
            {
                return Err(format!(
                    "{why}; run again with --keep-archive to extract it and keep the archive"
                ));
            }
            let found = session::existing(&job, &out).map_err(failure)?;
            if !found.is_empty() {
                return Err(format!(
                    "{} of its files already exist in {}; move them away first",
                    found.len(),
                    out.display()
                ));
            }
            ensure_fits(&job, &out, false, opts.keep_free, opts.keep_archive)?;
            if opts.verify_first && !opts.keep_archive {
                verify(&job, archive)?;
            }
            let journal =
                session::begin(&job, &paths, out, opts.keep_archive, None).map_err(failure)?;
            (job, journal)
        }
    };

    let keep = journal.keep;
    let total = journal.total_size;
    let output = journal.output.clone();
    let name = archive
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let bar = Arc::new(Progress::titled(
        &format!("▣ {name}"),
        Some(total),
        total.saturating_sub(job.remaining_size()),
    ));
    if !keep {
        bar.set_note(&format!("archive {}", human_size(journal.committed_len)));
    }
    let (on_bytes, on_commit) = (bar.clone(), bar.clone());
    let run = Run {
        job,
        journal,
        paths,
        stop: &NEVER,
        progress: EngineProgress {
            on_bytes: Box::new(move |n| on_bytes.inc(n)),
            on_commit: Box::new(move |len| {
                on_commit.set_note(&format!("archive {}", human_size(len)));
            }),
        },
        keep_free: opts.keep_free,
    };
    let outcome = run.execute();
    if let Some(mut bar) = Arc::into_inner(bar) {
        bar.finish(total);
    }

    match outcome.map_err(|e| format!("{} Run the same command again to resume.", failure(e)))? {
        Outcome::Finished(warning) => {
            if let Some(warning) = warning {
                announce("Warning", &warning);
            }
            let note = if keep {
                "archive kept"
            } else {
                "archive removed"
            };
            announce(
                "Extracted",
                &format!(
                    "{} ({note})",
                    Style::stdout().bold(&output.display().to_string())
                ),
            );
            Ok(output)
        }
        Outcome::Paused => {
            Err("extraction paused; run the same command again to resume".to_owned())
        }
    }
}

/// Reads every unit and lets the decoders check their checksums. Writes nothing.
fn verify(job: &hatchzip_core::engine::Job, archive: &Path) -> Result<(), String> {
    let name = archive
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let bar = Arc::new(Progress::titled(
        &format!("▣ checking {name}"),
        Some(job.remaining_size()),
        0,
    ));
    let on_bytes = bar.clone();
    let result = job.verify(&move |n| on_bytes.inc(n));
    if let Some(mut bar) = Arc::into_inner(bar) {
        bar.finish(0);
    }
    result.map_err(|e| {
        format!(
            "the archive is damaged, so nothing was extracted and the download was kept: {}",
            failure(e)
        )
    })
}

fn ensure_fits(
    job: &hatchzip_core::engine::Job,
    out: &Path,
    resuming: bool,
    keep_free: u64,
    keep_archive: bool,
) -> Result<(), String> {
    let plan = session::plan(job, out, resuming, keep_free, keep_archive).map_err(failure)?;
    if plan.fits {
        return Ok(());
    }
    let short = (plan.needed + plan.keep_free).saturating_sub(plan.free);
    let mut message = format!(
        "not enough free disk space to extract: {} more is needed ({} available, {} required plus {} kept free). Free some space or lower --keep-free",
        human_size(short),
        human_size(plan.free),
        human_size(plan.needed),
        human_size(plan.keep_free)
    );
    if plan.keep_archive && plan.either && plan.in_place_fits() {
        message
            .push_str("; without --keep-archive the archive is consumed as it extracts and fits");
    }
    Err(message)
}
