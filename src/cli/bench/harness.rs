//! The repeatable-harness benchmark command: plan, artifact output and exit status.

use super::BenchArgs;
use super::runner::{self, Plan};
use super::sampler::WorkloadSel;
use super::schema::{Counts, Summary, Workload};
use super::single::validate_url;
use crate::cli::ansi::Style;

pub(super) fn run(args: &BenchArgs) -> Result<u8, String> {
    let url = args.url.as_deref().map(validate_url).transpose()?;
    let mut argv = vec!["blaze".to_owned()];
    argv.extend(std::env::args().skip(1));
    let plan = Plan {
        runs: args.runs.unwrap_or(5),
        warmup: args.warmup.unwrap_or(1),
        workload: args.workload.unwrap_or(WorkloadSel::Full),
        size_mb: args.size_mb,
        seed: args.seed,
        url,
        argv,
    };
    let artifact = runner::run(&plan)?.artifact;
    let text = serde_json::to_string_pretty(&artifact).map_err(|e| e.to_string())?;
    if let Some(path) = &args.output {
        std::fs::write(path, format!("{text}\n"))
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    }
    if args.json {
        println!("{text}");
    } else {
        let style = Style::stdout();
        println!("{}\n", style.bold("Benchmark complete"));
        for w in &artifact.workloads {
            println!("{}", summary_line(w));
        }
        if let Some(path) = &args.output {
            println!("\nArtifact  {}", path.display());
        }
    }
    if let Some(error) = &artifact.error {
        return Err(error.clone());
    }
    if artifact.interrupted {
        eprintln!("Interrupted; the artifact holds the samples recorded so far");
        return Ok(130);
    }
    if counts_failed(&artifact.totals) {
        eprintln!(
            "{} {} failed and {} incomplete samples were recorded and not counted as throughput",
            Style::stderr().yellow("Warning:"),
            artifact.totals.failed,
            artifact.totals.incomplete
        );
        return Ok(1);
    }
    Ok(0)
}

fn counts_failed(c: &Counts) -> bool {
    c.failed + c.incomplete > 0
}

fn summary_line(w: &Workload) -> String {
    let s: &Summary = &w.summary;
    let fmt = |v: Option<f64>| v.map_or_else(|| "n/a".to_owned(), |v| format!("{v:.2}"));
    format!(
        "{:<6} ok {}/{}  median {}  min {}  max {}  stddev {}  MiB/s",
        w.id,
        w.counts.ok,
        w.samples.len(),
        fmt(s.median),
        fmt(s.min),
        fmt(s.max),
        fmt(s.stddev),
    )
}
