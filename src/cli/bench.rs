use super::ansi::{self, Style};
use super::bench_artifact::{self, Comparison};
use super::bench_run::{self, DEFAULT_SEED, Plan, WorkloadSel};
use super::util::{Progress, canonical};
use crate::config::Config;
use clap::{Args, Subcommand};
use serde::Serialize;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct BenchArgs {
    #[command(subcommand)]
    pub command: Option<BenchCommand>,
    /// Existing BlazeServe URL to benchmark instead of a temporary local server
    #[arg(long)]
    pub url: Option<String>,
    /// Size of test download in MB
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..=1000))]
    pub size_mb: u64,
    /// Display machine-readable JSON
    #[arg(long = "json")]
    pub json: bool,
    /// Recorded samples per workload. Any of --runs, --warmup, --workload or --output selects
    /// the repeatable harness
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub runs: Option<u32>,
    /// Discarded warm-up samples before the recorded ones [default: 1]
    #[arg(long, value_parser = clap::value_parser!(u32).range(0..=100))]
    pub warmup: Option<u32>,
    /// Workload to measure [default: full]
    #[arg(long, value_enum)]
    pub workload: Option<WorkloadSel>,
    /// Write the versioned JSON artifact to this file
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Seed for the deterministic fixture content
    #[arg(long, default_value_t = DEFAULT_SEED)]
    pub seed: u64,
}

#[derive(Subcommand, Debug)]
pub enum BenchCommand {
    /// Compare the medians of two benchmark artifacts
    Compare(CompareArgs),
}

#[derive(Args, Debug)]
pub struct CompareArgs {
    /// Baseline artifact
    pub a: PathBuf,
    /// Candidate artifact
    pub b: PathBuf,
    /// Display machine-readable JSON
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Serialize)]
struct Report {
    base_url: String,
    requested_bytes: u64,
    downloaded_bytes: u64,
    elapsed_seconds: f64,
    throughput_mib_per_second: f64,
}

pub(super) struct TempDir(pub(super) PathBuf);

impl TempDir {
    pub(super) fn create() -> Result<Self, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "blazeserve-benchmark-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).map_err(|e| format!("Benchmark failed: {e}"))?;
        Ok(Self(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const URL_RULE: &str =
    "Benchmark URL must be an HTTP(S) origin without credentials, query, or fragment.";

fn validate_url(url: &str) -> Result<String, String> {
    if url.contains(['?', '#']) {
        return Err(URL_RULE.to_owned());
    }
    let uri: ureq::http::Uri = url.parse().map_err(|_| URL_RULE.to_owned())?;
    let scheme_ok = matches!(uri.scheme_str(), Some("http" | "https"));
    let authority_ok = uri
        .authority()
        .is_some_and(|a| !a.as_str().contains('@') && !a.host().is_empty());
    if !(scheme_ok && authority_ok) {
        return Err(URL_RULE.to_owned());
    }
    Ok(url.trim_end_matches('/').to_owned())
}

fn measure(origin: &str, expected: u64, show_progress: bool) -> Result<(u64, f64), String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(None)
        .build()
        .into();
    let url = format!("{origin}/__speed__?bytes={expected}");
    let start = Instant::now();
    let response = agent.get(&url).call().map_err(|_| {
        format!(
            "Could not connect to a BlazeServe server at {origin}. \
             Start one with `blaze serve`, then run the benchmark again."
        )
    })?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "Benchmark server at {origin} returned HTTP {}. \
             Verify that the URL points to a running BlazeServe server.",
            response.status().as_u16()
        ));
    }
    let mut reader = response.into_body().into_reader();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut downloaded = 0u64;
    let mut progress = show_progress.then(|| Progress::new(Some(expected), 0));
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("Benchmark failed: {e}"))?;
        if n == 0 {
            break;
        }
        downloaded += n as u64;
        if let Some(p) = progress.as_mut() {
            p.update(downloaded);
        }
    }
    if let Some(p) = progress.as_mut() {
        p.finish(downloaded);
    }
    let elapsed = start.elapsed().as_secs_f64();
    if downloaded != expected {
        return Err(format!(
            "Benchmark download was incomplete: expected {expected} bytes, received {downloaded}."
        ));
    }
    Ok((downloaded, elapsed))
}

fn local_run(size_bytes: u64, json: bool) -> Result<(String, u64, f64), String> {
    let dir = TempDir::create()?;
    let base = canonical(&dir.0)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("Benchmark failed: {e}"))?;
    runtime.block_on(async move {
        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            base,
            log_json: !json && super::util::env_truthy("BLAZE_LOG_JSON"),
            ..Config::default()
        };
        let handle = crate::server::start(config)
            .await
            .map_err(|e| format!("Benchmark failed: {e}"))?;
        let origin = format!("http://127.0.0.1:{}", handle.local_addr().port());
        let probe = origin.clone();
        let result = tokio::task::spawn_blocking(move || measure(&probe, size_bytes, !json))
            .await
            .map_err(|e| format!("Benchmark failed: {e}"))
            .and_then(|r| r);
        handle.shutdown().await;
        result.map(|(downloaded, elapsed)| (origin, downloaded, elapsed))
    })
}

fn harness(args: &BenchArgs) -> Result<ExitCode, String> {
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
    let artifact = bench_run::run(&plan)?.artifact;
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
            println!("{}", bench_run::summary_line(w));
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
        return Ok(ExitCode::from(130));
    }
    if bench_run::counts_failed(&artifact.totals) {
        eprintln!(
            "{} {} failed and {} incomplete samples were recorded and not counted as throughput",
            Style::stderr().yellow("Warning:"),
            artifact.totals.failed,
            artifact.totals.incomplete
        );
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

fn read_artifact(path: &std::path::Path) -> Result<bench_artifact::Artifact, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    bench_artifact::parse(&text)
        .map_err(|e| format!("{} is not a valid artifact: {e}", path.display()))
}

fn print_comparison(c: &Comparison) {
    let num = |v: Option<f64>| v.map_or_else(|| "n/a".to_owned(), |v| format!("{v:.2}"));
    let signed = |v: Option<f64>, suffix: &str| {
        v.map_or_else(|| "n/a".to_owned(), |v| format!("{v:+.2}{suffix}"))
    };
    println!(
        "{:<8} {:>12} {:>12} {:>12} {:>9}",
        "Workload", "A median", "B median", "Delta", "Change"
    );
    for r in &c.rows {
        println!(
            "{:<8} {:>12} {:>12} {:>12} {:>9}",
            r.workload,
            num(r.a_median),
            num(r.b_median),
            signed(r.delta, ""),
            signed(r.percent, "%")
        );
    }
    println!("\nMedians in MiB/s. No threshold or significance test is applied.");
    for note in &c.notes {
        println!("Note: {note}");
    }
}

fn compare(args: &CompareArgs) -> Result<ExitCode, String> {
    let a = read_artifact(&args.a)?;
    let b = read_artifact(&args.b)?;
    let comparison = bench_artifact::compare(&a, &b);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&comparison).map_err(|e| e.to_string())?
        );
    } else {
        print_comparison(&comparison);
    }
    Ok(ExitCode::SUCCESS)
}

pub fn run(args: BenchArgs) -> Result<ExitCode, String> {
    if let Some(BenchCommand::Compare(compare_args)) = &args.command {
        return compare(compare_args);
    }
    if args.runs.is_some()
        || args.warmup.is_some()
        || args.workload.is_some()
        || args.output.is_some()
    {
        return harness(&args);
    }
    let expected = args.size_mb * 1024 * 1024;
    let style = Style::stdout();
    let remote = args.url.as_deref().map(validate_url).transpose()?;

    if !args.json {
        if let Some(origin) = &remote {
            println!("Benchmarking  {origin}");
        }
        println!("Download size  {} MB\n", args.size_mb);
        if args.size_mb > 500 {
            eprintln!(
                "{} Large benchmark size ({} MB) may impact server performance",
                Style::stderr().yellow("Warning:"),
                args.size_mb
            );
        }
    }

    let (origin, downloaded, elapsed) = match remote {
        Some(origin) => {
            let (d, e) = measure(&origin, expected, !args.json)?;
            (origin, d, e)
        }
        None => local_run(expected, args.json)?,
    };

    let mib_per_second = (downloaded as f64 / (1024.0 * 1024.0)) / elapsed.max(f64::EPSILON);
    if args.json {
        let report = Report {
            base_url: origin,
            requested_bytes: expected,
            downloaded_bytes: downloaded,
            elapsed_seconds: elapsed,
            throughput_mib_per_second: mib_per_second,
        };
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| e.to_string())?
        );
        return Ok(ExitCode::SUCCESS);
    }

    println!("{}\n", style.bold("Benchmark complete"));
    print!(
        "{}",
        ansi::rows(
            style,
            &[
                (
                    "Downloaded",
                    format!("{:.2} MB", downloaded as f64 / (1024.0 * 1024.0))
                ),
                ("Time", format!("{elapsed:.2} seconds")),
                ("Speed", format!("{mib_per_second:.2} MB/s")),
            ],
        )
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_dir_is_removed_on_drop() {
        let dir = TempDir::create().unwrap();
        let path = dir.0.clone();
        std::fs::write(path.join("f"), b"x").unwrap();
        assert!(path.is_dir());
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn url_rules() {
        assert_eq!(
            validate_url("http://127.0.0.1:8000/").unwrap(),
            "http://127.0.0.1:8000"
        );
        assert!(validate_url("ftp://host").is_err());
        assert!(validate_url("http://user:pw@host").is_err());
        assert!(validate_url("http://host/?x=1").is_err());
        assert!(validate_url("http://host/#frag").is_err());
        assert!(validate_url("not a url").is_err());
    }
}
