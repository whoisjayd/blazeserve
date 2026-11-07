//! Command-line interface. Every command resolves into [`crate::config::Config`] and
//! validates it before any socket is bound.

mod ansi;
mod bench;
mod bench_artifact;
mod bench_run;
mod doctor;
mod serve;
mod telemetry;
mod transfer;
mod util;

use ansi::Style;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

pub use util::{human_size, sha256_file};

#[derive(Parser, Debug)]
#[command(
    name = "blaze",
    version = crate::VERSION,
    about = "Fast HTTP file server for large static transfers",
    arg_required_else_help = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Serve a directory or a single file
    Serve(serve::ServeArgs),
    /// Quick share a single file
    Send(serve::SendArgs),
    /// SHA256 for files
    Checksum(ChecksumArgs),
    /// Show version and system info
    Version(VersionArgs),
    /// Validate system environment and server configuration
    Doctor(doctor::DoctorArgs),
    /// Run performance benchmark
    Benchmark(bench::BenchArgs),
    /// Download a file, resuming a partial transfer
    Get(transfer::GetArgs),
    /// Upload a file, resuming a partial transfer
    Put(transfer::PutArgs),
    /// Manage anonymous usage statistics
    Telemetry(telemetry::TelemetryArgs),
}

#[derive(Args, Debug)]
struct ChecksumArgs {
    /// Files to hash
    #[arg(required = true, value_parser = util::existing_file)]
    files: Vec<PathBuf>,
}

#[derive(Args, Debug)]
struct VersionArgs {
    /// Display machine-readable JSON
    #[arg(long = "json")]
    json: bool,
}

fn checksum(args: ChecksumArgs) -> Result<ExitCode, String> {
    let mut rows = Vec::with_capacity(args.files.len());
    for path in &args.files {
        let digest =
            util::sha256_file(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
        rows.push((digest, util::human_size(size), path.display().to_string()));
    }
    let style = Style::stdout();
    let width = rows.iter().map(|r| r.1.len()).max().unwrap_or(0).max(4);
    if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        println!(
            "{}",
            style.dim(&format!("{:<64}  {:>width$}  File", "Digest", "Size"))
        );
    }
    for (digest, size, file) in rows {
        println!("{digest}  {size:>width$}  {file}");
    }
    Ok(ExitCode::SUCCESS)
}

fn version(args: VersionArgs) -> Result<ExitCode, String> {
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    if args.json {
        let data = serde_json::json!({
            "name": "blazeserve",
            "version": crate::VERSION,
            "platform": os,
            "architecture": arch,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?
        );
        return Ok(ExitCode::SUCCESS);
    }
    let style = Style::stdout();
    println!(
        "{}\n",
        style.bold(&format!("BlazeServe {}", crate::VERSION))
    );
    print!(
        "{}",
        ansi::rows(
            style,
            &[
                ("Platform", os.to_owned()),
                ("Architecture", arch.to_owned())
            ]
        )
    );
    Ok(ExitCode::SUCCESS)
}

fn dispatch(command: Command) -> Result<ExitCode, String> {
    match command {
        Command::Serve(a) => serve::serve(a),
        Command::Send(a) => serve::send(a),
        Command::Checksum(a) => checksum(a),
        Command::Version(a) => version(a),
        Command::Doctor(a) => doctor::run(a),
        Command::Benchmark(a) => bench::run(a),
        Command::Get(a) => transfer::get(a),
        Command::Put(a) => transfer::put(a),
        Command::Telemetry(a) => telemetry::run(a),
    }
}

/// Parse arguments, run the command, and map the outcome to an exit code:
/// 0 success, 1 runtime failure, 2 usage error (reported by clap).
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli.command) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{} {message}", Style::stderr().red("Error:"));
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_definitions_are_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn serve_defaults_match_documented_values() {
        let cli = Cli::try_parse_from(["blaze", "serve"]).unwrap();
        let Command::Serve(a) = cli.command else {
            panic!("expected serve")
        };
        assert_eq!(a.common.port, 8000);
        assert_eq!(a.common.host, "0.0.0.0");
        assert_eq!(a.common.backlog, 8192);
        assert_eq!(a.timeout, 1800);
        assert!(!a.common.cors && !a.common.no_precompress);
    }

    #[test]
    fn out_of_range_values_are_usage_errors() {
        for bad in [
            ["--port", "0"],
            ["--timeout", "5"],
            ["--chunk-mb", "0"],
            ["--rate-mbps", "0"],
        ] {
            let argv = ["blaze", "serve", bad[0], bad[1]];
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn last_toggle_wins() {
        let cli = Cli::try_parse_from(["blaze", "serve", "--cors", "--no-cors"]).unwrap();
        let Command::Serve(a) = cli.command else {
            panic!("expected serve")
        };
        assert!(a.common.no_cors);
    }
}
