//! Command-line interface. Every command resolves into [`crate::config::Config`] and
//! validates it before any socket is bound.

mod ansi;
pub mod argv;
mod bench;
mod doctor;
mod exit;
mod jobs;
mod live;
mod serve;
mod telemetry;
mod transfer;
mod upgrade;
mod util;

use ansi::Style;
use clap::builder::styling::{AnsiColor, Styles};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(fuzzing)]
pub use transfer::{parse_digest_for_fuzz, suggested_name_for_fuzz};
pub use upgrade::api as upgrade_api;
pub use util::{human_size, sha256_file};

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().bold())
    .usage(AnsiColor::Yellow.on_default().bold())
    .literal(AnsiColor::Green.on_default().bold())
    .placeholder(AnsiColor::Cyan.on_default())
    .error(AnsiColor::Red.on_default().bold())
    .valid(AnsiColor::Green.on_default())
    .invalid(AnsiColor::Yellow.on_default());

const TOP_EXAMPLES: &str = "Examples:
  blaze serve .                     Serve the current directory on port 8000
  blaze send report.pdf             Share one file
  blaze get http://host:8000/big.iso   Resumable download
  blaze put backup.tar http://host:8000   Resumable upload (server needs --max-upload-mb)
  blaze doctor ./site --port 9000   Check a directory and port before serving
  blaze completions powershell      Print a shell completion script

Run 'blaze help <command>' for the options of one command.";

#[derive(Parser, Debug)]
#[command(
    name = "blaze",
    version = crate::VERSION,
    about = "Fast HTTP file server for large static transfers",
    after_help = TOP_EXAMPLES,
    styles = STYLES,
    arg_required_else_help = true
)]
pub struct Cli {
    /// When to use colour in output
    #[arg(long, global = true, value_enum, value_name = "WHEN", default_value_t = ColorWhen::Auto)]
    color: ColorWhen,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ColorWhen {
    /// Colour only on a terminal that supports it
    Auto,
    /// Always colour, even when piped
    Always,
    /// Never colour
    Never,
}

impl ColorWhen {
    fn apply(self) {
        anstream::ColorChoice::write_global(match self {
            Self::Auto => anstream::ColorChoice::Auto,
            Self::Always => anstream::ColorChoice::Always,
            Self::Never => anstream::ColorChoice::Never,
        });
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Serve a directory or a single file
    #[command(after_help = "Examples:
  blaze serve .
  blaze serve ./site --port 9000 --no-listing
  blaze serve ./data --auth-env BLAZE_AUTH --max-upload-mb 512
  blaze serve ./site --hide '*.env' --hide .git
  blaze serve ./site --qr
  blaze serve ./site --background   # then use blaze status and blaze stop")]
    Serve(serve::ServeArgs),
    /// Quick share a single file
    #[command(after_help = "Examples:
  blaze send ./big.iso
  blaze send ./big.iso --qr
  blaze send ./big.iso --expires-after 20m
  blaze send ./big.iso --background")]
    Send(serve::SendArgs),
    /// SHA256 for files
    Checksum(ChecksumArgs),
    /// Show version and system info
    Version(VersionArgs),
    /// Validate system environment and server configuration
    #[command(after_help = "Examples:
  blaze doctor
  blaze doctor ./site --port 9000 --json
  blaze doctor ./site --host 0.0.0.0 --port 9000   Matches: blaze serve ./site --host 0.0.0.0 --port 9000
  blaze doctor ./site --host ::1 --port 9000

By default the probe binds 127.0.0.1. Use --host to test the address you will serve on.
It binds and releases the port at once, so it is a point-in-time check, not a reservation.

The path is the directory you intend to serve; there is no 'serve' keyword.")]
    Doctor(doctor::DoctorArgs),
    /// Run performance benchmark
    Benchmark(bench::BenchArgs),
    /// Download a file, resuming a partial transfer
    #[command(after_help = "Examples:
  blaze get http://host:8000/big.iso
  blaze get http://host:8000/big.iso -o disk.iso --sha256 <digest>
  blaze get http://host:8000/big.iso --verify server-sha256   # check against the server's own SHA-256
  blaze get http://host:8000/big.iso -c 8   # up to 8 parallel connections
  blaze get http://host:8000/big.iso --limit-rate 2M   # cap total speed at 2 MiB/s
  blaze get http://host:8000/big.iso --idle-timeout 45s --max-time 30m   # give up when stalled or too slow overall")]
    Get(transfer::GetArgs),
    /// Upload a file, resuming a partial transfer
    Put(transfer::PutArgs),
    /// Show background jobs started with --background
    #[command(after_help = "Examples:
  blaze status
  blaze status 3f9a01bc
  blaze status --watch
  blaze status --json")]
    Status(jobs::StatusArgs),
    /// Stop a background job
    #[command(after_help = "Examples:
  blaze stop 3f9a01bc
  blaze stop 3f9a01bc --yes")]
    Stop(jobs::StopArgs),
    /// Manage anonymous usage statistics
    Telemetry(telemetry::TelemetryArgs),
    /// Upgrade BlazeServe the way it was installed
    #[command(after_help = "Examples:
  blaze upgrade --check
  blaze upgrade --check --json
  blaze upgrade --yes
  blaze upgrade --version 1.0.0 --yes   Install an exact version, also to go back

A downloaded binary replaces itself after checking its SHA-256 against the release SHA256SUMS.
pip and cargo installs run pip or cargo. Containers and package managers get instructions only.")]
    Upgrade(upgrade::UpgradeArgs),
    /// Print a shell completion script
    #[command(after_help = "Examples:
  blaze completions bash > ~/.local/share/bash-completion/completions/blaze
  blaze completions powershell | Out-String | Invoke-Expression")]
    Completions(CompletionsArgs),
}

#[derive(Args, Debug)]
struct ChecksumArgs {
    /// Files to hash
    #[arg(required = true, value_parser = util::existing_file)]
    files: Vec<PathBuf>,
}

#[derive(Args, Debug)]
struct CompletionsArgs {
    /// Shell to generate the script for
    shell: Shell,
}

fn completions(args: CompletionsArgs) -> Result<u8, String> {
    clap_complete::generate(
        args.shell,
        &mut Cli::command(),
        "blaze",
        &mut std::io::stdout(),
    );
    Ok(0)
}

#[derive(Args, Debug)]
struct VersionArgs {
    /// Display machine-readable JSON
    #[arg(long = "json")]
    json: bool,
}

fn checksum(args: ChecksumArgs) -> Result<u8, String> {
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
        anstream::println!(
            "{}",
            style.dim(&format!("{:<64}  {:>width$}  File", "Digest", "Size"))
        );
    }
    for (digest, size, file) in rows {
        anstream::println!("{digest}  {size:>width$}  {file}");
    }
    Ok(0)
}

fn version(args: VersionArgs) -> Result<u8, String> {
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    if args.json {
        let data = serde_json::json!({
            "name": "blazeserve",
            "version": crate::VERSION,
            "platform": os,
            "architecture": arch,
        });
        anstream::println!(
            "{}",
            serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?
        );
        return Ok(0);
    }
    let style = Style::stdout();
    anstream::println!(
        "{}\n",
        style.bold(&format!("BlazeServe {}", crate::VERSION))
    );
    anstream::print!(
        "{}",
        ansi::rows(
            style,
            &[
                ("Platform", os.to_owned()),
                ("Architecture", arch.to_owned())
            ]
        )
    );
    Ok(0)
}

/// A failed command: what to print and the status to exit with.
struct Failure {
    message: String,
    code: u8,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            code: exit::OTHER,
        }
    }
}

impl From<transfer::TransferError> for Failure {
    fn from(e: transfer::TransferError) -> Self {
        Self {
            code: e.code(),
            message: e.to_string(),
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn dispatch(command: Command) -> Result<u8, Failure> {
    match command {
        Command::Serve(a) => {
            let bg = a.common.bg.clone();
            Ok(jobs::run(jobs::Kind::Serve, &bg, move || serve::serve(a))?)
        }
        Command::Send(a) => {
            let bg = a.common.bg.clone();
            Ok(jobs::run(jobs::Kind::Send, &bg, move || serve::send(a))?)
        }
        Command::Checksum(a) => Ok(checksum(a)?),
        Command::Version(a) => Ok(version(a)?),
        Command::Doctor(a) => Ok(doctor::run(a)?),
        Command::Benchmark(a) => Ok(bench::run(a)?),
        Command::Get(a) => {
            let bg = a.bg.clone();
            jobs::run(jobs::Kind::Get, &bg, move || Ok(transfer::get(a)?))
        }
        Command::Put(a) => {
            let bg = a.bg.clone();
            jobs::run(jobs::Kind::Put, &bg, move || Ok(transfer::put(a)?))
        }
        Command::Status(a) => Ok(jobs::status(a)?),
        Command::Stop(a) => Ok(jobs::stop(a)?),
        Command::Telemetry(a) => Ok(telemetry::run(a)?),
        Command::Upgrade(a) => Ok(upgrade::run(a)?),
        Command::Completions(a) => Ok(completions(a)?),
    }
}

/// Asks the command running in this process to stop at its next safe point. Used by the Python
/// package when the user presses Ctrl+C.
pub fn request_stop() {
    jobs::request_stop();
}

/// The `serve` settings for `args` (everything after the program name), validated exactly as
/// the command line validates them.
pub fn serve_config_from(args: &[String]) -> Result<crate::config::Config, String> {
    let full = std::iter::once("blaze".to_owned()).chain(args.iter().cloned());
    match Cli::try_parse_from(full)
        .map_err(|e| e.to_string())?
        .command
    {
        Command::Serve(a) => serve::serve_config(&a),
        _ => Err("expected a serve command line".to_owned()),
    }
}

/// Parse arguments, run the command, and map the outcome to an exit code:
/// 0 success, 1 runtime failure, 2 usage error (reported by clap), 3 not enough disk space,
/// 4 integrity failure and 5 authentication refused (see `exit`).
pub fn main() -> ExitCode {
    jobs::mark_standalone();
    ExitCode::from(run(Cli::parse()))
}

/// Like [`main`] for an explicit argument list (embedders). Parse errors and help are
/// printed and returned as a status instead of ending the process.
pub fn main_from<I, T>(args: I) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    jobs::set_embedded_args(args.iter().skip(1).cloned().collect());
    match Cli::try_parse_from(args) {
        Ok(cli) => run(cli),
        Err(e) => {
            let _ = e.print();
            u8::try_from(e.exit_code()).unwrap_or(2)
        }
    }
}

fn run(cli: Cli) -> u8 {
    cli.color.apply();
    jobs::clear_stop();
    upgrade::remove_stale_backup();
    match dispatch(cli.command) {
        Ok(code) => code,
        Err(failure) => {
            anstream::eprintln!("{} {failure}", Style::stderr().red("error:"));
            failure.code
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
    fn help_subcommand_and_completions_parse() {
        let err = Cli::try_parse_from(["blaze", "help", "doctor"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let text = err.to_string();
        assert!(
            text.contains("Examples:") && text.contains("blaze doctor"),
            "{text}"
        );
        for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
            let cli = Cli::try_parse_from(["blaze", "completions", shell]).unwrap();
            assert!(matches!(cli.command, Command::Completions(_)));
        }
        assert!(Cli::try_parse_from(["blaze", "completions", "tcsh"]).is_err());
    }

    #[test]
    fn http2_is_on_unless_disabled() {
        let parse = |extra: &[&str]| {
            let mut argv = vec!["blaze", "serve"];
            argv.extend_from_slice(extra);
            let Command::Serve(a) = Cli::try_parse_from(argv).unwrap().command else {
                panic!("expected serve")
            };
            serve::serve_config(&a).unwrap().http2
        };
        assert!(parse(&[]));
        assert!(!parse(&["--no-http2"]));
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
