//! Command-line interface. Every command resolves into [`crate::config::Config`] and
//! validates it before any socket is bound.

mod ansi;
mod bench;
mod doctor;
mod serve;
mod telemetry;
mod transfer;
mod util;

use ansi::Style;
use clap::builder::styling::{AnsiColor, Styles};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::path::PathBuf;
use std::process::ExitCode;

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
  blaze serve ./site --qr")]
    Serve(serve::ServeArgs),
    /// Quick share a single file
    #[command(after_help = "Examples:
  blaze send ./big.iso
  blaze send ./big.iso --qr")]
    Send(serve::SendArgs),
    /// SHA256 for files
    Checksum(ChecksumArgs),
    /// Show version and system info
    Version(VersionArgs),
    /// Validate system environment and server configuration
    #[command(after_help = "Examples:
  blaze doctor
  blaze doctor ./site --port 9000 --json

The path is the directory you intend to serve; there is no 'serve' keyword.")]
    Doctor(doctor::DoctorArgs),
    /// Run performance benchmark
    Benchmark(bench::BenchArgs),
    /// Download a file, resuming a partial transfer
    #[command(after_help = "Examples:
  blaze get http://host:8000/big.iso
  blaze get http://host:8000/big.iso -o disk.iso --sha256 <digest>
  blaze get http://host:8000/big.iso -c 8   # up to 8 parallel connections
  blaze get http://host:8000/big.iso --limit-rate 2M   # cap total speed at 2 MiB/s")]
    Get(transfer::GetArgs),
    /// Upload a file, resuming a partial transfer
    Put(transfer::PutArgs),
    /// Manage anonymous usage statistics
    Telemetry(telemetry::TelemetryArgs),
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

fn dispatch(command: Command) -> Result<u8, String> {
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
        Command::Completions(a) => completions(a),
    }
}

/// Parse arguments, run the command, and map the outcome to an exit code:
/// 0 success, 1 runtime failure, 2 usage error (reported by clap).
pub fn main() -> ExitCode {
    ExitCode::from(run(Cli::parse()))
}

/// Like [`main`] for an explicit argument list (embedders). Parse errors and help are
/// printed and returned as a status instead of ending the process.
pub fn main_from<I, T>(args: I) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
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
    match dispatch(cli.command) {
        Ok(code) => code,
        Err(message) => {
            anstream::eprintln!("{} {message}", Style::stderr().red("error:"));
            1
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
