//! `blaze upgrade`: update this copy of BlazeServe the way it was installed.
//!
//! A standalone binary replaces itself from the GitHub release. A pip or cargo install runs that
//! tool. A container or an install owned by a package manager only gets instructions. Nothing
//! here sends a usage report.

mod archive;
mod channel;
mod replace;
mod source;
mod version;

use super::ansi::{self, Style};
use channel::Channel;
use clap::Args;
use serde::Serialize;
use source::{HashingWriter, HttpSource, Source};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use version::Version;

pub use replace::remove_stale_backup;

const MAX_SUMS_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 200 * 1024 * 1024;
const NEEDS_YES: &str =
    "upgrading needs confirmation: run it in a terminal, or pass --yes to go ahead without asking";

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    /// Report the installed and the latest version, and change nothing
    #[arg(long, conflicts_with = "version")]
    check: bool,
    /// Install this exact version (X.Y.Z) instead of the latest. Needed to downgrade or to pick a pre-release
    #[arg(long, value_name = "X.Y.Z")]
    version: Option<String>,
    /// Do not ask for confirmation
    #[arg(short, long)]
    yes: bool,
    /// With --check, print machine-readable JSON
    #[arg(long, requires = "check")]
    json: bool,
}

pub struct Opts {
    pub check: bool,
    pub version: Option<Version>,
    pub yes: bool,
}

pub struct Context {
    pub current: Version,
    pub exe: PathBuf,
    pub channel: Channel,
    pub python: Option<PathBuf>,
    pub triple: Option<&'static str>,
    pub interactive: bool,
}

pub trait Runner {
    /// Runs a program with the given arguments, never through a shell. `Ok(true)` means it succeeded.
    fn run(&self, program: &Path, args: &[String]) -> Result<bool, String>;
}

pub struct Deps<'a> {
    pub source: &'a dyn Source,
    pub runner: &'a dyn Runner,
    pub confirm: &'a dyn Fn(&str) -> bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub current: String,
    pub latest: Option<String>,
    pub target: Option<String>,
    pub update_available: bool,
    pub channel: &'static str,
    pub status: &'static str,
    #[serde(skip)]
    pub message: String,
}

struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &Path, args: &[String]) -> Result<bool, String> {
        std::process::Command::new(program)
            .args(args)
            .status()
            .map(|s| s.success())
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    format!("cannot find {} on this system", program.display())
                } else {
                    format!("cannot run {}: {e}", program.display())
                }
            })
    }
}

fn target_triple() -> Option<&'static str> {
    let musl = cfg!(target_env = "musl");
    match (std::env::consts::OS, std::env::consts::ARCH, musl) {
        ("linux", "x86_64", false) => Some("x86_64-unknown-linux-gnu"),
        ("linux", "x86_64", true) => Some("x86_64-unknown-linux-musl"),
        ("linux", "aarch64", false) => Some("aarch64-unknown-linux-gnu"),
        ("linux", "aarch64", true) => Some("aarch64-unknown-linux-musl"),
        ("windows", "x86_64", _) => Some("x86_64-pc-windows-msvc"),
        ("macos", "x86_64", _) => Some("x86_64-apple-darwin"),
        ("macos", "aarch64", _) => Some("aarch64-apple-darwin"),
        _ => None,
    }
}

fn detect_context(interactive: bool) -> Result<Context, String> {
    let current = Version::parse(crate::VERSION)
        .ok_or_else(|| format!("the built-in version {} is not valid", crate::VERSION))?;
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate this program: {e}"))?;
    // A symlinked install must replace the real file, not the link.
    let exe = if crate::platform::IS_WINDOWS {
        exe
    } else {
        std::fs::canonicalize(&exe).unwrap_or(exe)
    };
    let env = |name: &str| std::env::var(name).ok();
    let channel = channel::detect(&env, &exe);
    let python = env("BLAZE_PYTHON")
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from);
    Ok(Context {
        current,
        exe,
        channel,
        python,
        triple: target_triple(),
        interactive,
    })
}

fn prompt(question: &str) -> bool {
    anstream::eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok()
        && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn parse_requested(text: &Option<String>) -> Result<Option<Version>, String> {
    text.as_deref()
        .map(|t| {
            Version::parse(t).ok_or_else(|| {
                format!("'{t}' is not a version; use the form X.Y.Z, for example 1.2.3")
            })
        })
        .transpose()
}

pub fn run(args: UpgradeArgs) -> Result<u8, String> {
    let opts = Opts {
        check: args.check,
        version: parse_requested(&args.version)?,
        yes: args.yes,
    };
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let ctx = detect_context(interactive)?;
    let source = HttpSource::from_env()?;
    let report = execute(
        &opts,
        &ctx,
        &Deps {
            source: &source,
            runner: &SystemRunner,
            confirm: &prompt,
        },
    )?;
    if args.json {
        anstream::println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else if args.check {
        let style = Style::stdout();
        anstream::print!(
            "{}",
            ansi::rows(
                style,
                &[
                    ("Installed", report.current.clone()),
                    ("Latest", report.latest.clone().unwrap_or_default()),
                    ("Install", report.channel.to_owned()),
                ]
            )
        );
        anstream::println!("\n{}", report.message);
    } else {
        anstream::println!("{}", report.message);
    }
    Ok(0)
}

/// The library entry point: never prompts, so an upgrade needs `yes`. Returns the report as JSON.
pub fn api(check: bool, version: Option<String>, yes: bool) -> Result<String, String> {
    if check && version.is_some() {
        return Err("check cannot be combined with a version".to_owned());
    }
    let opts = Opts {
        check,
        version: parse_requested(&version)?,
        yes,
    };
    let ctx = detect_context(false)?;
    let source = HttpSource::from_env()?;
    let report = execute(
        &opts,
        &ctx,
        &Deps {
            source: &source,
            runner: &SystemRunner,
            confirm: &|_| false,
        },
    )?;
    let mut value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
    value["message"] = report.message.into();
    serde_json::to_string(&value).map_err(|e| e.to_string())
}

fn manual_steps(channel: &Channel, tag: &str) -> Option<String> {
    match channel {
        Channel::Docker => Some(format!(
            "This is a container. Pull the new image and recreate the container instead:\n  docker pull ghcr.io/whoisjayd/blazeserve:{tag}"
        )),
        Channel::Managed { manager, command } => Some(format!(
            "BlazeServe was installed by {manager}, so upgrade it there to keep it consistent:\n  {command}"
        )),
        _ => None,
    }
}

pub fn execute(opts: &Opts, ctx: &Context, deps: &Deps) -> Result<Report, String> {
    let acts = matches!(ctx.channel, Channel::Binary | Channel::Pip | Channel::Cargo);
    if !opts.check && acts && !opts.yes && !ctx.interactive {
        return Err(NEEDS_YES.to_owned());
    }

    let latest = if opts.version.is_none() {
        let tag = deps.source.latest_tag()?;
        let version = Version::parse(&tag)
            .ok_or_else(|| format!("the latest release has an unreadable tag ({tag})"))?;
        if version.is_prerelease() {
            return Err("the newest release is a pre-release; use --version to pick one".into());
        }
        Some(version)
    } else {
        None
    };
    let target = opts.version.clone().or_else(|| latest.clone());
    let update_available = target.as_ref().is_some_and(|t| *t != ctx.current)
        && (opts.version.is_some() || latest.as_ref().is_some_and(|l| *l > ctx.current));
    let report = |status: &'static str, message: String| Report {
        current: ctx.current.to_string(),
        latest: latest.as_ref().map(Version::to_string),
        target: target.as_ref().map(Version::to_string),
        update_available,
        channel: ctx.channel.name(),
        status,
        message,
    };
    let Some(target) = target.clone() else {
        return Err("no version to upgrade to".to_owned());
    };
    let tag = target.tag();

    if opts.check {
        return Ok(if update_available {
            let how = manual_steps(&ctx.channel, &tag)
                .unwrap_or_else(|| "Run 'blaze upgrade' to install it.".to_owned());
            report(
                "update_available",
                format!("BlazeServe {target} is available. {how}"),
            )
        } else {
            report(
                "up_to_date",
                format!("BlazeServe {} is the latest version.", ctx.current),
            )
        });
    }

    if !update_available {
        return Ok(report(
            "up_to_date",
            format!(
                "BlazeServe {} is already installed; nothing to do.",
                ctx.current
            ),
        ));
    }
    if let Some(steps) = manual_steps(&ctx.channel, &tag) {
        return Ok(report(
            "manual",
            format!("Not changed. BlazeServe {target} is available.\n{steps}"),
        ));
    }

    let downgrade = target < ctx.current;
    if !opts.yes {
        let verb = if downgrade { "Downgrade" } else { "Upgrade" };
        let question = format!("{verb} BlazeServe {} to {target}?", ctx.current);
        if !(deps.confirm)(&question) {
            return Ok(report(
                "cancelled",
                "Cancelled. Nothing was changed.".to_owned(),
            ));
        }
    }

    match &ctx.channel {
        Channel::Pip => {
            let python = ctx.python.as_deref().ok_or_else(|| {
                "cannot tell which Python installed BlazeServe; run: python -m pip install --upgrade blazeserve"
                    .to_owned()
            })?;
            let spec = match &opts.version {
                Some(v) => format!("blazeserve=={v}"),
                None => "blazeserve".to_owned(),
            };
            let args = ["-m", "pip", "install", "--upgrade", &spec].map(str::to_owned);
            if !deps.runner.run(python, &args)? {
                return Err(
                    "pip did not finish the upgrade (its messages are above). If a file was in use, close other blaze programs and try again"
                        .to_owned(),
                );
            }
        }
        Channel::Cargo => {
            let mut args = ["install", "blazeserve", "--locked", "--force"]
                .map(str::to_owned)
                .to_vec();
            if let Some(v) = &opts.version {
                args.extend(["--version".to_owned(), v.to_string()]);
            }
            if !deps.runner.run(Path::new("cargo"), &args)? {
                return Err("cargo did not finish the upgrade (its messages are above)".to_owned());
            }
        }
        Channel::Binary => install_binary(ctx, deps.source, &target)?,
        Channel::Docker | Channel::Managed { .. } => unreachable!("handled above"),
    }
    Ok(report(
        "upgraded",
        format!("BlazeServe {} is now {target}.", ctx.current),
    ))
}

/// A private folder beside the installed program, removed again however the upgrade ends.
struct WorkDir(PathBuf);

impl WorkDir {
    fn create(beside: &Path) -> Result<Self, String> {
        let dir = beside.parent().ok_or("cannot find the install folder")?;
        for n in 0..100u32 {
            let path = dir.join(format!(".blaze-upgrade-{}-{n}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Err(format!(
                        "cannot write to {} ({e}). Run the upgrade with permission to change that folder, or install blaze into a folder you own",
                        dir.display()
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "cannot prepare {} for the upgrade: {e}",
                        dir.display()
                    ));
                }
            }
        }
        Err("cannot create a work folder for the upgrade".to_owned())
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn install_binary(ctx: &Context, source: &dyn Source, target: &Version) -> Result<(), String> {
    let triple = ctx.triple.ok_or_else(|| {
        "there is no prebuilt BlazeServe for this platform; build it with: cargo install blazeserve --locked"
            .to_owned()
    })?;
    let tag = target.tag();
    let windows = triple.contains("windows");
    let stem = format!("blazeserve-{tag}-{triple}");
    let asset = format!("{stem}.{}", if windows { "zip" } else { "tar.gz" });
    let exe_name = if windows { "blaze.exe" } else { "blaze" };

    let work = WorkDir::create(&ctx.exe)?;

    anstream::eprintln!("Checking {asset} against SHA256SUMS");
    let mut sums = Vec::new();
    source.download(&tag, "SHA256SUMS", MAX_SUMS_BYTES, &mut sums)?;
    let sums = String::from_utf8_lossy(&sums);
    let expected = source::checksum_for(&sums, &asset)
        .ok_or_else(|| format!("SHA256SUMS has no entry for {asset}"))?;

    anstream::eprintln!("Downloading {asset}");
    let archive_path = work.0.join(&asset);
    let file = std::fs::File::create(&archive_path)
        .map_err(|e| format!("cannot create the download file: {e}"))?;
    let mut writer = HashingWriter::new(file);
    source.download(&tag, &asset, MAX_ARCHIVE_BYTES, &mut writer)?;
    writer
        .flush()
        .map_err(|e| format!("cannot write the download: {e}"))?;
    let (file, actual) = writer.finish();
    drop(file);
    if actual != expected {
        return Err(format!(
            "the download does not match its checksum (expected {expected}, got {actual}); nothing was changed"
        ));
    }

    let staged = work.0.join("staged");
    let mut out = std::fs::File::create(&staged)
        .map_err(|e| format!("cannot create the new program file: {e}"))?;
    archive::extract_binary(&archive_path, &format!("{stem}/{exe_name}"), &mut out)?;
    out.flush()
        .map_err(|e| format!("cannot write the new program: {e}"))?;
    drop(out);
    crate::platform::copy_executable_permissions(&ctx.exe, &staged)
        .map_err(|e| format!("cannot make the new program executable: {e}"))?;

    replace::replace_executable(&ctx.exe, &staged)
}

#[cfg(test)]
mod tests;
