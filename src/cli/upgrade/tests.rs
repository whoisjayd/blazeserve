use super::*;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;

const LINUX: &str = "x86_64-unknown-linux-gnu";
const WINDOWS: &str = "x86_64-pc-windows-msvc";

struct FakeSource {
    latest: String,
    files: HashMap<String, Vec<u8>>,
    calls: RefCell<Vec<String>>,
}

impl FakeSource {
    fn new(latest: &str) -> Self {
        Self {
            latest: latest.to_owned(),
            files: HashMap::new(),
            calls: RefCell::new(Vec::new()),
        }
    }

    /// Serves `archive` for `triple` at `tag`, with a matching SHA256SUMS.
    fn with_release(mut self, tag: &str, triple: &str, archive: Vec<u8>) -> Self {
        let asset = asset_name(tag, triple);
        let sums = format!("{}  {asset}\n", hex_digest(&archive));
        self.files
            .insert("SHA256SUMS".to_owned(), sums.into_bytes());
        self.files.insert(asset, archive);
        self
    }
}

impl Source for FakeSource {
    fn latest_tag(&self) -> Result<String, String> {
        self.calls.borrow_mut().push("latest".to_owned());
        Ok(self.latest.clone())
    }

    fn download(
        &self,
        _tag: &str,
        asset: &str,
        limit: u64,
        sink: &mut dyn Write,
    ) -> Result<(), String> {
        self.calls.borrow_mut().push(asset.to_owned());
        let data = self
            .files
            .get(asset)
            .ok_or_else(|| format!("{asset} was not found"))?;
        assert!(data.len() as u64 <= limit);
        sink.write_all(data).map_err(|e| e.to_string())
    }
}

#[derive(Default)]
struct FakeRunner {
    calls: RefCell<Vec<(PathBuf, Vec<String>)>>,
    fail: bool,
}

impl Runner for FakeRunner {
    fn run(&self, program: &Path, args: &[String]) -> Result<bool, String> {
        self.calls
            .borrow_mut()
            .push((program.to_owned(), args.to_vec()));
        Ok(!self.fail)
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    crate::cli::util::hex(&Sha256::digest(bytes))
}

fn asset_name(tag: &str, triple: &str) -> String {
    let ext = if triple.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("blazeserve-{tag}-{triple}.{ext}")
}

fn archive_with(tag: &str, triple: &str, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let stem = format!("blazeserve-{tag}-{triple}");
    let named: Vec<(String, &[u8])> = entries
        .iter()
        .map(|(n, d)| {
            (
                if n.starts_with("..") {
                    (*n).to_owned()
                } else {
                    format!("{stem}/{n}")
                },
                *d,
            )
        })
        .collect();
    if triple.contains("windows") {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, data) in &named {
            w.start_file(name.as_str(), zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    } else {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in &named {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&b.into_inner().unwrap()).unwrap();
        gz.finish().unwrap()
    }
}

fn context(channel: Channel, exe: &Path, interactive: bool) -> Context {
    Context {
        current: Version::parse("1.0.0").unwrap(),
        exe: exe.to_owned(),
        channel,
        python: Some(PathBuf::from("/venv/bin/python")),
        triple: Some(LINUX),
        interactive,
    }
}

fn opts(check: bool, version: Option<&str>, yes: bool) -> Opts {
    Opts {
        check,
        version: version.map(|v| Version::parse(v).unwrap()),
        yes,
    }
}

fn go(
    opts: &Opts,
    ctx: &Context,
    source: &FakeSource,
    runner: &FakeRunner,
    answer: bool,
) -> Result<Report, String> {
    execute(
        opts,
        ctx,
        &Deps {
            source,
            runner,
            confirm: &move |_| answer,
        },
    )
}

fn exe_in(dir: &Path) -> PathBuf {
    let exe = dir.join("blaze");
    std::fs::write(&exe, b"OLD").unwrap();
    exe
}

fn leftovers(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn check_reports_a_newer_release_without_changing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(Channel::Binary, &exe_in(dir.path()), false);
    let source = FakeSource::new("v1.2.0");
    let r = go(
        &opts(true, None, false),
        &ctx,
        &source,
        &FakeRunner::default(),
        false,
    )
    .unwrap();
    assert!(r.update_available);
    assert_eq!(
        (r.current.as_str(), r.latest.as_deref()),
        ("1.0.0", Some("1.2.0"))
    );
    assert_eq!(r.status, "update_available");
    assert_eq!(*source.calls.borrow(), ["latest"]);
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["update_available"], true);
    assert_eq!(json["channel"], "binary");
}

#[test]
fn check_when_current_or_ahead_is_up_to_date() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(Channel::Binary, &exe_in(dir.path()), false);
    for latest in ["v1.0.0", "v0.9.0"] {
        let r = go(
            &opts(true, None, false),
            &ctx,
            &FakeSource::new(latest),
            &FakeRunner::default(),
            false,
        )
        .unwrap();
        assert!(!r.update_available, "{latest}");
        assert_eq!(r.status, "up_to_date");
    }
}

#[test]
fn a_prerelease_is_never_the_default_target() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(Channel::Binary, &exe_in(dir.path()), false);
    let err = go(
        &opts(true, None, false),
        &ctx,
        &FakeSource::new("v2.0.0-rc.1"),
        &FakeRunner::default(),
        false,
    )
    .unwrap_err();
    assert!(err.contains("pre-release"), "{err}");
}

#[test]
fn up_to_date_does_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(Channel::Pip, &exe_in(dir.path()), false);
    let runner = FakeRunner::default();
    let r = go(
        &opts(false, None, true),
        &ctx,
        &FakeSource::new("v1.0.0"),
        &runner,
        false,
    )
    .unwrap();
    assert_eq!(r.status, "up_to_date");
    assert!(runner.calls.borrow().is_empty());
}

#[test]
fn without_a_terminal_an_upgrade_needs_yes_and_touches_no_network() {
    let dir = tempfile::tempdir().unwrap();
    let source = FakeSource::new("v1.2.0");
    for channel in [Channel::Binary, Channel::Pip, Channel::Cargo] {
        let ctx = context(channel, &exe_in(dir.path()), false);
        let runner = FakeRunner::default();
        let err = go(&opts(false, None, false), &ctx, &source, &runner, true).unwrap_err();
        assert!(err.contains("--yes"), "{err}");
        assert!(runner.calls.borrow().is_empty());
    }
    assert!(source.calls.borrow().is_empty());
}

#[test]
fn declining_the_prompt_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(Channel::Cargo, &exe_in(dir.path()), true);
    let runner = FakeRunner::default();
    let r = go(
        &opts(false, None, false),
        &ctx,
        &FakeSource::new("v1.2.0"),
        &runner,
        false,
    )
    .unwrap();
    assert_eq!(r.status, "cancelled");
    assert!(runner.calls.borrow().is_empty());
}

#[test]
fn pip_runs_pip_with_the_launching_interpreter_and_no_shell() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(Channel::Pip, &exe_in(dir.path()), false);
    let runner = FakeRunner::default();
    let r = go(
        &opts(false, None, true),
        &ctx,
        &FakeSource::new("v1.2.0"),
        &runner,
        false,
    )
    .unwrap();
    assert_eq!(r.status, "upgraded");
    let calls = runner.calls.borrow();
    assert_eq!(calls[0].0, Path::new("/venv/bin/python"));
    assert_eq!(
        calls[0].1,
        ["-m", "pip", "install", "--upgrade", "blazeserve"]
    );

    let runner = FakeRunner::default();
    go(
        &opts(false, Some("0.9.0"), true),
        &ctx,
        &FakeSource::new("v1.2.0"),
        &runner,
        false,
    )
    .unwrap();
    assert_eq!(
        runner.calls.borrow()[0].1.last().unwrap(),
        "blazeserve==0.9.0"
    );
}

#[test]
fn pip_failure_and_unknown_interpreter_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let mut ctx = context(Channel::Pip, &exe_in(dir.path()), false);
    let failing = FakeRunner {
        fail: true,
        ..Default::default()
    };
    assert!(
        go(
            &opts(false, None, true),
            &ctx,
            &FakeSource::new("v1.2.0"),
            &failing,
            false
        )
        .is_err()
    );
    ctx.python = None;
    let runner = FakeRunner::default();
    let err = go(
        &opts(false, None, true),
        &ctx,
        &FakeSource::new("v1.2.0"),
        &runner,
        false,
    )
    .unwrap_err();
    assert!(err.contains("python -m pip"), "{err}");
    assert!(runner.calls.borrow().is_empty());
}

#[test]
fn cargo_reinstalls_locked_and_forced() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(Channel::Cargo, &exe_in(dir.path()), true);
    let runner = FakeRunner::default();
    go(
        &opts(false, None, true),
        &ctx,
        &FakeSource::new("v1.2.0"),
        &runner,
        false,
    )
    .unwrap();
    assert_eq!(runner.calls.borrow()[0].0, Path::new("cargo"));
    assert_eq!(
        runner.calls.borrow()[0].1,
        ["install", "blazeserve", "--locked", "--force"]
    );

    let runner = FakeRunner::default();
    go(
        &opts(false, Some("1.1.0-rc.1"), true),
        &ctx,
        &FakeSource::new("v1.2.0"),
        &runner,
        false,
    )
    .unwrap();
    assert_eq!(runner.calls.borrow()[0].1[4..], ["--version", "1.1.0-rc.1"]);
}

#[test]
fn docker_and_package_managers_only_get_instructions() {
    let dir = tempfile::tempdir().unwrap();
    let managed = Channel::Managed {
        manager: "Homebrew",
        command: "brew upgrade blazeserve",
    };
    for (channel, want) in [
        (
            Channel::Docker,
            "docker pull ghcr.io/whoisjayd/blazeserve:v1.2.0",
        ),
        (managed, "brew upgrade blazeserve"),
    ] {
        let ctx = context(channel, &exe_in(dir.path()), false);
        let runner = FakeRunner::default();
        let r = go(
            &opts(false, None, false),
            &ctx,
            &FakeSource::new("v1.2.0"),
            &runner,
            true,
        )
        .unwrap();
        assert_eq!(r.status, "manual");
        assert!(r.message.contains(want), "{}", r.message);
        assert!(runner.calls.borrow().is_empty());
        assert_eq!(std::fs::read(&ctx.exe).unwrap(), b"OLD");
    }
}

#[test]
fn a_downgrade_needs_an_explicit_version() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(Channel::Cargo, &exe_in(dir.path()), false);
    let runner = FakeRunner::default();
    let r = go(
        &opts(false, None, true),
        &ctx,
        &FakeSource::new("v0.9.0"),
        &runner,
        false,
    )
    .unwrap();
    assert_eq!(r.status, "up_to_date");
    assert!(runner.calls.borrow().is_empty());
    go(
        &opts(false, Some("0.9.0"), true),
        &ctx,
        &FakeSource::new("v0.9.0"),
        &runner,
        false,
    )
    .unwrap();
    assert_eq!(runner.calls.borrow().len(), 1);
}

fn binary_source(tag: &str, triple: &str, entries: &[(&str, &[u8])]) -> FakeSource {
    FakeSource::new(tag).with_release(tag, triple, archive_with(tag, triple, entries))
}

#[test]
fn binary_upgrade_replaces_the_program_and_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let exe = exe_in(dir.path());
    let ctx = context(Channel::Binary, &exe, false);
    let source = binary_source("v1.2.0", LINUX, &[("blaze", b"NEW"), ("LICENSE", b"mit")]);
    let r = go(
        &opts(false, None, true),
        &ctx,
        &source,
        &FakeRunner::default(),
        false,
    )
    .unwrap();
    assert_eq!(r.status, "upgraded");
    assert_eq!(std::fs::read(&exe).unwrap(), b"NEW");
    assert!(
        !leftovers(dir.path())
            .iter()
            .any(|n| n.starts_with(".blaze-upgrade"))
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            std::fs::metadata(&exe).unwrap().permissions().mode() & 0o111,
            0
        );
    }
}

#[test]
fn binary_upgrade_reads_the_windows_zip_layout() {
    let dir = tempfile::tempdir().unwrap();
    let exe = exe_in(dir.path());
    let mut ctx = context(Channel::Binary, &exe, false);
    ctx.triple = Some(WINDOWS);
    let source = binary_source(
        "v1.2.0",
        WINDOWS,
        &[("blaze.exe", b"NEW-WIN"), ("README.md", b"r")],
    );
    go(
        &opts(false, None, true),
        &ctx,
        &source,
        &FakeRunner::default(),
        false,
    )
    .unwrap();
    assert_eq!(std::fs::read(&exe).unwrap(), b"NEW-WIN");
}

#[test]
fn a_checksum_mismatch_replaces_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let exe = exe_in(dir.path());
    let ctx = context(Channel::Binary, &exe, false);
    let mut source = binary_source("v1.2.0", LINUX, &[("blaze", b"NEW")]);
    let wrong = format!("{}  {}\n", "0".repeat(64), asset_name("v1.2.0", LINUX));
    source
        .files
        .insert("SHA256SUMS".to_owned(), wrong.into_bytes());
    let err = go(
        &opts(false, None, true),
        &ctx,
        &source,
        &FakeRunner::default(),
        false,
    )
    .unwrap_err();
    assert!(err.contains("checksum"), "{err}");
    assert_eq!(std::fs::read(&exe).unwrap(), b"OLD");
    assert_eq!(leftovers(dir.path()), ["blaze"]);
}

#[test]
fn a_missing_checksum_entry_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let exe = exe_in(dir.path());
    let ctx = context(Channel::Binary, &exe, false);
    let mut source = binary_source("v1.2.0", LINUX, &[("blaze", b"NEW")]);
    source.files.insert("SHA256SUMS".to_owned(), b"".to_vec());
    let err = go(
        &opts(false, None, true),
        &ctx,
        &source,
        &FakeRunner::default(),
        false,
    )
    .unwrap_err();
    assert!(err.contains("SHA256SUMS"), "{err}");
    assert_eq!(std::fs::read(&exe).unwrap(), b"OLD");
}

#[test]
fn a_corrupt_archive_with_a_valid_checksum_replaces_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let exe = exe_in(dir.path());
    let ctx = context(Channel::Binary, &exe, false);
    let source =
        FakeSource::new("v1.2.0").with_release("v1.2.0", LINUX, b"not an archive".to_vec());
    assert!(
        go(
            &opts(false, None, true),
            &ctx,
            &source,
            &FakeRunner::default(),
            false
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&exe).unwrap(), b"OLD");
    assert_eq!(leftovers(dir.path()), ["blaze"]);
}

#[test]
fn an_archive_with_a_traversal_entry_replaces_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let exe = exe_in(dir.path());
    let ctx = context(Channel::Binary, &exe, false);
    let source = binary_source(
        "v1.2.0",
        LINUX,
        &[("blaze", b"NEW"), ("../../escaped", b"x")],
    );
    let err = go(
        &opts(false, None, true),
        &ctx,
        &source,
        &FakeRunner::default(),
        false,
    )
    .unwrap_err();
    assert!(err.contains("unsafe path"), "{err}");
    assert_eq!(std::fs::read(&exe).unwrap(), b"OLD");
    assert_eq!(leftovers(dir.path()), ["blaze"]);
}

#[test]
fn an_unsupported_platform_points_at_cargo() {
    let dir = tempfile::tempdir().unwrap();
    let mut ctx = context(Channel::Binary, &exe_in(dir.path()), false);
    ctx.triple = None;
    let err = go(
        &opts(false, None, true),
        &ctx,
        &FakeSource::new("v1.2.0"),
        &FakeRunner::default(),
        false,
    )
    .unwrap_err();
    assert!(err.contains("cargo install"), "{err}");
}
