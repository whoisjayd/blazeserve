mod cli_support;

use cli_support::{blaze, code, stderr, stdout};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

const NEW_VERSION: &str = "9.9.9";

fn host_triple() -> &'static str {
    match (
        std::env::consts::OS,
        std::env::consts::ARCH,
        cfg!(target_env = "musl"),
    ) {
        ("linux", "x86_64", false) => "x86_64-unknown-linux-gnu",
        ("linux", "x86_64", true) => "x86_64-unknown-linux-musl",
        ("linux", "aarch64", false) => "aarch64-unknown-linux-gnu",
        ("linux", "aarch64", true) => "aarch64-unknown-linux-musl",
        ("windows", _, _) => "x86_64-pc-windows-msvc",
        ("macos", "x86_64", _) => "x86_64-apple-darwin",
        ("macos", _, _) => "aarch64-apple-darwin",
        other => panic!("no release target for {other:?}"),
    }
}

fn windows_host() -> bool {
    cfg!(windows)
}

fn asset_stem() -> String {
    format!("blazeserve-v{NEW_VERSION}-{}", host_triple())
}

fn asset_name() -> String {
    format!(
        "{}.{}",
        asset_stem(),
        if windows_host() { "zip" } else { "tar.gz" }
    )
}

fn exe_name() -> &'static str {
    if windows_host() { "blaze.exe" } else { "blaze" }
}

fn build_archive(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    if windows_host() {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, data) in entries {
            w.start_file(name.as_str(), zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    } else {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_cksum();
            b.append(&h, data.as_slice()).unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&b.into_inner().unwrap()).unwrap();
        gz.finish().unwrap()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A release server on loopback port 0 that serves canned responses and records requests.
struct Origin {
    port: u16,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    thread: Option<JoinHandle<()>>,
}

impl Origin {
    fn start(routes: HashMap<String, (u16, Vec<u8>)>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (flag, log) = (stop.clone(), requests.clone());
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(stream) = stream {
                    serve(stream, &routes, &log);
                }
            }
        });
        Self {
            port,
            stop,
            requests,
            thread: Some(thread),
        }
    }

    fn paths(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.0.clone())
            .collect()
    }

    fn env(&self, cmd: &mut Command) {
        cmd.env(
            "BLAZE_UPGRADE_API",
            format!("http://127.0.0.1:{}/api", self.port),
        )
        .env(
            "BLAZE_UPGRADE_DOWNLOADS",
            format!("http://127.0.0.1:{}/dl", self.port),
        );
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port));
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn serve(
    mut stream: TcpStream,
    routes: &HashMap<String, (u16, Vec<u8>)>,
    log: &Mutex<Vec<(String, String)>>,
) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
    let agent = head
        .lines()
        .find_map(|l| {
            l.strip_prefix("user-agent: ")
                .or_else(|| l.strip_prefix("User-Agent: "))
        })
        .unwrap_or("")
        .to_owned();
    log.lock().unwrap().push((path.clone(), agent));
    let (status, body) = routes
        .get(&path)
        .cloned()
        .unwrap_or((404, b"not found".to_vec()));
    let reason = if status == 200 { "OK" } else { "Error" };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(&body);
}

fn latest_json(version: &str) -> (u16, Vec<u8>) {
    (
        200,
        format!(r#"{{"tag_name":"v{version}","draft":false,"prerelease":false}}"#).into_bytes(),
    )
}

fn release_routes(archive: Vec<u8>, sums_hash: &str) -> HashMap<String, (u16, Vec<u8>)> {
    let mut routes = HashMap::new();
    routes.insert("/api/releases/latest".to_owned(), latest_json(NEW_VERSION));
    let sums = format!("{sums_hash}  {}\n", asset_name());
    routes.insert(
        format!("/dl/v{NEW_VERSION}/SHA256SUMS"),
        (200, sums.into_bytes()),
    );
    routes.insert(
        format!("/dl/v{NEW_VERSION}/{}", asset_name()),
        (200, archive),
    );
    routes
}

fn good_archive(binary: &[u8]) -> Vec<u8> {
    build_archive(&[
        (format!("{}/LICENSE", asset_stem()), b"MIT".to_vec()),
        (format!("{}/{}", asset_stem(), exe_name()), binary.to_vec()),
    ])
}

/// A private copy of the blaze binary, so the test binary itself is never replaced.
struct Install {
    _dir: tempfile::TempDir,
    exe: PathBuf,
    original: Vec<u8>,
}

fn install_copy() -> Install {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join(exe_name());
    std::fs::copy(env!("CARGO_BIN_EXE_blaze"), &exe).unwrap();
    let original = std::fs::read(&exe).unwrap();
    Install {
        _dir: dir,
        exe,
        original,
    }
}

fn upgrade_cmd(exe: &Path, origin: Option<&Origin>) -> Command {
    let mut cmd = Command::new(exe);
    cmd.env("NO_COLOR", "1")
        .env("BLAZE_INSTALL_CHANNEL", "binary")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env_remove("BLAZE_PYTHON")
        .stdin(std::process::Stdio::null());
    if let Some(origin) = origin {
        origin.env(&mut cmd);
    }
    cmd
}

fn out(cmd: &mut Command) -> Output {
    cmd.output().expect("spawn blaze")
}

#[test]
fn check_json_says_when_a_newer_release_exists() {
    let origin = Origin::start(HashMap::from([(
        "/api/releases/latest".to_owned(),
        latest_json(NEW_VERSION),
    )]));
    let mut cmd = blaze();
    origin.env(&mut cmd);
    let o = out(cmd
        .args(["upgrade", "--check", "--json"])
        .env("NO_PROXY", "127.0.0.1"));
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["current"], blazeserve::VERSION);
    assert_eq!(v["latest"], NEW_VERSION);
    assert_eq!(v["update_available"], true);
    let requests = origin.requests.lock().unwrap();
    assert!(
        requests[0].1.starts_with("blazeserve-upgrade/"),
        "{requests:?}"
    );
}

#[test]
fn check_is_quiet_success_when_up_to_date() {
    let origin = Origin::start(HashMap::from([(
        "/api/releases/latest".to_owned(),
        latest_json(blazeserve::VERSION),
    )]));
    let mut cmd = blaze();
    origin.env(&mut cmd);
    let o = out(cmd
        .args(["upgrade", "--check", "--json"])
        .env("NO_PROXY", "127.0.0.1"));
    assert_eq!(code(&o), 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["update_available"], false);

    let mut cmd = blaze();
    origin.env(&mut cmd);
    let o = out(cmd
        .args(["upgrade", "--check"])
        .env("NO_PROXY", "127.0.0.1"));
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("latest version"), "{}", stdout(&o));
}

#[test]
fn an_unreachable_or_missing_release_is_an_error_not_a_crash() {
    let origin = Origin::start(HashMap::new());
    let mut cmd = blaze();
    origin.env(&mut cmd);
    let o = out(cmd
        .args(["upgrade", "--check"])
        .env("NO_PROXY", "127.0.0.1"));
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("not found"), "{}", stderr(&o));
}

#[test]
fn plain_http_to_a_remote_host_is_refused_before_any_request() {
    let o = out(blaze()
        .args(["upgrade", "--check"])
        .env("BLAZE_UPGRADE_API", "http://example.com/api"));
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("https"), "{}", stderr(&o));
}

#[test]
fn without_a_terminal_an_upgrade_needs_yes() {
    let origin = Origin::start(HashMap::new());
    let install = install_copy();
    let o = out(upgrade_cmd(&install.exe, Some(&origin)).arg("upgrade"));
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("--yes"), "{}", stderr(&o));
    assert!(origin.paths().is_empty());
    assert_eq!(std::fs::read(&install.exe).unwrap(), install.original);
}

#[test]
fn upgrade_replaces_a_copy_of_the_program() {
    let new_bytes = b"NEW PROGRAM BYTES".to_vec();
    let archive = good_archive(&new_bytes);
    let origin = Origin::start(release_routes(archive.clone(), &sha256_hex(&archive)));
    let install = install_copy();
    let o = out(upgrade_cmd(&install.exe, Some(&origin)).args(["upgrade", "--yes"]));
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains(NEW_VERSION), "{}", stdout(&o));
    assert_eq!(std::fs::read(&install.exe).unwrap(), new_bytes);
    let dir = install.exe.parent().unwrap();
    let names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !names.iter().any(|n| n.starts_with(".blaze-upgrade")),
        "{names:?}"
    );
    if windows_host() {
        let backup = dir.join(format!("{}.old", exe_name()));
        assert_eq!(std::fs::read(backup).unwrap(), install.original);
    } else {
        assert_eq!(names.len(), 1, "{names:?}");
    }
}

#[test]
fn a_checksum_mismatch_leaves_the_program_alone() {
    let archive = good_archive(b"NEW PROGRAM BYTES");
    let origin = Origin::start(release_routes(archive, &"0".repeat(64)));
    let install = install_copy();
    let o = out(upgrade_cmd(&install.exe, Some(&origin)).args(["upgrade", "--yes"]));
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("checksum"), "{}", stderr(&o));
    assert_eq!(std::fs::read(&install.exe).unwrap(), install.original);
}

#[test]
fn an_archive_that_tries_to_escape_is_rejected() {
    let archive = build_archive(&[
        (format!("{}/{}", asset_stem(), exe_name()), b"NEW".to_vec()),
        ("../escaped".to_owned(), b"x".to_vec()),
    ]);
    let origin = Origin::start(release_routes(archive.clone(), &sha256_hex(&archive)));
    let install = install_copy();
    let o = out(upgrade_cmd(&install.exe, Some(&origin)).args(["upgrade", "--yes"]));
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("unsafe path"), "{}", stderr(&o));
    assert_eq!(std::fs::read(&install.exe).unwrap(), install.original);
    assert!(
        !install
            .exe
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("escaped")
            .exists()
    );
}

#[test]
fn a_corrupt_archive_leaves_the_program_alone() {
    let archive = b"definitely not an archive".to_vec();
    let origin = Origin::start(release_routes(archive.clone(), &sha256_hex(&archive)));
    let install = install_copy();
    let o = out(upgrade_cmd(&install.exe, Some(&origin)).args(["upgrade", "--yes"]));
    assert_eq!(code(&o), 1);
    assert_eq!(std::fs::read(&install.exe).unwrap(), install.original);
}

#[test]
fn a_container_only_gets_pull_instructions() {
    let origin = Origin::start(HashMap::from([(
        "/api/releases/latest".to_owned(),
        latest_json(NEW_VERSION),
    )]));
    let install = install_copy();
    let o = out(upgrade_cmd(&install.exe, Some(&origin))
        .env("BLAZE_INSTALL_CHANNEL", "docker")
        .arg("upgrade"));
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).contains(&format!(
            "docker pull ghcr.io/whoisjayd/blazeserve:v{NEW_VERSION}"
        )),
        "{}",
        stdout(&o)
    );
    assert_eq!(std::fs::read(&install.exe).unwrap(), install.original);
}
