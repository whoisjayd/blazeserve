mod cli_support;

use blazeserve::config::Config;
use cli_support::{blaze, canonical, code, pattern, stderr, stdout};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

const MIB: usize = 1024 * 1024;

async fn serve(dir: &Path) -> blazeserve::server::ServerHandle {
    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: canonical(dir),
        max_upload_bytes: 64 * MIB as u64,
        ..Config::default()
    };
    blazeserve::server::start(config)
        .await
        .expect("start server")
}

/// One isolated job registry per test, shared by every `blaze` call it makes.
struct Env {
    state: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            state: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self) -> PathBuf {
        self.state.path().to_path_buf()
    }

    async fn run(&self, args: &[&str]) -> Output {
        let state = self.path();
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        tokio::task::spawn_blocking(move || {
            // On Windows a child spawned at the same moment can inherit another call's
            // pipe handles and hold its output open, so spawns take turns.
            static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let child = {
                let _turn = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
                blaze()
                    .env("BLAZE_STATE_DIR", state)
                    .args(args)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .expect("spawn blaze")
            };
            child.wait_with_output().expect("wait for blaze")
        })
        .await
        .unwrap()
    }

    /// Starts a background job and returns its ID.
    async fn launch(&self, args: &[&str]) -> String {
        let mut full = args.to_vec();
        full.push("--background");
        let out = self.run(&full).await;
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        let id = stdout(&out).trim().to_owned();
        assert_eq!(id.len(), 8, "stdout should be just the job ID: {id:?}");
        id
    }

    async fn job(&self, id: &str) -> Value {
        let out = self.run(&["status", id, "--json"]).await;
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        let v: Value = serde_json::from_str(&stdout(&out)).expect("status --json is JSON");
        v["jobs"][0].clone()
    }

    async fn wait_until(&self, id: &str, what: &str, done: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let job = self.job(id).await;
            if done(&job) {
                return job;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}: {job}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_finished(&self, id: &str) -> Value {
        self.wait_until(id, "the job to finish", |j| {
            !matches!(
                j["state"].as_str(),
                Some("starting" | "running" | "stopping")
            )
        })
        .await
    }

    async fn stop(&self, id: &str) -> Output {
        self.run(&["stop", id, "--yes"]).await
    }

    fn all_text(&self) -> String {
        let mut all = String::new();
        for e in std::fs::read_dir(self.state.path().join("jobs")).unwrap() {
            let p = e.unwrap().path();
            all.push_str(&String::from_utf8_lossy(&std::fs::read(&p).unwrap()));
        }
        all
    }
}

fn s(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_get_runs_to_completion_and_the_result_stays_inspectable() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(3 * MIB + 5);
    std::fs::write(served.path().join("big.bin"), &data).unwrap();
    let server = serve(served.path()).await;
    let url = format!("http://{}/big.bin", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("big.bin");
    let env = Env::new();

    let id = env.launch(&["get", &url, "-o", &s(&dest)]).await;
    let job = env.wait_finished(&id).await;

    assert_eq!(job["state"], "completed", "{job}");
    assert_eq!(job["kind"], "get");
    assert_eq!(job["direction"], "download");
    assert_eq!(job["label"], "big.bin");
    assert_eq!(job["bytes_done"], data.len());
    assert_eq!(job["bytes_total"], data.len());
    assert_eq!(job["percent"], 100.0);
    assert!(job["pid"].as_u64().unwrap() > 0);
    assert!(job["started_at"].as_u64().unwrap() <= job["updated_at"].as_u64().unwrap());
    assert!(Path::new(job["log"].as_str().unwrap()).exists());
    assert_eq!(std::fs::read(&dest).unwrap(), data);

    let text = env.run(&["status", &id]).await;
    assert_eq!(code(&text), 0);
    let text = stdout(&text);
    assert!(
        text.contains("completed") && text.contains("big.bin"),
        "{text}"
    );
    assert!(text.contains("result:") && text.contains("log:"), "{text}");
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parallel_download_is_one_job_without_double_counting() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(20 * MIB + 3);
    std::fs::write(served.path().join("seg.bin"), &data).unwrap();
    let server = serve(served.path()).await;
    let url = format!("http://{}/seg.bin", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("seg.bin");
    let env = Env::new();

    let id = env
        .launch(&[
            "get",
            &url,
            "-o",
            &s(&dest),
            "-c",
            "4",
            "--limit-rate",
            "8M",
        ])
        .await;
    let mut peak = 0u64;
    let job = loop {
        let job = env.job(&id).await;
        peak = peak.max(job["bytes_done"].as_u64().unwrap());
        if job["state"] != "running" && job["state"] != "starting" {
            break job;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(job["state"], "completed", "{job}");
    assert!(peak <= data.len() as u64, "progress overshot: {peak}");
    assert_eq!(job["bytes_done"], data.len());
    let all = env.run(&["status", "--all", "--json"]).await;
    let v: Value = serde_json::from_str(&stdout(&all)).unwrap();
    assert_eq!(
        v["jobs"].as_array().unwrap().len(),
        1,
        "one job, not one per connection"
    );
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_put_uploads_and_reports_an_upload() {
    let served = tempfile::tempdir().unwrap();
    let server = serve(served.path()).await;
    let src_dir = tempfile::tempdir().unwrap();
    let data = pattern(2 * MIB + 9);
    let src = src_dir.path().join("up.bin");
    std::fs::write(&src, &data).unwrap();
    let env = Env::new();

    let id = env
        .launch(&["put", &s(&src), &format!("http://{}", server.local_addr())])
        .await;
    let job = env.wait_finished(&id).await;

    assert_eq!(job["state"], "completed", "{job}");
    assert_eq!(job["direction"], "upload");
    assert_eq!(job["bytes_done"], data.len());
    assert_eq!(std::fs::read(served.path().join("up.bin")).unwrap(), data);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_byte_download_completes_with_a_known_empty_total() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("empty.txt"), b"").unwrap();
    let server = serve(served.path()).await;
    let url = format!("http://{}/empty.txt", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("empty.txt");
    let env = Env::new();

    let id = env.launch(&["get", &url, "-o", &s(&dest)]).await;
    let job = env.wait_finished(&id).await;
    assert_eq!(job["state"], "completed", "{job}");
    assert_eq!(job["bytes_done"], 0);
    assert!(job["percent"].is_null());
    assert!(dest.exists());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verification_failure_is_recorded_as_a_failed_job() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("abc.txt"), b"abc").unwrap();
    let server = serve(served.path()).await;
    let url = format!("http://{}/abc.txt", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("abc.txt");
    let env = Env::new();

    let id = env
        .launch(&["get", &url, "-o", &s(&dest), "--sha256", &"0".repeat(64)])
        .await;
    let job = env.wait_finished(&id).await;
    assert_eq!(job["state"], "failed", "{job}");
    assert!(job["result"].as_str().unwrap().contains("SHA-256 mismatch"));
    assert!(!dest.exists());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_network_failure_after_launch_belongs_to_the_job_not_the_launcher() {
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("x.bin");
    let env = Env::new();
    // Nothing listens on port 1.
    let id = env
        .launch(&[
            "get",
            "http://127.0.0.1:1/x.bin",
            "-o",
            &s(&dest),
            "--retries",
            "0",
        ])
        .await;
    let job = env.wait_finished(&id).await;
    assert_eq!(job["state"], "failed", "{job}");
    assert!(job["ready_at"].is_number());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn launch_errors_are_returned_to_the_caller_and_leave_no_job_behind() {
    let env = Env::new();
    let out = env
        .run(&[
            "get",
            "http://127.0.0.1:1/x.bin",
            "--sha256",
            "nothex",
            "--background",
        ])
        .await;
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("--sha256"), "{}", stderr(&out));
    assert!(stdout(&out).trim().is_empty(), "no job ID on failure");

    let out = env
        .run(&[
            "get",
            "http://127.0.0.1:1/x.bin",
            "--auth-env",
            "BLAZE_TEST_SURELY_UNSET_VAR",
            "--background",
        ])
        .await;
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("missing or empty"),
        "{}",
        stderr(&out)
    );

    let all = env.run(&["status", "--all", "--json"]).await;
    let v: Value = serde_json::from_str(&stdout(&all)).unwrap();
    assert_eq!(v["jobs"].as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_interrupts_a_transfer_and_keeps_resume_data() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(4 * MIB);
    std::fs::write(served.path().join("slow.bin"), &data).unwrap();
    let server = serve(served.path()).await;
    let url = format!("http://{}/slow.bin", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("slow.bin");
    let env = Env::new();

    let id = env
        .launch(&["get", &url, "-o", &s(&dest), "--limit-rate", "256K"])
        .await;
    let running = env
        .wait_until(&id, "progress", |j| {
            j["state"] == "running" && j["bytes_done"].as_u64().unwrap_or(0) > 0
        })
        .await;
    assert_eq!(running["phase"], "transferring");
    assert_eq!(running["bytes_total"], data.len());

    let out = env.stop(&id).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("interrupted"), "{}", stdout(&out));
    let job = env.job(&id).await;
    assert_eq!(job["state"], "interrupted", "{job}");
    assert!(!dest.exists());
    assert!(out_dir.path().join("slow.bin.part").exists());
    assert!(out_dir.path().join("slow.bin.part.meta").exists());

    // The partial file resumes: only the missing tail crosses the wire.
    let before = server.state().metrics.bytes_sent();
    let resumed = env.run(&["get", &url, "-o", &s(&dest)]).await;
    assert_eq!(code(&resumed), 0, "{}", stderr(&resumed));
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    assert!(server.state().metrics.bytes_sent() - before < data.len() as u64);

    // Stopping a finished job reports it and changes nothing.
    let again = env.stop(&id).await;
    assert_eq!(code(&again), 0);
    assert!(stdout(&again).contains("interrupted"));
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_asks_first_and_never_stops_without_a_yes() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("slow.bin"), pattern(4 * MIB)).unwrap();
    let server = serve(served.path()).await;
    let url = format!("http://{}/slow.bin", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("slow.bin");
    let env = Env::new();
    let id = env
        .launch(&["get", &url, "-o", &s(&dest), "--limit-rate", "128K"])
        .await;
    env.wait_until(&id, "progress", |j| {
        j["state"] == "running" && j["bytes_done"].as_u64().unwrap_or(0) > 0
    })
    .await;

    // No terminal and no --yes: refuse, and say what would have been stopped.
    let out = env.run(&["stop", &id]).await;
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("slow.bin"),
        "progress shown: {}",
        stderr(&out)
    );
    assert_eq!(env.job(&id).await["state"], "running");

    let out = env.stop(&id).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_and_stop_reject_unknown_and_malformed_ids() {
    let env = Env::new();
    for args in [
        vec!["status", "deadbeef"],
        vec!["stop", "deadbeef", "--yes"],
        vec!["status", "../../etc"],
        vec!["stop", "NOTANID1", "--yes"],
    ] {
        let out = env.run(&args).await;
        assert_eq!(code(&out), 1, "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).starts_with("error:"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_registry_is_success_and_json_is_versioned() {
    let env = Env::new();
    let text = env.run(&["status"]).await;
    assert_eq!(code(&text), 0, "{}", stderr(&text));
    assert!(stdout(&text).contains("No active background jobs"));

    let json = env.run(&["status", "--json"]).await;
    assert_eq!(code(&json), 0);
    let v: Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(v["version"], 1);
    assert_eq!(v["jobs"].as_array().unwrap().len(), 0);
    assert!(v["generated_at"].as_u64().unwrap() > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_store_is_an_error_not_an_empty_list() {
    let blocker = tempfile::tempdir().unwrap();
    // The jobs folder cannot be created because a file sits in its place.
    std::fs::write(blocker.path().join("jobs"), b"not a folder").unwrap();
    let out = tokio::task::spawn_blocking({
        let dir = blocker.path().to_path_buf();
        move || {
            blaze()
                .env("BLAZE_STATE_DIR", dir)
                .args(["status"])
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("job store"), "{}", stderr(&out));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_and_watch_cannot_be_combined() {
    let env = Env::new();
    let out = env.run(&["status", "--json", "--watch"]).await;
    assert_eq!(code(&out), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_and_signed_queries_never_reach_the_registry_or_log() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("c.bin"), pattern(64 * 1024)).unwrap();
    let server = serve(served.path()).await;
    let addr = server.local_addr();
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("c.bin");
    let env = Env::new();

    let url = format!("http://hunteruser:hunterpass2@{addr}/c.bin?X-Signature=SIGSECRET9");
    let id = env.launch(&["get", &url, "-o", &s(&dest)]).await;
    let job = env.wait_finished(&id).await;
    // Whether the server accepts the URL or not, nothing secret may be stored.
    assert!(
        job["remote"].as_str().is_none_or(|r| !r.contains('@')),
        "{job}"
    );
    let all = env.all_text();
    for secret in ["hunteruser", "hunterpass2", "SIGSECRET9", "X-Signature"] {
        assert!(
            !all.contains(secret),
            "{secret} leaked into the registry: {all}"
        );
    }

    let id = env
        .launch(&[
            "get",
            &format!("http://{addr}/c.bin"),
            "-o",
            &s(&out_dir.path().join("d.bin")),
            "--auth",
            "bob:PWSECRET7",
        ])
        .await;
    env.wait_finished(&id).await;
    let all = env.all_text();
    assert!(!all.contains("PWSECRET7") && !all.contains("bob:"), "{all}");
    server.shutdown().await;
}

/// A port that was free a moment ago; `blaze serve` has no port 0.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn http_get(port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

fn serve_args<'a>(path: &'a str, port: &'a str) -> Vec<&'a str> {
    vec!["serve", path, "--host", "127.0.0.1", "--port", port]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_serve_is_reachable_listed_as_a_server_and_stops_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.txt"), b"hello").unwrap();
    let port = free_port();
    let env = Env::new();

    let id = env
        .launch(&serve_args(&s(dir.path()), &port.to_string()))
        .await;
    // The launcher returns only once the socket is bound, so this connects at once.
    let reply = http_get(port, "/hello.txt").expect("server should already be listening");
    assert!(
        reply.starts_with("HTTP/1.1 200") && reply.ends_with("hello"),
        "{reply}"
    );

    let job = env.job(&id).await;
    assert_eq!(job["kind"], "serve");
    assert_eq!(job["state"], "running");
    assert_eq!(job["listen"], format!("http://127.0.0.1:{port}"));
    assert!(job["bytes_total"].is_null() && job["phase"].is_null());
    assert!(job["uptime_seconds"].is_number());
    let text = stdout(&env.run(&["status"]).await);
    assert!(
        text.contains(&format!("listening on http://127.0.0.1:{port}")),
        "{text}"
    );
    assert!(!text.contains("ETA"), "{text}");

    let out = env.stop(&id).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let said = stdout(&out);
    assert!(
        said.contains("stopped") && said.contains("graceful shutdown completed"),
        "{said}"
    );
    assert_eq!(env.job(&id).await["state"], "stopped");
    assert!(
        http_get(port, "/").is_none(),
        "the listener should be closed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_send_serves_one_file_under_its_name() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("report.pdf");
    std::fs::write(&file, b"pdf bytes").unwrap();
    let port = free_port();
    let env = Env::new();

    let id = env
        .launch(&[
            "send",
            &s(&file),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .await;
    let job = env.job(&id).await;
    assert_eq!(job["kind"], "send");
    assert_eq!(job["label"], "report.pdf");
    assert!(
        http_get(port, "/report.pdf")
            .unwrap()
            .ends_with("pdf bytes")
    );
    assert_eq!(code(&env.stop(&id).await), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_conflict_is_returned_to_the_launcher() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let env = Env::new();

    let (path, port) = (s(dir.path()), port.to_string());
    let mut args = serve_args(&path, &port);
    args.push("--background");
    let out = env.run(&args).await;
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("bind"), "{}", stderr(&out));
    assert!(stdout(&out).trim().is_empty());
    let all = env.run(&["status", "--all", "--json"]).await;
    let v: Value = serde_json::from_str(&stdout(&all)).unwrap();
    assert_eq!(v["jobs"].as_array().unwrap().len(), 0);
    drop(taken);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_password_variable_stops_a_server_launch() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::new();
    let out = env
        .run(&[
            "serve",
            &s(dir.path()),
            "--auth-env",
            "BLAZE_TEST_SURELY_UNSET_VAR",
            "--background",
        ])
        .await;
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("missing or empty"),
        "{}",
        stderr(&out)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transfers_and_servers_run_side_by_side_and_are_told_apart() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("slow.bin"), pattern(2 * MIB)).unwrap();
    let port = free_port();
    let env = Env::new();
    let server = env
        .launch(&serve_args(&s(dir.path()), &port.to_string()))
        .await;
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("slow.bin");
    let url = format!("http://127.0.0.1:{port}/slow.bin");
    let get = env
        .launch(&["get", &url, "-o", &s(&dest), "--limit-rate", "128K"])
        .await;
    env.wait_until(&get, "progress", |j| {
        j["state"] == "running" && j["bytes_done"].as_u64().unwrap_or(0) > 0
    })
    .await;

    let out = env.run(&["status", "--json"]).await;
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    let jobs = v["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 2);
    let kinds: Vec<_> = jobs.iter().map(|j| j["kind"].as_str().unwrap()).collect();
    assert!(
        kinds.contains(&"serve") && kinds.contains(&"get"),
        "{kinds:?}"
    );

    assert_eq!(code(&env.stop(&get).await), 0);
    assert_eq!(code(&env.stop(&server).await), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_launcher_exits_while_the_worker_keeps_running() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("slow.bin"), pattern(2 * MIB)).unwrap();
    let server = serve(served.path()).await;
    let url = format!("http://{}/slow.bin", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("slow.bin");
    let env = Env::new();

    // `launch` returns only after the launching process has exited and its pipes closed.
    let id = env
        .launch(&["get", &url, "-o", &s(&dest), "--limit-rate", "128K"])
        .await;
    let job = env.job(&id).await;
    assert!(matches!(job["state"].as_str(), Some("running")), "{job}");
    let out = env.stop(&id).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    server.shutdown().await;
}
