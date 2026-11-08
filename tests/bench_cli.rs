use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MIB: u64 = 1024 * 1024;

struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    /// Private temp directory handed to the child, so leftovers are attributable to it.
    fn scratch(&self) -> PathBuf {
        let p = self.dir.path().join("scratch");
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn blaze(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_blaze"))
            .args(args)
            .env("TMP", self.scratch())
            .env("TEMP", self.scratch())
            .env("TMPDIR", self.scratch())
            .env("NO_COLOR", "1")
            .output()
            .expect("run blaze")
    }

    fn scratch_is_empty(&self) -> bool {
        std::fs::read_dir(self.scratch()).unwrap().next().is_none()
    }
}

fn json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn workload<'a>(artifact: &'a Value, id: &str) -> &'a Value {
    artifact["workloads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["id"] == id)
        .unwrap_or_else(|| panic!("workload {id} missing"))
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn success_artifact(sb: &Sandbox, name: &str) -> PathBuf {
    let out = sb.file(name);
    let o = sb.blaze(&[
        "benchmark",
        "--runs",
        "3",
        "--warmup",
        "1",
        "--size-mb",
        "8",
        "--workload",
        "both",
        "--output",
        out.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    out
}

#[test]
fn success_artifact_is_complete_accounted_and_cleaned_up() {
    let sb = Sandbox::new();
    let path = success_artifact(&sb, "a.json");
    let a = json(&path);

    assert_eq!(a["schema_version"], 1);
    assert_eq!(a["complete"], true);
    assert_eq!(a["interrupted"], false);
    assert!(a["error"].is_null());
    assert_eq!(a["server"]["mode"], "isolated");
    assert_eq!(a["command"][0], "blaze");
    assert_eq!(a["protocol"]["runs"], 3);
    assert_eq!(a["protocol"]["warmup"], 1);
    assert_eq!(a["fixture"]["size_bytes"], 8 * MIB);
    assert_eq!(a["fixture"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(a["totals"]["ok"], 6);
    assert_eq!(a["totals"]["failed"], 0);

    let full = workload(&a, "full");
    let range = workload(&a, "range");
    assert_eq!(full["requested_bytes"], 8 * MIB);
    assert_eq!(range["requested_bytes"], 4 * MIB);
    for (w, bytes, http) in [(full, 8 * MIB, 200), (range, 4 * MIB, 206)] {
        let samples = w["samples"].as_array().unwrap();
        assert_eq!(samples.len(), 3, "warm-up samples are not recorded");
        for s in samples {
            assert_eq!(s["status"], "ok");
            assert_eq!(s["downloaded_bytes"], bytes);
            assert_eq!(s["http_status"], http);
            assert!(s["throughput_mib_per_second"].as_f64().unwrap() > 0.0);
            assert!(s["failure"].is_null());
        }
        assert_eq!(w["summary"]["samples_used"], 3);
        assert_eq!(w["summary"]["unit"], "MiB/s");
        assert!(w["summary"]["median"].as_f64().unwrap() > 0.0);
    }

    for key in [
        "os_version",
        "cpu_count",
        "cpu_model",
        "memory_total_bytes",
        "filesystem",
    ] {
        let fact = &a["environment"][key];
        assert!(
            fact["value"].is_null() != fact["reason"].is_null(),
            "{key} must hold exactly one of value and reason: {fact}"
        );
    }
    assert!(sb.scratch_is_empty(), "temporary fixture was left behind");
}

#[test]
fn same_seed_gives_identical_fixture_and_other_seed_does_not() {
    let sb = Sandbox::new();
    let run = |name: &str, seed: &str| {
        let out = sb.file(name);
        let o = sb.blaze(&[
            "benchmark",
            "--runs",
            "1",
            "--warmup",
            "0",
            "--size-mb",
            "1",
            "--seed",
            seed,
            "--output",
            out.to_str().unwrap(),
        ]);
        assert!(o.status.success(), "{}", stderr(&o));
        json(&out)["fixture"]["sha256"].as_str().unwrap().to_owned()
    };
    let first = run("one.json", "42");
    assert_eq!(first, run("two.json", "42"));
    assert_ne!(first, run("three.json", "43"));
}

#[test]
fn failed_output_write_still_cleans_up() {
    let sb = Sandbox::new();
    let blocked = sb.dir.path().join("is-a-directory");
    std::fs::create_dir(&blocked).unwrap();
    let o = sb.blaze(&[
        "benchmark",
        "--runs",
        "1",
        "--warmup",
        "0",
        "--size-mb",
        "1",
        "--output",
        blocked.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("could not write"), "{}", stderr(&o));
    assert!(sb.scratch_is_empty(), "temporary fixture was left behind");
}

#[test]
fn unreachable_server_yields_an_error_artifact() {
    let sb = Sandbox::new();
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let url = format!("http://127.0.0.1:{port}");
    let out = sb.file("dead.json");
    let o = sb.blaze(&[
        "benchmark",
        "--url",
        &url,
        "--runs",
        "2",
        "--warmup",
        "0",
        "--size-mb",
        "1",
        "--output",
        out.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
    let a = json(&out);
    assert_eq!(a["server"]["mode"], "external");
    assert!(a["fixture"].is_null());
    assert_eq!(a["totals"]["failed"], 2);
    assert_eq!(a["totals"]["ok"], 0);
    let w = workload(&a, "full");
    assert!(w["summary"]["median"].is_null());
    assert!(
        w["summary"]["reason"]
            .as_str()
            .unwrap()
            .contains("no successful")
    );
    for s in w["samples"].as_array().unwrap() {
        assert_eq!(s["status"], "failed");
        assert!(s["throughput_mib_per_second"].is_null());
        assert!(!s["failure"].as_str().unwrap().is_empty());
    }

    let cmp = sb.blaze(&[
        "benchmark",
        "compare",
        out.to_str().unwrap(),
        out.to_str().unwrap(),
    ]);
    assert!(cmp.status.success(), "{}", stderr(&cmp));
    assert!(stdout(&cmp).contains("n/a"));
}

#[test]
fn truncated_transfer_is_incomplete_and_never_counted() {
    let sb = Sandbox::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while !seen.ends_with(b"\r\n\r\n") {
            if conn.read(&mut byte).unwrap_or(0) == 0 {
                return;
            }
            seen.push(byte[0]);
        }
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {MIB}\r\n\r\n");
        conn.write_all(head.as_bytes()).unwrap();
        conn.write_all(&[7u8; 1000]).unwrap();
    });
    let out = sb.file("short.json");
    let url = format!("http://127.0.0.1:{port}");
    let o = sb.blaze(&[
        "benchmark",
        "--url",
        &url,
        "--runs",
        "1",
        "--warmup",
        "0",
        "--size-mb",
        "1",
        "--output",
        out.to_str().unwrap(),
    ]);
    server.join().unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let a = json(&out);
    assert_eq!(a["totals"]["incomplete"], 1);
    assert_eq!(a["totals"]["ok"], 0);
    let s = &workload(&a, "full")["samples"][0];
    assert_eq!(s["status"], "incomplete");
    assert!(s["downloaded_bytes"].as_u64().unwrap() < MIB);
    assert!(s["throughput_mib_per_second"].is_null());
    assert!(workload(&a, "full")["summary"]["median"].is_null());
}

#[test]
fn external_server_rejects_range_workloads() {
    let sb = Sandbox::new();
    let o = sb.blaze(&[
        "benchmark",
        "--url",
        "http://127.0.0.1:9",
        "--workload",
        "range",
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("isolated server"), "{}", stderr(&o));
}

#[test]
fn compare_reports_deltas_and_rejects_invalid_artifacts() {
    let sb = Sandbox::new();
    let a_path = success_artifact(&sb, "a.json");

    let mut b = json(&a_path);
    for w in b["workloads"].as_array_mut().unwrap() {
        for s in w["samples"].as_array_mut().unwrap() {
            let t = s["throughput_mib_per_second"].as_f64().unwrap();
            s["throughput_mib_per_second"] = (t * 2.0).into();
        }
        for key in ["median", "mean", "min", "max", "stddev", "p95"] {
            if let Some(v) = w["summary"][key].as_f64() {
                w["summary"][key] = (v * 2.0).into();
            }
        }
    }
    let b_path = sb.file("b.json");
    std::fs::write(&b_path, serde_json::to_string(&b).unwrap()).unwrap();

    let o = sb.blaze(&[
        "benchmark",
        "compare",
        a_path.to_str().unwrap(),
        b_path.to_str().unwrap(),
        "--json",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let cmp: Value = serde_json::from_str(&stdout(&o)).unwrap();
    let rows = cmp["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for r in rows {
        let pct = r["percent"].as_f64().unwrap();
        assert!((pct - 100.0).abs() < 1e-6, "{r}");
        assert!(r["delta"].as_f64().unwrap() > 0.0);
    }

    let human = sb.blaze(&[
        "benchmark",
        "compare",
        a_path.to_str().unwrap(),
        b_path.to_str().unwrap(),
    ]);
    assert!(stdout(&human).contains("No threshold or significance test is applied"));

    let mut bad_version = json(&a_path);
    bad_version["schema_version"] = 2.into();
    let bad_version_path = sb.file("v2.json");
    std::fs::write(&bad_version_path, bad_version.to_string()).unwrap();
    let mut truncated = json(&a_path);
    truncated.as_object_mut().unwrap().remove("fixture");
    let truncated_path = sb.file("truncated.json");
    std::fs::write(&truncated_path, truncated.to_string()).unwrap();
    let mut miscounted = json(&a_path);
    miscounted["totals"]["ok"] = 1.into();
    let miscounted_path = sb.file("miscounted.json");
    std::fs::write(&miscounted_path, miscounted.to_string()).unwrap();

    for (bad, needle) in [
        (&bad_version_path, "unsupported schema_version"),
        (&truncated_path, "fixture"),
        (&miscounted_path, "totals"),
    ] {
        let o = sb.blaze(&[
            "benchmark",
            "compare",
            a_path.to_str().unwrap(),
            bad.to_str().unwrap(),
        ]);
        assert_eq!(o.status.code(), Some(1));
        assert!(stderr(&o).contains(needle), "{needle}: {}", stderr(&o));
    }
}

#[test]
fn single_run_json_keeps_its_exact_keys() {
    let sb = Sandbox::new();
    let o = sb.blaze(&["benchmark", "--size-mb", "1", "--json"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let v: Value = serde_json::from_str(stdout(&o).trim()).unwrap();
    let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "base_url",
            "downloaded_bytes",
            "elapsed_seconds",
            "requested_bytes",
            "throughput_mib_per_second"
        ]
    );
    assert!(sb.scratch_is_empty());
}
