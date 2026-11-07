//! Repeatable benchmark runner: deterministic fixture, isolated server, timed samples.

use super::bench::TempDir;
use super::bench_artifact::{
    Artifact, BlazeInfo, Counts, Environment, Fact, FixtureInfo, Protocol, SCHEMA_VERSION, Sample,
    ServerInfo, Summary, TOOL, Workload, count, summarize, throughput, totals,
};
use super::util::{canonical, hex};
use crate::config::Config;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

pub const DEFAULT_SEED: u64 = 0x426c_617a_6545;
const FIXTURE_NAME: &str = "fixture.bin";
const MIB: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum WorkloadSel {
    Full,
    Range,
    Both,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub runs: u32,
    pub warmup: u32,
    pub workload: WorkloadSel,
    pub size_mb: u64,
    pub seed: u64,
    pub url: Option<String>,
    pub argv: Vec<String>,
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Write `size` pseudo-random bytes derived only from `seed` and return their SHA-256.
/// The chunk size is a multiple of 8, so the stream does not depend on buffering.
pub fn write_fixture(path: &Path, size: u64, seed: u64) -> std::io::Result<String> {
    let mut file = std::fs::File::create(path)?;
    let mut state = seed;
    let mut buf = vec![0u8; MIB as usize];
    let mut hasher = Sha256::new();
    let mut left = size;
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        for chunk in buf[..n].chunks_mut(8) {
            let word = splitmix64(&mut state).to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        file.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    file.flush()?;
    Ok(hex(&hasher.finalize()))
}

struct Spec {
    id: &'static str,
    description: &'static str,
    path: String,
    range: Option<(u64, u64)>,
    expected: u64,
}

fn specs(plan: &Plan, size: u64) -> Vec<Spec> {
    let full = if plan.url.is_some() {
        Spec {
            id: "full",
            description: "full download of /__speed__ from an external server",
            path: format!("/__speed__?bytes={size}"),
            range: None,
            expected: size,
        }
    } else {
        Spec {
            id: "full",
            description: "full-file GET of the fixture",
            path: format!("/{FIXTURE_NAME}"),
            range: None,
            expected: size,
        }
    };
    // The middle half of the file: starts off-zero so it cannot take a full-file path.
    let start = size / 4;
    let len = size / 2;
    let range = Spec {
        id: "range",
        description: "single byte range covering the middle half of the fixture",
        path: format!("/{FIXTURE_NAME}"),
        range: Some((start, start + len - 1)),
        expected: len,
    };
    match plan.workload {
        WorkloadSel::Full => vec![full],
        WorkloadSel::Range => vec![range],
        WorkloadSel::Both => vec![full, range],
    }
}

fn sample_once(agent: &ureq::Agent, base: &str, spec: &Spec, index: u32) -> Sample {
    let url = format!("{base}{}", spec.path);
    let mut sample = Sample {
        base_url: base.to_owned(),
        workload: spec.id.to_owned(),
        index,
        status: "failed".into(),
        requested_bytes: spec.expected,
        downloaded_bytes: 0,
        elapsed_seconds: 0.0,
        throughput_mib_per_second: None,
        http_status: None,
        failure: None,
    };
    let start = Instant::now();
    let mut request = agent.get(&url);
    if let Some((first, last)) = spec.range {
        request = request.header("Range", format!("bytes={first}-{last}").as_str());
    }
    let response = match request.call() {
        Ok(r) => r,
        Err(e) => {
            sample.elapsed_seconds = start.elapsed().as_secs_f64();
            sample.failure = Some(format!("request failed: {e}"));
            return sample;
        }
    };
    let code = response.status().as_u16();
    sample.http_status = Some(code);
    let wanted = if spec.range.is_some() { 206 } else { 200 };
    if code != wanted {
        sample.elapsed_seconds = start.elapsed().as_secs_f64();
        sample.failure = Some(format!("expected HTTP {wanted}, received {code}"));
        return sample;
    }
    let mut reader = response.into_body().into_reader();
    let mut buf = vec![0u8; MIB as usize];
    let mut read_error = None;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => sample.downloaded_bytes += n as u64,
            Err(e) => {
                read_error = Some(e.to_string());
                break;
            }
        }
    }
    sample.elapsed_seconds = start.elapsed().as_secs_f64();
    let got = sample.downloaded_bytes;
    if got > spec.expected {
        sample.failure = Some(format!("received {got} bytes, expected {}", spec.expected));
    } else if got < spec.expected {
        sample.status = "incomplete".into();
        sample.failure = Some(match read_error {
            Some(e) => format!(
                "transfer interrupted after {got} of {} bytes: {e}",
                spec.expected
            ),
            None => format!("server closed after {got} of {} bytes", spec.expected),
        });
    } else if let Some(e) = read_error {
        sample.failure = Some(format!("read error after the last byte: {e}"));
    } else {
        sample.status = "ok".into();
        sample.throughput_mib_per_second = Some(throughput(got, sample.elapsed_seconds));
    }
    sample
}

fn build_workload(spec: &Spec, samples: Vec<Sample>) -> Workload {
    let ok: Vec<f64> = samples
        .iter()
        .filter_map(|s| s.throughput_mib_per_second)
        .collect();
    Workload {
        id: spec.id.to_owned(),
        description: spec.description.to_owned(),
        requested_bytes: spec.expected,
        counts: count(&samples),
        summary: summarize(&ok),
        samples,
    }
}

fn collect(
    specs: &[Spec],
    base: &str,
    warmup: u32,
    runs: u32,
    cancel: &AtomicBool,
) -> Vec<Workload> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(None)
        .build()
        .into();
    let mut out = Vec::new();
    for spec in specs {
        for i in 0..warmup {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let _ = sample_once(&agent, base, spec, i);
        }
        let mut samples = Vec::new();
        for i in 0..runs {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            samples.push(sample_once(&agent, base, spec, i));
        }
        out.push(build_workload(spec, samples));
    }
    out
}

fn run_cmd(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

pub fn parse_cpuinfo(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "model name").then(|| value.trim().to_owned())
    })
}

pub fn parse_meminfo(text: &str) -> Option<u64> {
    let rest = text.lines().find_map(|l| l.strip_prefix("MemTotal:"))?;
    let kib: u64 = rest.trim().strip_suffix("kB")?.trim().parse().ok()?;
    kib.checked_mul(1024)
}

/// File system type of the longest mount point that contains `path`.
pub fn parse_mounts(text: &str, path: &str) -> Option<String> {
    let mut best: Option<(usize, &str)> = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (_, Some(point), Some(fstype)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let contains = path == point
            || (path.starts_with(point)
                && (point.ends_with('/') || path[point.len()..].starts_with('/')));
        if contains && best.is_none_or(|(len, _)| point.len() >= len) {
            best = Some((point.len(), fstype));
        }
    }
    best.map(|(_, t)| t.to_owned())
}

fn missing<T>(what: &str) -> Fact<T> {
    Fact::missing(format!(
        "{what} is not readable on this platform without native APIs"
    ))
}

pub fn collect_environment(tmp: &Path) -> Environment {
    let linux_cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|t| parse_cpuinfo(&t));
    let linux_mem = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| parse_meminfo(&t));
    let linux_os = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| format!("Linux {}", s.trim()));
    let filesystem = std::fs::read_to_string("/proc/mounts")
        .ok()
        .and_then(|t| parse_mounts(&t, &tmp.to_string_lossy()));

    let (os_version, cpu_model, memory) = if cfg!(windows) {
        (
            run_cmd("cmd", &["/C", "ver"]),
            std::env::var("PROCESSOR_IDENTIFIER")
                .ok()
                .filter(|s| !s.is_empty()),
            run_cmd(
                "powershell",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
                ],
            )
            .and_then(|s| s.parse::<u64>().ok()),
        )
    } else if cfg!(target_os = "macos") {
        (
            run_cmd("sw_vers", &["-productVersion"]).map(|v| format!("macOS {v}")),
            run_cmd("sysctl", &["-n", "machdep.cpu.brand_string"]),
            run_cmd("sysctl", &["-n", "hw.memsize"]).and_then(|s| s.parse::<u64>().ok()),
        )
    } else {
        (linux_os, linux_cpu, linux_mem)
    };

    let fact = |value: Option<String>, what: &str| match value {
        Some(v) => Fact::some(v),
        None => missing(what),
    };
    Environment {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        os_version: fact(os_version, "OS version"),
        cpu_count: std::thread::available_parallelism()
            .map(|n| Fact::some(n.get() as u64))
            .unwrap_or_else(|e| Fact::missing(format!("parallelism query failed: {e}"))),
        cpu_model: fact(cpu_model, "CPU model"),
        memory_total_bytes: memory.map_or_else(|| missing("total memory"), Fact::some),
        filesystem: fact(filesystem, "file system type"),
    }
}

#[derive(Default)]
struct Execution {
    base_url: String,
    external: bool,
    server_args: Value,
    fixture: Option<FixtureInfo>,
    environment: Option<Environment>,
    workloads: Vec<Workload>,
    interrupted: bool,
    error: Option<String>,
}

async fn sample_all(plan: &Plan, base: &str, size: u64, ex: &mut Execution) {
    let specs = specs(plan, size);
    let cancel = Arc::new(AtomicBool::new(false));
    let job_cancel = Arc::clone(&cancel);
    let (base_owned, warmup, runs) = (base.to_owned(), plan.warmup, plan.runs);
    let mut job = tokio::task::spawn_blocking(move || {
        collect(&specs, &base_owned, warmup, runs, &job_cancel)
    });
    let signal = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    let joined = tokio::select! {
        r = &mut job => r,
        () = signal => {
            cancel.store(true, Ordering::Relaxed);
            ex.interrupted = true;
            job.await
        }
    };
    match joined {
        Ok(workloads) => ex.workloads = workloads,
        Err(e) => ex.error = Some(format!("measurement task failed: {e}")),
    }
}

async fn isolated(plan: &Plan, ex: &mut Execution) -> Result<(), String> {
    let dir = TempDir::create()?;
    let size = plan.size_mb * MIB;
    let fixture_path = dir.0.join(FIXTURE_NAME);
    let seed = plan.seed;
    let sha256 = tokio::task::spawn_blocking(move || write_fixture(&fixture_path, size, seed))
        .await
        .map_err(|e| format!("fixture task failed: {e}"))?
        .map_err(|e| format!("could not create the fixture: {e}"))?;
    ex.fixture = Some(FixtureInfo {
        seed,
        size_bytes: size,
        sha256,
    });
    ex.environment = Some(collect_environment(&dir.0));

    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: canonical(&dir.0)?,
        ..Config::default()
    };
    ex.server_args = json!({
        "host": config.host,
        "port": "ephemeral",
        "chunk_bytes": config.chunk_bytes,
        "sndbuf_bytes": config.sndbuf_bytes,
        "timeout_secs": config.timeout_secs,
        "precompress": config.precompress,
        "rate_mbps": Value::Null,
        "tls": false,
        "max_connections": config.max_connections,
    });
    let handle = crate::server::start(config)
        .await
        .map_err(|e| format!("could not start the isolated server: {e}"))?;
    let origin = format!("http://127.0.0.1:{}", handle.local_addr().port());
    ex.base_url.clone_from(&origin);
    sample_all(plan, &origin, size, ex).await;
    handle.shutdown().await;
    Ok(())
}

async fn execute(plan: &Plan, ex: &mut Execution) {
    match &plan.url {
        Some(origin) => {
            ex.external = true;
            ex.base_url.clone_from(origin);
            ex.server_args = json!({ "note": "external server; its arguments are unknown" });
            ex.environment = Some(collect_environment(&std::env::temp_dir()));
            sample_all(plan, origin, plan.size_mb * MIB, ex).await;
        }
        None => {
            if let Err(e) = isolated(plan, ex).await {
                ex.error = Some(e);
            }
        }
    }
}

fn assemble(plan: &Plan, ex: Execution) -> Artifact {
    let environment = ex
        .environment
        .unwrap_or_else(|| collect_environment(&std::env::temp_dir()));
    let mut capabilities = BTreeMap::new();
    capabilities.insert("isolated_server".to_owned(), !ex.external);
    capabilities.insert("range_workload".to_owned(), !ex.external);
    capabilities.insert(
        "os_version".to_owned(),
        environment.os_version.value.is_some(),
    );
    capabilities.insert(
        "cpu_model".to_owned(),
        environment.cpu_model.value.is_some(),
    );
    capabilities.insert(
        "memory_total".to_owned(),
        environment.memory_total_bytes.value.is_some(),
    );
    capabilities.insert(
        "filesystem".to_owned(),
        environment.filesystem.value.is_some(),
    );
    let complete = ex.error.is_none() && !ex.interrupted;
    Artifact {
        schema_version: SCHEMA_VERSION,
        tool: TOOL.into(),
        complete,
        interrupted: ex.interrupted,
        error: ex.error,
        command: plan.argv.clone(),
        blaze: BlazeInfo {
            version: crate::VERSION.into(),
            git_rev: option_env!("BLAZE_GIT_REV")
                .filter(|r| !r.is_empty())
                .map_or_else(
                    || Fact::missing("BLAZE_GIT_REV was not set when this binary was built"),
                    |r| Fact::some(r.to_owned()),
                ),
        },
        server: ServerInfo {
            mode: if ex.external { "external" } else { "isolated" }.into(),
            base_url: ex.base_url,
            args: if ex.server_args.is_null() { json!({}) } else { ex.server_args },
        },
        fixture: ex.fixture,
        protocol: Protocol {
            warmup: plan.warmup,
            runs: plan.runs,
            cache_state: "warm: discarded warm-up samples precede the recorded samples".into(),
            timing: "request sent to last response body byte received; server start and fixture creation excluded".into(),
            client: "ureq HTTP/1.1, new connection per sample, 1 MiB read buffer".into(),
        },
        environment,
        capabilities,
        totals: totals(&ex.workloads),
        workloads: ex.workloads,
    }
}

pub struct Outcome {
    pub artifact: Artifact,
}

pub fn run(plan: &Plan) -> Result<Outcome, String> {
    if plan.url.is_some() && plan.workload != WorkloadSel::Full {
        return Err(
            "--workload range and both need the isolated server; omit --url or use --workload full"
                .into(),
        );
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("Benchmark failed: {e}"))?;
    let mut ex = Execution::default();
    runtime.block_on(execute(plan, &mut ex));
    Ok(Outcome {
        artifact: assemble(plan, ex),
    })
}

pub fn counts_failed(c: &Counts) -> bool {
    c.failed + c.incomplete > 0
}

pub fn summary_line(w: &Workload) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_is_deterministic_and_seed_dependent() {
        let dir = TempDir::create().unwrap();
        let (a, b, c) = (dir.0.join("a"), dir.0.join("b"), dir.0.join("c"));
        let size = MIB + 13;
        let ha = write_fixture(&a, size, 7).unwrap();
        assert_eq!(ha, write_fixture(&b, size, 7).unwrap());
        assert_ne!(ha, write_fixture(&c, size, 8).unwrap());
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        assert_eq!(std::fs::metadata(&a).unwrap().len(), size);
        assert_eq!(ha, super::super::util::sha256_file(&a).unwrap());
    }

    #[test]
    fn system_file_parsers() {
        assert_eq!(
            parse_cpuinfo("processor : 0\nmodel name\t: Fast CPU @ 3GHz\n").as_deref(),
            Some("Fast CPU @ 3GHz")
        );
        assert_eq!(
            parse_meminfo("MemTotal:       16384 kB\nMemFree: 1 kB\n"),
            Some(16384 * 1024)
        );
        assert_eq!(parse_meminfo("nothing"), None);
        let mounts = "rootfs / ext4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\ntmpfs /tmpx other rw 0 0\n";
        assert_eq!(
            parse_mounts(mounts, "/tmp/blaze-1").as_deref(),
            Some("tmpfs")
        );
        assert_eq!(parse_mounts(mounts, "/tmpfoo/x").as_deref(), Some("ext4"));
        assert_eq!(parse_mounts(mounts, "/home/u").as_deref(), Some("ext4"));
    }

    #[test]
    fn ranges_start_off_zero_and_fit_the_file() {
        let plan = Plan {
            runs: 1,
            warmup: 0,
            workload: WorkloadSel::Both,
            size_mb: 8,
            seed: 1,
            url: None,
            argv: vec![],
        };
        let size = plan.size_mb * MIB;
        let all = specs(&plan, size);
        let range = &all[1];
        let (first, last) = range.range.unwrap();
        assert!(first > 0 && last < size);
        assert_eq!(last - first + 1, range.expected);
    }
}
