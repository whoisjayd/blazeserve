//! Repeatable benchmark runner: isolated or external server, execution and artifact assembly.

use super::environment::collect_environment;
use super::fixture::{FIXTURE_NAME, MIB, TempDir, write_fixture};
use super::sampler::{WorkloadSel, collect, specs};
use super::schema::{
    Artifact, BlazeInfo, Environment, Fact, FixtureInfo, Protocol, SCHEMA_VERSION, ServerInfo,
    TOOL, Workload,
};
use super::stats::totals;
use crate::cli::util::canonical;
use crate::config::Config;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone)]
pub(super) struct Plan {
    pub runs: u32,
    pub warmup: u32,
    pub workload: WorkloadSel,
    pub size_mb: u64,
    pub seed: u64,
    pub url: Option<String>,
    pub argv: Vec<String>,
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
    let specs = specs(plan.workload, plan.url.is_some(), size);
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

pub(super) struct Outcome {
    pub artifact: Artifact,
}

pub(super) fn run(plan: &Plan) -> Result<Outcome, String> {
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
