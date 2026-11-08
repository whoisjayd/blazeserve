//! Artifact builders shared by the unit tests of the schema-consuming modules.

use super::schema::{
    Artifact, BlazeInfo, Environment, Fact, Protocol, SCHEMA_VERSION, Sample, ServerInfo, TOOL,
    Workload,
};
use super::stats::{count, summarize};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn sample(index: u32, status: &str, got: u64) -> Sample {
    let ok = status == "ok";
    Sample {
        base_url: "http://127.0.0.1:1".into(),
        workload: "full".into(),
        index,
        status: status.into(),
        requested_bytes: 100,
        downloaded_bytes: got,
        elapsed_seconds: 1.0,
        throughput_mib_per_second: ok.then_some(10.0 + f64::from(index)),
        http_status: Some(200),
        failure: (!ok).then(|| "boom".to_string()),
    }
}

pub(super) fn artifact(samples: Vec<Sample>) -> Artifact {
    let ok: Vec<f64> = samples
        .iter()
        .filter_map(|s| s.throughput_mib_per_second)
        .collect();
    let counts = count(&samples);
    let workload = Workload {
        id: "full".into(),
        description: "full file".into(),
        requested_bytes: 100,
        counts: counts.clone(),
        summary: summarize(&ok),
        samples,
    };
    Artifact {
        schema_version: SCHEMA_VERSION,
        tool: TOOL.into(),
        complete: true,
        interrupted: false,
        error: None,
        command: vec!["blaze".into(), "benchmark".into()],
        blaze: BlazeInfo {
            version: "1.0.0".into(),
            git_rev: Fact::missing("not recorded"),
        },
        server: ServerInfo {
            mode: "external".into(),
            base_url: "http://127.0.0.1:1".into(),
            args: Value::Null,
        },
        fixture: None,
        protocol: Protocol {
            warmup: 0,
            runs: 3,
            cache_state: "warm".into(),
            timing: "request to last byte".into(),
            client: "ureq".into(),
        },
        environment: Environment {
            os: "linux".into(),
            arch: "x86_64".into(),
            os_version: Fact::missing("n/a"),
            cpu_count: Fact::some(4),
            cpu_model: Fact::missing("n/a"),
            memory_total_bytes: Fact::missing("n/a"),
            filesystem: Fact::missing("n/a"),
        },
        capabilities: BTreeMap::new(),
        totals: counts,
        workloads: vec![workload],
    }
}

pub(super) fn good() -> Artifact {
    artifact(vec![
        sample(0, "ok", 100),
        sample(1, "ok", 100),
        sample(2, "ok", 100),
    ])
}
