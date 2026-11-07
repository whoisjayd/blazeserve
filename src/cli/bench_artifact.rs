//! Versioned benchmark artifact: schema, summary statistics, validation and comparison.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const SCHEMA_VERSION: u32 = 1;
pub const TOOL: &str = "blaze benchmark";

/// `Option` that must be present in the JSON (serde would otherwise default a missing
/// key to `None`, hiding a truncated artifact).
fn required<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

/// A measurement that may be unavailable; an unavailable value always carries a reason.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
pub struct Fact<T> {
    #[serde(deserialize_with = "required")]
    pub value: Option<T>,
    #[serde(deserialize_with = "required")]
    pub reason: Option<String>,
}

impl<T> Fact<T> {
    pub fn some(value: T) -> Self {
        Self {
            value: Some(value),
            reason: None,
        }
    }

    pub fn missing(reason: impl Into<String>) -> Self {
        Self {
            value: None,
            reason: Some(reason.into()),
        }
    }

    fn check(&self, what: &str) -> Result<(), String> {
        match (&self.value, &self.reason) {
            (Some(_), None) => Ok(()),
            (None, Some(r)) if !r.is_empty() => Ok(()),
            (None, _) => Err(format!("{what} is unavailable without a reason")),
            (Some(_), Some(_)) => Err(format!("{what} has both a value and a reason")),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub ok: u64,
    pub incomplete: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlazeInfo {
    pub version: String,
    pub git_rev: Fact<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerInfo {
    /// `isolated` (started by the harness) or `external` (`--url`).
    pub mode: String,
    pub base_url: String,
    pub args: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureInfo {
    pub seed: u64,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    pub warmup: u32,
    pub runs: u32,
    pub cache_state: String,
    pub timing: String,
    pub client: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub os: String,
    pub arch: String,
    pub os_version: Fact<String>,
    pub cpu_count: Fact<u64>,
    pub cpu_model: Fact<String>,
    pub memory_total_bytes: Fact<u64>,
    pub filesystem: Fact<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub base_url: String,
    pub workload: String,
    pub index: u32,
    /// `ok`, `incomplete` (fewer bytes than requested) or `failed`.
    pub status: String,
    pub requested_bytes: u64,
    pub downloaded_bytes: u64,
    pub elapsed_seconds: f64,
    #[serde(deserialize_with = "required")]
    pub throughput_mib_per_second: Option<f64>,
    #[serde(deserialize_with = "required")]
    pub http_status: Option<u16>,
    #[serde(deserialize_with = "required")]
    pub failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub unit: String,
    pub samples_used: u64,
    #[serde(deserialize_with = "required")]
    pub median: Option<f64>,
    #[serde(deserialize_with = "required")]
    pub mean: Option<f64>,
    #[serde(deserialize_with = "required")]
    pub min: Option<f64>,
    #[serde(deserialize_with = "required")]
    pub max: Option<f64>,
    #[serde(deserialize_with = "required")]
    pub stddev: Option<f64>,
    #[serde(deserialize_with = "required")]
    pub p95: Option<f64>,
    #[serde(deserialize_with = "required")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub id: String,
    pub description: String,
    pub requested_bytes: u64,
    pub counts: Counts,
    pub samples: Vec<Sample>,
    pub summary: Summary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub schema_version: u32,
    pub tool: String,
    pub complete: bool,
    pub interrupted: bool,
    #[serde(deserialize_with = "required")]
    pub error: Option<String>,
    pub command: Vec<String>,
    pub blaze: BlazeInfo,
    pub server: ServerInfo,
    #[serde(deserialize_with = "required")]
    pub fixture: Option<FixtureInfo>,
    pub protocol: Protocol,
    pub environment: Environment,
    pub capabilities: BTreeMap<String, bool>,
    pub workloads: Vec<Workload>,
    pub totals: Counts,
}

const MIB: f64 = 1024.0 * 1024.0;

pub fn throughput(bytes: u64, seconds: f64) -> f64 {
    (bytes as f64 / MIB) / seconds.max(f64::EPSILON)
}

/// Summary over successful samples only; failed and incomplete transfers never count
/// as throughput.
pub fn summarize(values: &[f64]) -> Summary {
    let mut summary = Summary {
        unit: "MiB/s".into(),
        samples_used: values.len() as u64,
        median: None,
        mean: None,
        min: None,
        max: None,
        stddev: None,
        p95: None,
        reason: None,
    };
    if values.is_empty() {
        summary.reason = Some("no successful samples".into());
        return summary;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let mean = sorted.iter().sum::<f64>() / n as f64;
    summary.median = Some(if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    });
    summary.mean = Some(mean);
    summary.min = Some(sorted[0]);
    summary.max = Some(sorted[n - 1]);
    // Nearest-rank percentile.
    let rank = ((0.95 * n as f64).ceil() as usize).clamp(1, n);
    summary.p95 = Some(sorted[rank - 1]);
    if n >= 2 {
        let var = sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
        summary.stddev = Some(var.sqrt());
    } else {
        summary.reason = Some("stddev needs at least 2 successful samples".into());
    }
    summary
}

pub fn count(samples: &[Sample]) -> Counts {
    let mut c = Counts::default();
    for s in samples {
        match s.status.as_str() {
            "ok" => c.ok += 1,
            "incomplete" => c.incomplete += 1,
            _ => c.failed += 1,
        }
    }
    c
}

pub fn totals(workloads: &[Workload]) -> Counts {
    workloads.iter().fold(Counts::default(), |mut t, w| {
        t.ok += w.counts.ok;
        t.incomplete += w.counts.incomplete;
        t.failed += w.counts.failed;
        t
    })
}

fn finite(v: f64, what: &str) -> Result<(), String> {
    if v.is_finite() && v >= 0.0 {
        Ok(())
    } else {
        Err(format!("{what} must be a finite non-negative number"))
    }
}

fn validate_sample(workload: &Workload, s: &Sample) -> Result<(), String> {
    let at = format!("workload {} sample {}", workload.id, s.index);
    if s.workload != workload.id {
        return Err(format!("{at}: workload id does not match its container"));
    }
    finite(s.elapsed_seconds, &format!("{at}: elapsed_seconds"))?;
    match s.status.as_str() {
        "ok" => {
            if s.downloaded_bytes != s.requested_bytes {
                return Err(format!("{at}: ok sample with a byte mismatch"));
            }
            let t = s
                .throughput_mib_per_second
                .ok_or_else(|| format!("{at}: ok sample without throughput"))?;
            finite(t, &format!("{at}: throughput"))?;
            if s.failure.is_some() {
                return Err(format!("{at}: ok sample with a failure message"));
            }
        }
        "incomplete" | "failed" => {
            if s.throughput_mib_per_second.is_some() {
                return Err(format!("{at}: {} sample counted as throughput", s.status));
            }
            if s.failure.as_deref().is_none_or(str::is_empty) {
                return Err(format!(
                    "{at}: {} sample without a failure message",
                    s.status
                ));
            }
            if s.status == "incomplete" && s.downloaded_bytes >= s.requested_bytes {
                return Err(format!("{at}: incomplete sample received every byte"));
            }
        }
        other => return Err(format!("{at}: unknown status {other:?}")),
    }
    Ok(())
}

fn validate_summary(w: &Workload) -> Result<(), String> {
    let s = &w.summary;
    let at = format!("workload {} summary", w.id);
    if s.samples_used != w.counts.ok {
        return Err(format!("{at}: samples_used differs from the ok count"));
    }
    let stats = [s.median, s.mean, s.min, s.max, s.p95];
    if w.counts.ok == 0 {
        if stats.iter().chain([&s.stddev]).any(Option::is_some) || s.reason.is_none() {
            return Err(format!(
                "{at}: statistics reported without successful samples"
            ));
        }
        return Ok(());
    }
    if stats.iter().any(Option::is_none) {
        return Err(format!("{at}: statistics missing"));
    }
    for v in stats.iter().flatten().chain(s.stddev.iter()) {
        finite(*v, &format!("{at}: statistic"))?;
    }
    let (min, median, max) = (
        s.min.unwrap_or(0.0),
        s.median.unwrap_or(0.0),
        s.max.unwrap_or(0.0),
    );
    if !(min <= median && median <= max) {
        return Err(format!("{at}: min, median and max are out of order"));
    }
    Ok(())
}

/// Parse and validate an artifact, rejecting unknown versions, missing fields and
/// inconsistent counts.
pub fn parse(text: &str) -> Result<Artifact, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    match value.get("schema_version").and_then(Value::as_u64) {
        Some(v) if v == u64::from(SCHEMA_VERSION) => {}
        Some(v) => return Err(format!("unsupported schema_version {v}")),
        None => return Err("missing schema_version".into()),
    }
    let a: Artifact = serde_json::from_value(value).map_err(|e| e.to_string())?;
    validate(&a)?;
    Ok(a)
}

pub fn validate(a: &Artifact) -> Result<(), String> {
    if a.tool != TOOL {
        return Err(format!("unexpected tool {:?}", a.tool));
    }
    a.blaze.git_rev.check("blaze.git_rev")?;
    let e = &a.environment;
    e.os_version.check("environment.os_version")?;
    e.cpu_count.check("environment.cpu_count")?;
    e.cpu_model.check("environment.cpu_model")?;
    e.memory_total_bytes
        .check("environment.memory_total_bytes")?;
    e.filesystem.check("environment.filesystem")?;
    match a.server.mode.as_str() {
        "isolated" if a.fixture.is_some() => {}
        "isolated" => return Err("isolated server without fixture parameters".into()),
        "external" if a.fixture.is_none() => {}
        "external" => return Err("external server cannot have a fixture".into()),
        other => return Err(format!("unknown server mode {other:?}")),
    }
    if a.complete && (a.error.is_some() || a.interrupted) {
        return Err("complete artifact reports an error or interruption".into());
    }
    if !a.complete && a.error.is_none() && !a.interrupted {
        return Err("incomplete artifact without an error or interruption".into());
    }
    let mut ids = BTreeSet::new();
    for w in &a.workloads {
        if !ids.insert(w.id.as_str()) {
            return Err(format!("duplicate workload {}", w.id));
        }
        for s in &w.samples {
            validate_sample(w, s)?;
        }
        if count(&w.samples) != w.counts {
            return Err(format!(
                "workload {}: counts do not match its samples",
                w.id
            ));
        }
        validate_summary(w)?;
    }
    if totals(&a.workloads) != a.totals {
        return Err("totals do not match the workloads".into());
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Row {
    pub workload: String,
    pub unit: &'static str,
    pub a_median: Option<f64>,
    pub b_median: Option<f64>,
    pub delta: Option<f64>,
    pub percent: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct Comparison {
    pub rows: Vec<Row>,
    pub notes: Vec<String>,
}

/// Report medians side by side. No threshold or significance is applied.
pub fn compare(a: &Artifact, b: &Artifact) -> Comparison {
    let mut notes = Vec::new();
    if a.fixture != b.fixture {
        notes.push("fixture parameters differ between the artifacts".into());
    }
    if a.environment != b.environment {
        notes.push("environment differs between the artifacts".into());
    }
    if a.server.args != b.server.args {
        notes.push("server arguments differ between the artifacts".into());
    }
    let mut rows = Vec::new();
    for wa in &a.workloads {
        let Some(wb) = b.workloads.iter().find(|w| w.id == wa.id) else {
            notes.push(format!("workload {} is only in the first artifact", wa.id));
            continue;
        };
        let (am, bm) = (wa.summary.median, wb.summary.median);
        let delta = am.zip(bm).map(|(x, y)| y - x);
        let percent = am
            .zip(bm)
            .and_then(|(x, y)| (x > 0.0).then(|| (y - x) / x * 100.0));
        rows.push(Row {
            workload: wa.id.clone(),
            unit: "MiB/s",
            a_median: am,
            b_median: bm,
            delta,
            percent,
        });
    }
    for wb in &b.workloads {
        if !a.workloads.iter().any(|w| w.id == wb.id) {
            notes.push(format!("workload {} is only in the second artifact", wb.id));
        }
    }
    Comparison { rows, notes }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(index: u32, status: &str, got: u64) -> Sample {
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

    pub fn artifact(samples: Vec<Sample>) -> Artifact {
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

    fn good() -> Artifact {
        artifact(vec![
            sample(0, "ok", 100),
            sample(1, "ok", 100),
            sample(2, "ok", 100),
        ])
    }

    #[test]
    fn statistics() {
        let s = summarize(&[4.0, 1.0, 2.0, 3.0]);
        assert_eq!(s.median, Some(2.5));
        assert_eq!(s.mean, Some(2.5));
        assert_eq!((s.min, s.max), (Some(1.0), Some(4.0)));
        assert_eq!(s.p95, Some(4.0));
        assert!((s.stddev.unwrap() - 1.2909944).abs() < 1e-6);
        let one = summarize(&[7.0]);
        assert_eq!((one.median, one.stddev), (Some(7.0), None));
        assert!(one.reason.is_some());
        let none = summarize(&[]);
        assert_eq!((none.median, none.samples_used), (None, 0));
    }

    #[test]
    fn good_artifact_round_trips() {
        let a = good();
        let parsed = parse(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(parsed, a);
    }

    #[test]
    fn rejects_bad_artifacts() {
        let text = serde_json::to_string(&good()).unwrap();
        assert!(parse("{").is_err());
        assert!(parse(&text.replace("\"schema_version\":1", "\"schema_version\":2")).is_err());
        assert!(parse(&text.replace("\"tool\":\"blaze benchmark\"", "\"tool\":\"x\"")).is_err());

        let mut v: Value = serde_json::from_str(&text).unwrap();
        v.as_object_mut().unwrap().remove("fixture");
        assert!(parse(&v.to_string()).unwrap_err().contains("fixture"));

        let mut a = good();
        a.workloads[0].counts.ok = 2;
        assert!(validate(&a).unwrap_err().contains("counts"));

        let mut a = good();
        a.totals.failed = 1;
        assert!(validate(&a).unwrap_err().contains("totals"));

        let mut a = good();
        a.workloads[0].samples[0].downloaded_bytes = 5;
        assert!(validate(&a).is_err());

        let mut a = artifact(vec![sample(0, "incomplete", 10)]);
        a.workloads[0].samples[0].throughput_mib_per_second = Some(1.0);
        assert!(validate(&a).unwrap_err().contains("throughput"));

        let mut a = good();
        a.environment.cpu_model = Fact {
            value: None,
            reason: None,
        };
        assert!(validate(&a).unwrap_err().contains("cpu_model"));

        let mut a = good();
        a.complete = false;
        assert!(validate(&a).is_err());
    }

    #[test]
    fn failed_samples_never_count_as_throughput() {
        let a = artifact(vec![
            sample(0, "ok", 100),
            sample(1, "incomplete", 10),
            sample(2, "failed", 0),
        ]);
        validate(&a).unwrap();
        assert_eq!(
            a.totals,
            Counts {
                ok: 1,
                incomplete: 1,
                failed: 1
            }
        );
        assert_eq!(a.workloads[0].summary.samples_used, 1);
    }

    #[test]
    fn compare_reports_delta_without_thresholds() {
        let a = good();
        let mut b = good();
        for s in &mut b.workloads[0].samples {
            s.throughput_mib_per_second = s.throughput_mib_per_second.map(|t| t * 2.0);
        }
        b.workloads[0].summary = summarize(
            &b.workloads[0]
                .samples
                .iter()
                .filter_map(|s| s.throughput_mib_per_second)
                .collect::<Vec<_>>(),
        );
        let c = compare(&a, &b);
        let row = &c.rows[0];
        assert_eq!(row.a_median, Some(11.0));
        assert_eq!(row.b_median, Some(22.0));
        assert_eq!(row.delta, Some(11.0));
        assert_eq!(row.percent, Some(100.0));
        assert!(c.notes.is_empty());
    }
}
