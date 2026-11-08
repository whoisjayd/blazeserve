//! Artifact parsing and consistency validation.

use super::schema::{Artifact, SCHEMA_VERSION, Sample, TOOL, Workload};
use super::stats::{count, totals};
use serde_json::Value;
use std::collections::BTreeSet;

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
pub(super) fn parse(text: &str) -> Result<Artifact, String> {
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

pub(super) fn validate(a: &Artifact) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::bench::schema::{Counts, Fact};
    use crate::cli::bench::test_support::{artifact, good, sample};

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
}
