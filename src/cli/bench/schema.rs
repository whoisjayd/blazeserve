//! Versioned benchmark artifact schema.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) const SCHEMA_VERSION: u32 = 1;
pub(super) const TOOL: &str = "blaze benchmark";

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
pub(super) struct Fact<T> {
    #[serde(deserialize_with = "required")]
    pub value: Option<T>,
    #[serde(deserialize_with = "required")]
    pub reason: Option<String>,
}

impl<T> Fact<T> {
    pub(super) fn some(value: T) -> Self {
        Self {
            value: Some(value),
            reason: None,
        }
    }

    pub(super) fn missing(reason: impl Into<String>) -> Self {
        Self {
            value: None,
            reason: Some(reason.into()),
        }
    }

    pub(super) fn check(&self, what: &str) -> Result<(), String> {
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
pub(super) struct Counts {
    pub ok: u64,
    pub incomplete: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BlazeInfo {
    pub version: String,
    pub git_rev: Fact<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerInfo {
    /// `isolated` (started by the harness) or `external` (`--url`).
    pub mode: String,
    pub base_url: String,
    pub args: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FixtureInfo {
    pub seed: u64,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Protocol {
    pub warmup: u32,
    pub runs: u32,
    pub cache_state: String,
    pub timing: String,
    pub client: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Environment {
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
pub(super) struct Sample {
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
pub(super) struct Summary {
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
pub(super) struct Workload {
    pub id: String,
    pub description: String,
    pub requested_bytes: u64,
    pub counts: Counts,
    pub samples: Vec<Sample>,
    pub summary: Summary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifact {
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
