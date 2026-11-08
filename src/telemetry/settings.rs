//! Export settings: endpoint validation, header parsing and the OTEL_* environment rules.

use hyper::header::{HeaderName, HeaderValue};
use percent_encoding::percent_decode_str;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use super::DEFAULT_SERVICE_NAME;

const DEFAULT_METRIC_INTERVAL: Duration = Duration::from_secs(15);
const MIN_METRIC_INTERVAL: Duration = Duration::from_millis(100);

const ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const TRACES_ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
const METRICS_ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT";
const PROTOCOL_VARS: [&str; 3] = [
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
    "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
];

type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryError(pub(super) String);

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TelemetryError {}

fn fail<T>(msg: impl Into<String>) -> Result<T, TelemetryError> {
    Err(TelemetryError(msg.into()))
}

/// A validated collector URL. `Debug` shows the host only.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub(super) url: String,
    pub(super) host: String,
}

impl Endpoint {
    fn parse(raw: &str, source: &str) -> Result<Self, TelemetryError> {
        let invalid = || {
            TelemetryError(format!(
                "invalid OTLP endpoint in {source}: expected http(s)://host[:port][/path]"
            ))
        };
        let uri: hyper::Uri = raw.trim().parse().map_err(|_| invalid())?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) {
            return Err(invalid());
        }
        let authority = uri.authority().ok_or_else(invalid)?;
        if authority.as_str().contains('@') {
            return fail(format!(
                "OTLP endpoint in {source} must not embed credentials; use OTEL_EXPORTER_OTLP_HEADERS"
            ));
        }
        let host = uri.host().filter(|h| !h.is_empty()).ok_or_else(invalid)?;
        Ok(Self {
            url: raw.trim().to_owned(),
            host: host.trim_matches(['[', ']']).to_owned(),
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn as_str(&self) -> &str {
        &self.url
    }

    #[cfg_attr(not(feature = "otel"), allow(dead_code))]
    fn is_plaintext_remote(&self) -> bool {
        let plain = self
            .url
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("http://"));
        let local = self.host.eq_ignore_ascii_case("localhost")
            || self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        plain && !local
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Endpoint({})", self.host)
    }
}

#[derive(Clone)]
#[cfg_attr(not(feature = "otel"), allow(dead_code))]
pub(super) struct Secret(pub(super) String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Fully resolved export settings. Header values never appear in `Debug`.
///
/// Resolved and validated even without the `otel` feature, so a bad configuration is
/// reported the same way in every build; only the exporter itself needs the feature.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "otel"), allow(dead_code))]
pub struct Settings {
    pub(super) traces: Option<Endpoint>,
    pub(super) metrics: Option<Endpoint>,
    pub(super) traces_headers: Vec<(String, Secret)>,
    pub(super) metrics_headers: Vec<(String, Secret)>,
    pub(super) service_name: String,
    pub(super) resource_attributes: Vec<(String, String)>,
    pub(super) metric_interval: Duration,
}

fn join(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

fn parse_pairs(var: &str, raw: &str) -> Result<Vec<(String, String)>, TelemetryError> {
    let bad = || TelemetryError(format!("invalid entry in {var}: expected key=value pairs"));
    let mut out = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (key, value) = entry.split_once('=').ok_or_else(bad)?;
        let key = key.trim();
        let value = percent_decode_str(value.trim())
            .decode_utf8()
            .map_err(|_| bad())?
            .into_owned();
        if key.is_empty() {
            return Err(bad());
        }
        out.push((key.to_owned(), value));
    }
    Ok(out)
}

fn parse_headers(var: &str, raw: &str) -> Result<Vec<(String, Secret)>, TelemetryError> {
    let mut out = Vec::new();
    for (key, value) in parse_pairs(var, raw)? {
        let valid =
            HeaderName::from_bytes(key.as_bytes()).is_ok() && HeaderValue::from_str(&value).is_ok();
        if !valid {
            return fail(format!(
                "invalid header in {var}: name or value is not a valid HTTP header"
            ));
        }
        out.push((key, Secret(value)));
    }
    Ok(out)
}

fn merge_headers(
    mut base: Vec<(String, Secret)>,
    over: Vec<(String, Secret)>,
) -> Vec<(String, Secret)> {
    for (k, v) in over {
        base.retain(|(existing, _)| !existing.eq_ignore_ascii_case(&k));
        base.push((k, v));
    }
    base
}

impl Settings {
    /// Resolve settings from an explicit endpoint and an environment source.
    ///
    /// `explicit` is the `--otlp-endpoint` base URL; an empty string means "use the standard
    /// `OTEL_EXPORTER_OTLP_*` variables". An explicit base wins over the environment for both
    /// signals. Returns `Ok(None)` when nothing is configured or export is disabled.
    pub fn resolve(explicit: &str, env: Env<'_>) -> Result<Option<Self>, TelemetryError> {
        let get = |k: &str| {
            env(k)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        if get("OTEL_SDK_DISABLED").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
            return Ok(None);
        }
        for var in PROTOCOL_VARS {
            if let Some(p) = get(var)
                && p != "http/protobuf"
            {
                return fail(format!(
                    "{var} must be \"http/protobuf\" (got {p:?}); grpc and http/json are not supported"
                ));
            }
        }

        let explicit = explicit.trim();
        let signal = |exporter_var: &str,
                      specific_var: &str,
                      path: &str|
         -> Result<Option<Endpoint>, TelemetryError> {
            if get(exporter_var).is_some_and(|v| v.eq_ignore_ascii_case("none")) {
                return Ok(None);
            }
            if !explicit.is_empty() {
                return Endpoint::parse(&join(explicit, path), "--otlp-endpoint").map(Some);
            }
            if let Some(v) = get(specific_var) {
                return Endpoint::parse(&v, specific_var).map(Some);
            }
            if let Some(v) = get(ENDPOINT_VAR) {
                return Endpoint::parse(&join(&v, path), ENDPOINT_VAR).map(Some);
            }
            Ok(None)
        };
        let traces = signal("OTEL_TRACES_EXPORTER", TRACES_ENDPOINT_VAR, "/v1/traces")?;
        let metrics = signal("OTEL_METRICS_EXPORTER", METRICS_ENDPOINT_VAR, "/v1/metrics")?;
        if traces.is_none() && metrics.is_none() {
            return Ok(None);
        }

        let generic_headers = match get("OTEL_EXPORTER_OTLP_HEADERS") {
            Some(raw) => parse_headers("OTEL_EXPORTER_OTLP_HEADERS", &raw)?,
            None => Vec::new(),
        };
        let signal_headers = |var: &str| -> Result<Vec<(String, Secret)>, TelemetryError> {
            let specific = match get(var) {
                Some(raw) => parse_headers(var, &raw)?,
                None => Vec::new(),
            };
            Ok(merge_headers(generic_headers.clone(), specific))
        };
        let traces_headers = signal_headers("OTEL_EXPORTER_OTLP_TRACES_HEADERS")?;
        let metrics_headers = signal_headers("OTEL_EXPORTER_OTLP_METRICS_HEADERS")?;

        let mut attributes = match get("OTEL_RESOURCE_ATTRIBUTES") {
            Some(raw) => parse_pairs("OTEL_RESOURCE_ATTRIBUTES", &raw)?,
            None => Vec::new(),
        };
        let from_attributes = attributes
            .iter()
            .position(|(k, _)| k == "service.name")
            .map(|i| attributes.remove(i).1);
        let service_name = get("OTEL_SERVICE_NAME")
            .or(from_attributes)
            .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_owned());

        let metric_interval = match get("OTEL_METRIC_EXPORT_INTERVAL") {
            None => DEFAULT_METRIC_INTERVAL,
            Some(raw) => raw
                .parse::<u64>()
                .map(Duration::from_millis)
                .ok()
                .filter(|d| *d >= MIN_METRIC_INTERVAL)
                .ok_or_else(|| {
                    TelemetryError(
                        "OTEL_METRIC_EXPORT_INTERVAL must be a number of milliseconds of at least 100"
                            .to_owned(),
                    )
                })?,
        };

        Ok(Some(Self {
            traces,
            metrics,
            traces_headers,
            metrics_headers,
            service_name,
            resource_attributes: attributes,
            metric_interval,
        }))
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[cfg_attr(not(feature = "otel"), allow(dead_code))]
    pub(super) fn has_headers(&self) -> bool {
        !self.traces_headers.is_empty() || !self.metrics_headers.is_empty()
    }

    #[cfg_attr(not(feature = "otel"), allow(dead_code))]
    pub(super) fn insecure_remote(&self) -> Option<&Endpoint> {
        [&self.traces, &self.metrics]
            .into_iter()
            .flatten()
            .find(|e| e.is_plaintext_remote())
    }
}

/// True when any standard OTLP endpoint variable is set, so the CLI can opt in without a flag.
pub fn env_endpoint_present() -> bool {
    [ENDPOINT_VAR, TRACES_ENDPOINT_VAR, METRICS_ENDPOINT_VAR]
        .iter()
        .any(|k| std::env::var(k).is_ok_and(|v| !v.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn resolve(explicit: &str, pairs: &[(&str, &str)]) -> Result<Option<Settings>, TelemetryError> {
        Settings::resolve(explicit, &env(pairs))
    }

    #[test]
    fn nothing_configured_is_off() {
        assert!(resolve("", &[]).unwrap().is_none());
    }

    #[test]
    fn generic_endpoint_gets_signal_paths_appended() {
        let s = resolve(
            "",
            &[(
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "https://collector.example/otlp/",
            )],
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            s.traces.unwrap().as_str(),
            "https://collector.example/otlp/v1/traces"
        );
        assert_eq!(
            s.metrics.unwrap().as_str(),
            "https://collector.example/otlp/v1/metrics"
        );
    }

    #[test]
    fn signal_endpoint_is_used_verbatim_and_beats_generic() {
        let s = resolve(
            "",
            &[
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://generic:4318"),
                (
                    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                    "http://traces.example:9/custom",
                ),
            ],
        )
        .unwrap()
        .unwrap();
        assert_eq!(s.traces.unwrap().as_str(), "http://traces.example:9/custom");
        assert_eq!(
            s.metrics.unwrap().as_str(),
            "http://generic:4318/v1/metrics"
        );
    }

    #[test]
    fn explicit_base_wins_over_environment() {
        let s = resolve(
            "http://flag:4318",
            &[("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://env:1/x")],
        )
        .unwrap()
        .unwrap();
        assert_eq!(s.traces.unwrap().as_str(), "http://flag:4318/v1/traces");
    }

    #[test]
    fn signal_only_environment_enables_only_that_signal() {
        let s = resolve(
            "",
            &[(
                "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
                "http://m:1/v1/metrics",
            )],
        )
        .unwrap()
        .unwrap();
        assert!(s.traces.is_none() && s.metrics.is_some());
    }

    #[test]
    fn exporter_none_disables_a_signal() {
        let s = resolve("http://c:4318", &[("OTEL_TRACES_EXPORTER", "none")])
            .unwrap()
            .unwrap();
        assert!(s.traces.is_none() && s.metrics.is_some());
    }

    #[test]
    fn sdk_disabled_wins() {
        assert!(
            resolve("http://c:4318", &[("OTEL_SDK_DISABLED", "TRUE")])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn grpc_and_json_protocols_are_rejected_naming_the_variable() {
        for (var, val) in [
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
            ("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/json"),
        ] {
            let err = resolve("http://c:4318", &[(var, val)])
                .unwrap_err()
                .to_string();
            assert!(err.contains(var), "{err}");
        }
        assert!(
            resolve(
                "http://c:4318",
                &[("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")]
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn service_name_precedence() {
        let attrs = (
            "OTEL_RESOURCE_ATTRIBUTES",
            "service.name=from-attrs,deployment.environment=prod",
        );
        let s = resolve("http://c:1", &[attrs]).unwrap().unwrap();
        assert_eq!(s.service_name(), "from-attrs");
        assert_eq!(
            s.resource_attributes,
            vec![("deployment.environment".into(), "prod".into())]
        );
        let s = resolve("http://c:1", &[attrs, ("OTEL_SERVICE_NAME", "explicit")])
            .unwrap()
            .unwrap();
        assert_eq!(s.service_name(), "explicit");
        let s = resolve("http://c:1", &[]).unwrap().unwrap();
        assert_eq!(s.service_name(), DEFAULT_SERVICE_NAME);
    }

    #[test]
    fn headers_are_percent_decoded_and_signal_specific_override() {
        let s = resolve(
            "http://c:1",
            &[
                (
                    "OTEL_EXPORTER_OTLP_HEADERS",
                    "authorization=Basic%20abc,x-team=core",
                ),
                ("OTEL_EXPORTER_OTLP_METRICS_HEADERS", "X-Team=metrics"),
            ],
        )
        .unwrap()
        .unwrap();
        assert_eq!(s.traces_headers[0].0, "authorization");
        assert_eq!(s.traces_headers[0].1.0, "Basic abc");
        let team = s
            .metrics_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-team"))
            .unwrap();
        assert_eq!(team.1.0, "metrics");
        assert_eq!(s.traces_headers.len(), 2);
    }

    #[test]
    fn errors_and_debug_never_echo_secrets() {
        let secret = "tok-s3cr3t-value";
        let s = resolve(
            "http://c:1",
            &[(
                "OTEL_EXPORTER_OTLP_HEADERS",
                &format!("authorization=Bearer {secret}"),
            )],
        )
        .unwrap()
        .unwrap();
        assert!(!format!("{s:?}").contains(secret));

        let err = resolve(
            "http://c:1",
            &[("OTEL_EXPORTER_OTLP_HEADERS", &format!("bad name={secret}"))],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("OTEL_EXPORTER_OTLP_HEADERS") && !err.contains(secret),
            "{err}"
        );

        let err = resolve(
            "",
            &[(
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "https://user:hunter2@host:4318",
            )],
        )
        .unwrap_err()
        .to_string();
        assert!(!err.contains("hunter2") && !err.contains("user:"), "{err}");

        let err = resolve("not a url", &[]).unwrap_err().to_string();
        assert!(
            err.contains("--otlp-endpoint") && !err.contains("not a url"),
            "{err}"
        );
    }

    #[test]
    fn endpoint_requires_http_scheme_and_host() {
        for bad in ["ftp://h:1", "http://", "//h:1", "h:4318/path"] {
            assert!(Endpoint::parse(bad, "test").is_err(), "{bad}");
        }
        assert_eq!(
            Endpoint::parse("http://[::1]:4318", "t").unwrap().host(),
            "::1"
        );
    }

    #[test]
    fn plaintext_remote_detection() {
        assert!(
            Endpoint::parse("http://collector.example:4318", "t")
                .unwrap()
                .is_plaintext_remote()
        );
        assert!(
            !Endpoint::parse("https://collector.example", "t")
                .unwrap()
                .is_plaintext_remote()
        );
        assert!(
            !Endpoint::parse("http://127.0.0.1:4318", "t")
                .unwrap()
                .is_plaintext_remote()
        );
        assert!(
            !Endpoint::parse("http://localhost:4318", "t")
                .unwrap()
                .is_plaintext_remote()
        );
    }

    #[test]
    fn metric_interval_is_validated() {
        let s = resolve("http://c:1", &[("OTEL_METRIC_EXPORT_INTERVAL", "2500")])
            .unwrap()
            .unwrap();
        assert_eq!(s.metric_interval, Duration::from_millis(2500));
        assert!(resolve("http://c:1", &[("OTEL_METRIC_EXPORT_INTERVAL", "5")]).is_err());
    }
}
