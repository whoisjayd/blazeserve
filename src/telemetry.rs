//! OpenTelemetry export over OTLP/HTTP (protobuf).
//!
//! Nothing runs unless an endpoint is configured, and without the `otel` feature the
//! whole module compiles to no-ops. Providers are per server, never global, so two
//! servers in one process stay independent.

use crate::config::Config;
use hyper::HeaderMap;
use hyper::header::{HeaderName, HeaderValue};
use percent_encoding::percent_decode_str;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

pub const DEFAULT_SERVICE_NAME: &str = "blazeserve";
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

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
pub struct TelemetryError(String);

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
    url: String,
    host: String,
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
struct Secret(String);

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
    traces: Option<Endpoint>,
    metrics: Option<Endpoint>,
    traces_headers: Vec<(String, Secret)>,
    metrics_headers: Vec<(String, Secret)>,
    service_name: String,
    resource_attributes: Vec<(String, String)>,
    metric_interval: Duration,
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
    fn has_headers(&self) -> bool {
        !self.traces_headers.is_empty() || !self.metrics_headers.is_empty()
    }

    #[cfg_attr(not(feature = "otel"), allow(dead_code))]
    fn insecure_remote(&self) -> Option<&Endpoint> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceIds {
    pub trace_id: String,
    pub span_id: String,
}

pub struct RequestInfo<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub scheme: &'static str,
    pub version: &'static str,
    pub client_ip: IpAddr,
    pub peer_ip: IpAddr,
    pub user_agent: Option<&'a str>,
    pub host: Option<&'a str>,
    pub request_id: &'a str,
    pub headers: &'a HeaderMap,
}

#[derive(Debug, Clone, Copy)]
pub struct Outcome {
    pub status: u16,
    pub response_bytes: u64,
    /// Recorded only when the full request body is known to have been accepted.
    pub request_bytes: Option<u64>,
    /// False when the response body was dropped before it finished (client went away).
    pub complete: bool,
}

#[derive(Clone, Default)]
pub struct Telemetry {
    #[cfg(feature = "otel")]
    rt: Option<std::sync::Arc<imp::Runtime>>,
}

impl fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Telemetry")
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

impl Telemetry {
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Reads the standard `OTEL_*` variables only when `config.otlp_endpoint` opts in.
    pub fn init(config: &Config) -> Result<Self, TelemetryError> {
        let Some(explicit) = config.otlp_endpoint.as_deref() else {
            return Ok(Self::disabled());
        };
        let env = |k: &str| std::env::var(k).ok();
        match Settings::resolve(explicit, &env)? {
            Some(settings) => Self::init_with(config, settings),
            None => Ok(Self::disabled()),
        }
    }

    pub fn init_with(config: &Config, settings: Settings) -> Result<Self, TelemetryError> {
        #[cfg(feature = "otel")]
        {
            if settings.has_headers()
                && let Some(ep) = settings.insecure_remote()
            {
                crate::logging::log_app(
                    config,
                    "WARN",
                    &format!(
                        "OTLP headers are sent over plain http to {}; use https for remote collectors",
                        ep.host()
                    ),
                );
            }
            let rt = imp::Runtime::build(config, &settings)?;
            if config.verbose {
                let signals = match (settings.traces.is_some(), settings.metrics.is_some()) {
                    (true, true) => "traces and metrics",
                    (true, false) => "traces",
                    _ => "metrics",
                };
                let host = settings
                    .traces
                    .as_ref()
                    .or(settings.metrics.as_ref())
                    .map_or("-", Endpoint::host);
                crate::logging::log_app(
                    config,
                    "INFO",
                    &format!("OpenTelemetry export enabled for {signals} to {host}"),
                );
            }
            Ok(Self {
                rt: Some(std::sync::Arc::new(rt)),
            })
        }
        #[cfg(not(feature = "otel"))]
        {
            let _ = settings;
            crate::logging::log_app(
                config,
                "WARN",
                "OTLP endpoint ignored: this build does not include the otel feature",
            );
            Ok(Self::disabled())
        }
    }

    pub fn is_enabled(&self) -> bool {
        #[cfg(feature = "otel")]
        {
            self.rt.is_some()
        }
        #[cfg(not(feature = "otel"))]
        {
            false
        }
    }

    pub fn start_request(&self, info: &RequestInfo<'_>) -> RequestSpan {
        #[cfg(feature = "otel")]
        if let Some(rt) = &self.rt {
            return RequestSpan {
                inner: Some(rt.start(info)),
            };
        }
        let _ = info;
        RequestSpan::inert()
    }

    pub fn connection_rejected(&self) {
        #[cfg(feature = "otel")]
        if let Some(rt) = &self.rt {
            rt.connection_rejected();
        }
    }

    /// Flush and stop exporters. Always returns within roughly `timeout`, even when the
    /// collector is unreachable.
    pub async fn shutdown(&self, timeout: Duration) {
        #[cfg(feature = "otel")]
        if let Some(rt) = &self.rt {
            let rt = rt.clone();
            let job = tokio::task::spawn_blocking(move || rt.shutdown_blocking(timeout));
            let _ = tokio::time::timeout(timeout + Duration::from_millis(500), job).await;
        }
        let _ = timeout;
    }
}

pub struct RequestSpan {
    #[cfg(feature = "otel")]
    inner: Option<imp::ActiveSpan>,
}

impl RequestSpan {
    pub fn inert() -> Self {
        Self {
            #[cfg(feature = "otel")]
            inner: None,
        }
    }

    pub fn trace_ids(&self) -> Option<TraceIds> {
        #[cfg(feature = "otel")]
        {
            self.inner.as_ref().and_then(imp::ActiveSpan::trace_ids)
        }
        #[cfg(not(feature = "otel"))]
        {
            None
        }
    }

    pub fn finish(self, outcome: Outcome) {
        #[cfg(feature = "otel")]
        if let Some(mut span) = self.inner {
            span.finish(&outcome);
        }
        let _ = outcome;
    }
}

#[cfg(feature = "otel")]
mod imp {
    use super::{Endpoint, Outcome, RequestInfo, Secret, Settings, TelemetryError, TraceIds};
    use crate::config::Config;
    use crate::logging;
    use async_trait::async_trait;
    use hyper::header::{HeaderName, HeaderValue};
    use opentelemetry::metrics::{Counter, Histogram, MeterProvider as _, UpDownCounter};
    use opentelemetry::propagation::TextMapPropagator;
    use opentelemetry::trace::{
        Span as _, SpanBuilder, SpanKind, Status, Tracer as _, TracerProvider as _,
    };
    use opentelemetry::{Context, KeyValue};
    use opentelemetry_http::{Bytes, HeaderExtractor, HttpClient, HttpError, Request, Response};
    use opentelemetry_otlp::{
        MetricExporter, Protocol, SpanExporter, WithExportConfig, WithHttpConfig,
    };
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider, Span as SdkSpan};
    use std::fmt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const EXPORT_TIMEOUT: Duration = Duration::from_secs(5);
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);
    const MAX_USER_AGENT: usize = 256;
    const MAX_HOST: usize = 253;
    const MAX_RESPONSE_BODY: u64 = 1 << 20;

    const DURATION_BUCKETS: [f64; 15] = [
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
    ];
    const SIZE_BUCKETS: [f64; 14] = [
        0.0,
        256.0,
        1024.0,
        4096.0,
        16_384.0,
        65_536.0,
        262_144.0,
        1_048_576.0,
        4_194_304.0,
        16_777_216.0,
        67_108_864.0,
        268_435_456.0,
        1_073_741_824.0,
        4_294_967_296.0,
    ];

    struct Instruments {
        duration: Histogram<f64>,
        active: UpDownCounter<i64>,
        request_size: Histogram<u64>,
        response_size: Histogram<u64>,
        rejected: Counter<u64>,
    }

    pub struct Runtime {
        tracer: Option<SdkTracer>,
        tracer_provider: Option<SdkTracerProvider>,
        meter_provider: Option<SdkMeterProvider>,
        instruments: Option<Instruments>,
        propagator: TraceContextPropagator,
        down: AtomicBool,
    }

    /// Rate-limits collector failure reports so a dead collector cannot flood the log.
    struct ErrorReporter {
        log: Config,
        last: Mutex<Option<Instant>>,
    }

    impl ErrorReporter {
        fn new(config: &Config) -> Self {
            Self {
                log: Config {
                    log_json: config.log_json,
                    ..Config::default()
                },
                last: Mutex::new(None),
            }
        }

        fn report(&self, host: &str, what: &str) {
            {
                let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
                if last.is_some_and(|t| t.elapsed() < ERROR_LOG_INTERVAL) {
                    return;
                }
                *last = Some(Instant::now());
            }
            logging::log_app(
                &self.log,
                "WARN",
                &format!("OpenTelemetry export to {host} failed: {what}"),
            );
        }
    }

    /// HTTP client for the OTLP exporters, built on `ureq` (rustls with `ring`), so no
    /// system TLS library is needed. It blocks, which is correct here: the SDK runs
    /// exporters on its own threads, never on the request path.
    #[derive(Clone)]
    struct UreqClient {
        agent: ureq::Agent,
        headers: Arc<Vec<(HeaderName, HeaderValue)>>,
        host: Arc<str>,
        reporter: Arc<ErrorReporter>,
    }

    impl fmt::Debug for UreqClient {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("UreqClient")
                .field("host", &self.host)
                .finish()
        }
    }

    impl UreqClient {
        fn new(
            headers: &[(String, Secret)],
            endpoint: &Endpoint,
            reporter: Arc<ErrorReporter>,
        ) -> Result<Self, TelemetryError> {
            let mut parsed = Vec::with_capacity(headers.len());
            for (k, v) in headers {
                let name = HeaderName::from_bytes(k.as_bytes())
                    .map_err(|_| TelemetryError("invalid OTLP header name".into()))?;
                let mut value = HeaderValue::from_str(&v.0)
                    .map_err(|_| TelemetryError("invalid OTLP header value".into()))?;
                value.set_sensitive(true);
                parsed.push((name, value));
            }
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .timeout_global(Some(EXPORT_TIMEOUT))
                .timeout_connect(Some(CONNECT_TIMEOUT))
                .http_status_as_error(false)
                .max_redirects(0)
                .user_agent(format!("blazeserve/{}", crate::VERSION))
                .build()
                .into();
            Ok(Self {
                agent,
                headers: Arc::new(parsed),
                host: Arc::from(endpoint.host()),
                reporter,
            })
        }

        fn send_blocking(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
            let (mut parts, body) = request.into_parts();
            // `insert`, not `append`: the exporter also reads OTEL_EXPORTER_OTLP_HEADERS from
            // the process environment and must not produce duplicate header lines.
            for (name, value) in self.headers.iter() {
                parts.headers.insert(name.clone(), value.clone());
            }
            let outgoing = ureq::http::Request::from_parts(parts, body.to_vec());
            match self.agent.run(outgoing) {
                Ok(mut resp) => {
                    let status = resp.status();
                    let payload = resp
                        .body_mut()
                        .with_config()
                        .limit(MAX_RESPONSE_BODY)
                        .read_to_vec()
                        .unwrap_or_default();
                    if !status.is_success() {
                        self.reporter.report(
                            &self.host,
                            &format!("collector returned HTTP {}", status.as_u16()),
                        );
                    }
                    Response::builder()
                        .status(status)
                        .body(Bytes::from(payload))
                        .map_err(|e| Box::new(e) as HttpError)
                }
                Err(e) => {
                    let what = match &e {
                        ureq::Error::Timeout(_) => "timed out",
                        ureq::Error::Io(_)
                        | ureq::Error::ConnectionFailed
                        | ureq::Error::HostNotFound => "connection failed",
                        _ => "request failed",
                    };
                    self.reporter.report(&self.host, what);
                    Err(Box::new(e))
                }
            }
        }
    }

    #[async_trait]
    impl HttpClient for UreqClient {
        async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
            self.send_blocking(request)
        }
    }

    fn build_error(signal: &str, ep: &Endpoint, err: impl fmt::Display) -> TelemetryError {
        let detail = logging::redact(&err.to_string());
        TelemetryError(format!(
            "cannot set up OTLP {signal} export to {}: {detail}",
            ep.host()
        ))
    }

    fn resource(settings: &Settings) -> Resource {
        let mut builder =
            Resource::builder_empty().with_service_name(settings.service_name.clone());
        if !settings
            .resource_attributes
            .iter()
            .any(|(k, _)| k == "service.version")
        {
            builder = builder.with_attribute(KeyValue::new("service.version", crate::VERSION));
        }
        builder
            .with_attributes(
                settings
                    .resource_attributes
                    .iter()
                    .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
            )
            .build()
    }

    fn normalize_method(method: &str) -> &'static str {
        match method {
            "GET" => "GET",
            "HEAD" => "HEAD",
            "POST" => "POST",
            "PUT" => "PUT",
            "DELETE" => "DELETE",
            "PATCH" => "PATCH",
            "OPTIONS" => "OPTIONS",
            "CONNECT" => "CONNECT",
            "TRACE" => "TRACE",
            _ => "_OTHER",
        }
    }

    fn status_class(status: u16) -> &'static str {
        match status / 100 {
            1 => "1xx",
            2 => "2xx",
            3 => "3xx",
            4 => "4xx",
            5 => "5xx",
            _ => "other",
        }
    }

    fn truncated(s: &str, max: usize) -> String {
        match s.char_indices().nth(max) {
            Some((i, _)) => s[..i].to_owned(),
            None => s.to_owned(),
        }
    }

    fn host_only(host: &str) -> &str {
        if let Some(rest) = host.strip_prefix('[') {
            return rest.split(']').next().unwrap_or(rest);
        }
        host.split(':').next().unwrap_or(host)
    }

    impl Runtime {
        pub fn build(config: &Config, settings: &Settings) -> Result<Self, TelemetryError> {
            let reporter = Arc::new(ErrorReporter::new(config));
            let resource = resource(settings);

            let (tracer_provider, tracer) = match &settings.traces {
                None => (None, None),
                Some(ep) => {
                    let client =
                        UreqClient::new(&settings.traces_headers, ep, Arc::clone(&reporter))?;
                    let exporter = SpanExporter::builder()
                        .with_http()
                        .with_http_client(client)
                        .with_endpoint(ep.as_str())
                        .with_protocol(Protocol::HttpBinary)
                        .with_timeout(EXPORT_TIMEOUT)
                        .build()
                        .map_err(|e| build_error("traces", ep, e))?;
                    let provider = SdkTracerProvider::builder()
                        .with_batch_exporter(exporter)
                        .with_resource(resource.clone())
                        .build();
                    let tracer = provider.tracer("blazeserve");
                    (Some(provider), Some(tracer))
                }
            };

            let (meter_provider, instruments) = match &settings.metrics {
                None => (None, None),
                Some(ep) => {
                    let client =
                        UreqClient::new(&settings.metrics_headers, ep, Arc::clone(&reporter))?;
                    let exporter = MetricExporter::builder()
                        .with_http()
                        .with_http_client(client)
                        .with_endpoint(ep.as_str())
                        .with_protocol(Protocol::HttpBinary)
                        .with_timeout(EXPORT_TIMEOUT)
                        .build()
                        .map_err(|e| build_error("metrics", ep, e))?;
                    let reader = PeriodicReader::builder(exporter)
                        .with_interval(settings.metric_interval)
                        .build();
                    let provider = SdkMeterProvider::builder()
                        .with_reader(reader)
                        .with_resource(resource)
                        .build();
                    let meter = provider.meter("blazeserve");
                    let instruments = Instruments {
                        duration: meter
                            .f64_histogram("http.server.request.duration")
                            .with_unit("s")
                            .with_description(
                                "Time from request start until the response body completes",
                            )
                            .with_boundaries(DURATION_BUCKETS.to_vec())
                            .build(),
                        active: meter
                            .i64_up_down_counter("http.server.active_requests")
                            .with_unit("{request}")
                            .with_description("Requests currently in flight")
                            .build(),
                        request_size: meter
                            .u64_histogram("http.server.request.body.size")
                            .with_unit("By")
                            .with_description("Bytes accepted in completed upload request bodies")
                            .with_boundaries(SIZE_BUCKETS.to_vec())
                            .build(),
                        response_size: meter
                            .u64_histogram("http.server.response.body.size")
                            .with_unit("By")
                            .with_description("Response body bytes actually produced")
                            .with_boundaries(SIZE_BUCKETS.to_vec())
                            .build(),
                        rejected: meter
                            .u64_counter("blazeserve.connections.rejected")
                            .with_unit("{connection}")
                            .with_description("Connections refused at the admission limit")
                            .build(),
                    };
                    (Some(provider), Some(instruments))
                }
            };

            Ok(Self {
                tracer,
                tracer_provider,
                meter_provider,
                instruments,
                propagator: TraceContextPropagator::new(),
                down: AtomicBool::new(false),
            })
        }

        pub fn start(self: &Arc<Self>, info: &RequestInfo<'_>) -> ActiveSpan {
            let method = normalize_method(info.method);
            let span = self.tracer.as_ref().map(|tracer| {
                let parent: Context = self.propagator.extract(&HeaderExtractor(info.headers));
                let mut attrs = vec![
                    KeyValue::new("http.request.method", method),
                    KeyValue::new("url.path", info.path.to_owned()),
                    KeyValue::new("url.scheme", info.scheme),
                    KeyValue::new("network.protocol.version", info.version),
                    KeyValue::new("network.peer.address", info.peer_ip.to_string()),
                    KeyValue::new("client.address", info.client_ip.to_string()),
                    KeyValue::new("blaze.request_id", info.request_id.to_owned()),
                ];
                if let Some(host) = info.host {
                    attrs.push(KeyValue::new(
                        "server.address",
                        truncated(host_only(host), MAX_HOST),
                    ));
                }
                if let Some(ua) = info.user_agent {
                    attrs.push(KeyValue::new(
                        "user_agent.original",
                        truncated(ua, MAX_USER_AGENT),
                    ));
                }
                let builder = SpanBuilder::from_name(method)
                    .with_kind(SpanKind::Server)
                    .with_attributes(attrs);
                tracer.build_with_context(builder, &parent)
            });
            if let Some(i) = &self.instruments {
                i.active.add(
                    1,
                    &[
                        KeyValue::new("http.request.method", method),
                        KeyValue::new("url.scheme", info.scheme),
                    ],
                );
            }
            ActiveSpan {
                rt: Arc::clone(self),
                span,
                start: Instant::now(),
                method,
                scheme: info.scheme,
                finished: false,
            }
        }

        pub fn connection_rejected(&self) {
            if let Some(i) = &self.instruments {
                i.rejected.add(1, &[]);
            }
        }

        pub fn shutdown_blocking(&self, timeout: Duration) {
            if self.down.swap(true, Ordering::SeqCst) {
                return;
            }
            if let Some(tp) = &self.tracer_provider {
                let _ = tp.shutdown_with_timeout(timeout);
            }
            if let Some(mp) = &self.meter_provider {
                let _ = mp.shutdown_with_timeout(timeout);
            }
        }
    }

    impl Drop for Runtime {
        /// A server dropped without a graceful shutdown must not block its caller on a
        /// collector round trip, so the final flush happens on a detached thread.
        fn drop(&mut self) {
            if self.down.swap(true, Ordering::SeqCst) {
                return;
            }
            let tp = self.tracer_provider.clone();
            let mp = self.meter_provider.clone();
            if tp.is_none() && mp.is_none() {
                return;
            }
            let _ = std::thread::Builder::new()
                .name("blazeserve-otel-flush".into())
                .spawn(move || {
                    if let Some(tp) = tp {
                        let _ = tp.shutdown_with_timeout(super::FLUSH_TIMEOUT);
                    }
                    if let Some(mp) = mp {
                        let _ = mp.shutdown_with_timeout(super::FLUSH_TIMEOUT);
                    }
                });
        }
    }

    pub struct ActiveSpan {
        rt: Arc<Runtime>,
        span: Option<SdkSpan>,
        start: Instant,
        method: &'static str,
        scheme: &'static str,
        finished: bool,
    }

    impl ActiveSpan {
        pub fn trace_ids(&self) -> Option<TraceIds> {
            let span = self.span.as_ref()?;
            let ctx = span.span_context();
            ctx.is_valid().then(|| TraceIds {
                trace_id: ctx.trace_id().to_string(),
                span_id: ctx.span_id().to_string(),
            })
        }

        pub fn finish(&mut self, o: &Outcome) {
            if self.finished {
                return;
            }
            self.finished = true;
            let class = status_class(o.status);
            if let Some(mut span) = self.span.take() {
                span.set_attribute(KeyValue::new(
                    "http.response.status_code",
                    i64::from(o.status),
                ));
                span.set_attribute(KeyValue::new(
                    "http.response.body.size",
                    i64::try_from(o.response_bytes).unwrap_or(i64::MAX),
                ));
                span.set_attribute(KeyValue::new("blaze.response.complete", o.complete));
                if o.status >= 500 {
                    span.set_attribute(KeyValue::new("error.type", o.status.to_string()));
                    span.set_status(Status::error(""));
                }
                span.end();
            }
            if let Some(i) = &self.rt.instruments {
                let labels = [
                    KeyValue::new("http.request.method", self.method),
                    KeyValue::new("blaze.status_class", class),
                    KeyValue::new("url.scheme", self.scheme),
                ];
                i.duration
                    .record(self.start.elapsed().as_secs_f64(), &labels);
                i.response_size.record(o.response_bytes, &labels);
                if let Some(bytes) = o.request_bytes {
                    i.request_size.record(bytes, &labels);
                }
                i.active.add(
                    -1,
                    &[
                        KeyValue::new("http.request.method", self.method),
                        KeyValue::new("url.scheme", self.scheme),
                    ],
                );
            }
        }
    }

    impl Drop for ActiveSpan {
        /// Keeps the in-flight gauge balanced if a request is abandoned before `finish`.
        fn drop(&mut self) {
            if self.finished {
                return;
            }
            self.finished = true;
            if let Some(mut span) = self.span.take() {
                span.end();
            }
            if let Some(i) = &self.rt.instruments {
                i.active.add(
                    -1,
                    &[
                        KeyValue::new("http.request.method", self.method),
                        KeyValue::new("url.scheme", self.scheme),
                    ],
                );
            }
        }
    }
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

    #[test]
    fn disabled_telemetry_is_inert() {
        let t = Telemetry::disabled();
        assert!(!t.is_enabled());
        let cfg = Config::default();
        assert!(!Telemetry::init(&cfg).unwrap().is_enabled());
    }
}
