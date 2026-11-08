//! OpenTelemetry SDK wiring: providers, instruments and the per-request span.

use super::settings::{Endpoint, Settings, TelemetryError};
use super::transport::{EXPORT_TIMEOUT, ErrorReporter, UreqClient};
use super::{Outcome, RequestInfo, TraceIds};
use crate::config::Config;
use crate::logging;
use opentelemetry::metrics::{Counter, Histogram, MeterProvider as _, UpDownCounter};
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::{
    Span as _, SpanBuilder, SpanKind, Status, Tracer as _, TracerProvider as _,
};
use opentelemetry::{Context, KeyValue};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_otlp::{
    MetricExporter, Protocol, SpanExporter, WithExportConfig, WithHttpConfig,
};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider, Span as SdkSpan};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(super) const MAX_USER_AGENT: usize = 256;
pub(super) const MAX_HOST: usize = 253;

pub(super) const DURATION_BUCKETS: [f64; 15] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
];
pub(super) const SIZE_BUCKETS: [f64; 14] = [
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

pub(super) struct Instruments {
    pub(super) duration: Histogram<f64>,
    pub(super) active: UpDownCounter<i64>,
    pub(super) request_size: Histogram<u64>,
    pub(super) response_size: Histogram<u64>,
    pub(super) rejected: Counter<u64>,
}

pub(super) struct Runtime {
    pub(super) tracer: Option<SdkTracer>,
    pub(super) tracer_provider: Option<SdkTracerProvider>,
    pub(super) meter_provider: Option<SdkMeterProvider>,
    pub(super) instruments: Option<Instruments>,
    pub(super) propagator: TraceContextPropagator,
    pub(super) down: AtomicBool,
}

pub(super) fn build_error(signal: &str, ep: &Endpoint, err: impl fmt::Display) -> TelemetryError {
    let detail = logging::redact(&err.to_string());
    TelemetryError(format!(
        "cannot set up OTLP {signal} export to {}: {detail}",
        ep.host()
    ))
}

pub(super) fn resource(settings: &Settings) -> Resource {
    let mut builder = Resource::builder_empty().with_service_name(settings.service_name.clone());
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

pub(super) fn normalize_method(method: &str) -> &'static str {
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

pub(super) fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

pub(super) fn truncated(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_owned(),
        None => s.to_owned(),
    }
}

pub(super) fn host_only(host: &str) -> &str {
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
                let client = UreqClient::new(&settings.traces_headers, ep, Arc::clone(&reporter))?;
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
                let client = UreqClient::new(&settings.metrics_headers, ep, Arc::clone(&reporter))?;
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

pub(super) struct ActiveSpan {
    pub(super) rt: Arc<Runtime>,
    pub(super) span: Option<SdkSpan>,
    pub(super) start: Instant,
    pub(super) method: &'static str,
    pub(super) scheme: &'static str,
    pub(super) finished: bool,
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
