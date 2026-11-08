//! OpenTelemetry export over OTLP/HTTP (protobuf).
//!
//! Nothing runs unless an endpoint is configured, and without the `otel` feature the
//! whole module compiles to no-ops. Providers are per server, never global, so two
//! servers in one process stay independent.

use crate::config::Config;
use hyper::HeaderMap;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

#[cfg(feature = "otel")]
mod exporter;
mod settings;
#[cfg(feature = "otel")]
mod transport;

pub use settings::{Endpoint, Settings, TelemetryError, env_endpoint_present};

pub const DEFAULT_SERVICE_NAME: &str = "blazeserve";
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

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
    rt: Option<std::sync::Arc<exporter::Runtime>>,
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
            let rt = exporter::Runtime::build(config, &settings)?;
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
    inner: Option<exporter::ActiveSpan>,
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
            self.inner
                .as_ref()
                .and_then(exporter::ActiveSpan::trace_ids)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_telemetry_is_inert() {
        let t = Telemetry::disabled();
        assert!(!t.is_enabled());
        let cfg = Config::default();
        assert!(!Telemetry::init(&cfg).unwrap().is_enabled());
    }
}
