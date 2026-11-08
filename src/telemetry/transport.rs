//! The HTTP client the OTLP exporters send through, and the rate-limited failure report.

use super::settings::{Endpoint, Secret, TelemetryError};
use crate::config::Config;
use crate::logging;
use async_trait::async_trait;
use hyper::header::{HeaderName, HeaderValue};
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(super) const EXPORT_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);
pub(super) const MAX_RESPONSE_BODY: u64 = 1 << 20;

/// Rate-limits collector failure reports so a dead collector cannot flood the log.
pub(super) struct ErrorReporter {
    pub(super) log: Config,
    pub(super) last: Mutex<Option<Instant>>,
}

impl ErrorReporter {
    pub(super) fn new(config: &Config) -> Self {
        Self {
            log: Config {
                log_json: config.log_json,
                ..Config::default()
            },
            last: Mutex::new(None),
        }
    }

    pub(super) fn report(&self, host: &str, what: &str) {
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
pub(super) struct UreqClient {
    pub(super) agent: ureq::Agent,
    pub(super) headers: Arc<Vec<(HeaderName, HeaderValue)>>,
    pub(super) host: Arc<str>,
    pub(super) reporter: Arc<ErrorReporter>,
}

impl fmt::Debug for UreqClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UreqClient")
            .field("host", &self.host)
            .finish()
    }
}

impl UreqClient {
    pub(super) fn new(
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

    pub(super) fn send_blocking(
        &self,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, HttpError> {
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
