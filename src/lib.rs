//! BlazeServe: a fast, safe HTTP/1.1 file server for large static transfers.

pub mod cache;
pub mod cli;
pub mod config;
pub mod handler;
pub mod limiter;
pub mod logging;
pub mod metrics;
#[cfg(feature = "python")]
pub mod python;
pub mod range;
pub mod security;
pub mod server;
pub mod telemetry;
pub mod ui;
pub mod upload;
pub mod usage;
pub mod zip_stream;

use std::sync::Arc;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type Body = http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub socket_addr: std::net::SocketAddr,
    /// Identity used for rate limiting and logs. Equals the socket peer unless a
    /// trusted proxy chain resolved a forwarded client (see `server::resolve_client_ip`).
    pub client_ip: std::net::IpAddr,
    pub tls: bool,
}

/// Per-server state. Never global: two servers in one process must not share it.
#[derive(Debug)]
pub struct AppState {
    pub config: config::Config,
    pub metrics: Arc<metrics::Metrics>,
    pub limiters: limiter::IpLimiterPool,
    pub telemetry: telemetry::Telemetry,
}

impl AppState {
    pub fn new(config: config::Config) -> Arc<Self> {
        Self::with_telemetry(config, telemetry::Telemetry::disabled())
    }

    pub fn with_telemetry(config: config::Config, telemetry: telemetry::Telemetry) -> Arc<Self> {
        Arc::new(Self {
            config,
            metrics: Arc::new(metrics::Metrics::new()),
            limiters: limiter::IpLimiterPool::new(4096),
            telemetry,
        })
    }
}
