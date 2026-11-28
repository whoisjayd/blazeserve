//! BlazeServe: a fast, safe HTTP/1.1 file server for large static transfers.

pub mod cache;
pub mod cli;
pub mod config;
pub mod handler;
pub mod limiter;
pub mod logging;
pub mod metrics;
mod platform;
#[cfg(feature = "python")]
pub mod python;
pub mod range;
pub mod security;
pub mod server;
mod testknobs;
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
    pub hashes: handler::HashCache,
    pub uploads: upload::UploadState,
    pub zip_slots: Arc<tokio::sync::Semaphore>,
}

impl AppState {
    pub fn new(config: config::Config) -> Arc<Self> {
        Arc::new(Self {
            config,
            metrics: Arc::new(metrics::Metrics::new()),
            limiters: limiter::IpLimiterPool::new(4096),
            hashes: handler::HashCache::new(),
            uploads: upload::UploadState::default(),
            zip_slots: zip_stream::new_slots(),
        })
    }
}
