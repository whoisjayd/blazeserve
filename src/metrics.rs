//! Lock-free telemetry. Names and types of the Prometheus series are a public
//! contract (see `deploy/monitoring/`): do not rename without a migration note.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

#[derive(Debug)]
pub struct Metrics {
    started: Instant,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    requests_total: AtomicU64,
    requests_active: AtomicI64,
    errors_total: AtomicU64,
    connections_active: AtomicI64,
    connections_rejected_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Stats {
    pub uptime_seconds: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub requests_total: u64,
    pub requests_active: u64,
    pub errors_total: u64,
    pub bytes_per_second: u64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            requests_total: AtomicU64::new(0),
            requests_active: AtomicI64::new(0),
            errors_total: AtomicU64::new(0),
            connections_active: AtomicI64::new(0),
            connections_rejected_total: AtomicU64::new(0),
        }
    }

    pub fn add_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Relaxed);
    }
    /// Count only bytes actually accepted from the client.
    pub fn add_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Relaxed);
    }
    pub fn add_error(&self) {
        self.errors_total.fetch_add(1, Relaxed);
    }
    pub fn add_connection_rejected(&self) {
        self.connections_rejected_total.fetch_add(1, Relaxed);
    }

    /// RAII guard: counts a parsed request and decrements the active gauge exactly
    /// once on every exit path, including panics and dropped futures.
    pub fn request_guard(self: &Arc<Self>) -> RequestGuard {
        self.requests_total.fetch_add(1, Relaxed);
        self.requests_active.fetch_add(1, Relaxed);
        RequestGuard(Arc::clone(self))
    }

    pub fn connection_guard(&self) -> ConnectionGuard<'_> {
        self.connections_active.fetch_add(1, Relaxed);
        ConnectionGuard(self)
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Relaxed)
    }
    pub fn requests_active(&self) -> u64 {
        self.requests_active.load(Relaxed).max(0) as u64
    }
    pub fn connections_active(&self) -> u64 {
        self.connections_active.load(Relaxed).max(0) as u64
    }

    fn uptime(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    pub fn stats(&self) -> Stats {
        let uptime = self.uptime();
        let sent = self.bytes_sent.load(Relaxed);
        Stats {
            uptime_seconds: uptime as u64,
            bytes_sent: sent,
            bytes_received: self.bytes_received.load(Relaxed),
            requests_total: self.requests_total.load(Relaxed),
            requests_active: self.requests_active(),
            errors_total: self.errors_total.load(Relaxed),
            bytes_per_second: if uptime > 0.0 {
                (sent as f64 / uptime) as u64
            } else {
                0
            },
        }
    }

    pub fn to_prometheus(&self) -> String {
        let s = self.stats();
        let mut out = String::with_capacity(1024);
        let mut series = |name: &str, kind: &str, help: &str, value: u64| {
            let _ = write!(
                out,
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
            );
        };
        series(
            "blazeserve_uptime_seconds",
            "gauge",
            "Total server uptime in seconds",
            s.uptime_seconds,
        );
        series(
            "blazeserve_bytes_sent_total",
            "counter",
            "Total bytes sent to clients",
            s.bytes_sent,
        );
        series(
            "blazeserve_bytes_received_total",
            "counter",
            "Total bytes received via uploads",
            s.bytes_received,
        );
        series(
            "blazeserve_requests_total",
            "counter",
            "Total HTTP requests handled",
            s.requests_total,
        );
        series(
            "blazeserve_requests_active",
            "gauge",
            "Current active in-flight HTTP requests",
            s.requests_active,
        );
        series(
            "blazeserve_errors_total",
            "counter",
            "Total server errors encountered",
            s.errors_total,
        );
        series(
            "blazeserve_connections_active",
            "gauge",
            "Currently admitted TCP connections",
            self.connections_active(),
        );
        series(
            "blazeserve_connections_rejected_total",
            "counter",
            "Connections refused because the admission limit was reached",
            self.connections_rejected_total.load(Relaxed),
        );
        out
    }
}

pub struct RequestGuard(Arc<Metrics>);
impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.0.requests_active.fetch_sub(1, Relaxed);
    }
}

pub struct ConnectionGuard<'a>(&'a Metrics);
impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.0.connections_active.fetch_sub(1, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_balances_active_gauge() {
        let m = Arc::new(Metrics::new());
        {
            let _a = m.request_guard();
            let _b = m.request_guard();
            assert_eq!(m.requests_active(), 2);
        }
        assert_eq!(m.requests_active(), 0);
        assert_eq!(m.stats().requests_total, 2);
    }

    #[test]
    fn prometheus_keeps_public_names() {
        let text = Metrics::new().to_prometheus();
        for name in [
            "blazeserve_uptime_seconds",
            "blazeserve_bytes_sent_total",
            "blazeserve_bytes_received_total",
            "blazeserve_requests_total",
            "blazeserve_requests_active",
            "blazeserve_errors_total",
        ] {
            assert!(text.contains(&format!("# TYPE {name} ")), "{name} missing");
        }
    }
}
