# Changelog

All notable changes to BlazeServe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-09-04

### Added
- **SRE Operational Probes**: Added Kubernetes liveness probe (`/__live__`) and readiness probe (`/__ready__`) verifying filesystem mount accessibility.
- **Prometheus OpenMetrics Telemetry**: Native zero-dependency Prometheus exposition format available at `/__metrics__` and `/metrics` exposing Golden Signals (throughput, latency, active connections, error counters).
- **RFC 7232 / 9110 HTTP Caching**: Full conditional request validation supporting `If-None-Match` (ETag) and `If-Modified-Since` (Last-Modified) returning `304 Not Modified` with zero network overhead.
- **Per-IP Rate Limiting**: Added thread-safe `IPRateLimiterPool` with LRU eviction, returning standard `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers alongside HTTP `429 Too Many Requests` rejection.
- **Defense-in-Depth Security Headers**: Automatic injection of `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, and `Strict-Transport-Security` (on TLS).
- **Correlation Tracing**: Automatic generation and propagation of `X-Request-ID` headers for end-to-end distributed request tracing.
- **Structured JSON Logging**: Added `--log-json` CLI flag and `BLAZE_LOG_JSON=1` environment variable support with ISO8601 timestamps, request IDs, and client IP tracking.
- **Modern Responsive HTML5 Web UI**: Beautiful glassmorphic directory explorer with dark/light mode (`prefers-color-scheme`), client-side instant search filter, file type icons, and drag-and-drop upload zone.
- **SRE Environment Diagnostic (`blaze doctor`)**: CLI command auditing directory read permissions, socket port availability, kernel zero-copy capabilities, and sequential read-ahead support.
- **Machine-Readable Version**: Added `--json` flag to `blaze version` command.
- **Cloud & Kubernetes Artifacts**: Added a production `Deployment` and `Service`, with optional Ingress and ServiceMonitor templates.
- **SRE Monitoring Stack**: Added Prometheus scrape configuration (`deploy/monitoring/prometheus.yml`), Prometheus alert rules (`deploy/monitoring/alerts.yml`), and production Grafana dashboard JSON (`deploy/monitoring/grafana-dashboard.json`).
- **DevOps Blueprints**: Added a hardened systemd service, unbuffered streaming reverse proxy configs for Nginx, Caddy, and Traefik v3 (`deploy/reverse-proxy/`), and Linux kernel networking sysctl tuning script (`deploy/linux-tuning/tuning.sh`).
- **Multi-Stage Dockerfile**: Hardened distroless-style build using unprivileged system user `blazeserve` (`uid: 10001`), read-only root filesystem, dropped Linux capabilities, and native Docker container `HEALTHCHECK`.

### Changed
- **Modular Code Architecture**: Decomposed monolithic server into single-responsibility modules: `metrics.py`, `limiter.py`, `security.py`, `ui.py`, `handlers.py`, and `server.py` while maintaining 100% backwards-compatible re-exports.
- **Modern Toolchain & Dependencies**: Upgraded minimum Python support to `>=3.10` (Python 3.9 EOL), upgraded Click to `>=8.3.0`, Rich to `>=14.0.0`, Rich-Click to `>=1.8.0`, Ruff to `>=0.9.0`, Mypy to `>=1.11`, Pytest to `>=8.0`, and added `pytest-cov`.
- **Enterprise CI/CD**: Modernized GitHub Actions workflow to matrix across Python 3.10–3.13, Ruff linting/formatting, strict Mypy typing, Pytest coverage enforcement, Docker smoke testing, and OIDC PyPI publishing.
- **Safe Deployment Defaults**: Compose and Kubernetes deployments now mount served data read-only and leave uploads disabled unless operators explicitly configure authenticated writable storage; systemd now matches the reverse-proxy backend on port 8000.
### Fixed
- **Memory-Safe Mmap Lifecycle**: Fixed Windows `BufferError` and file-locking `PermissionError` by implementing deterministic `memoryview.release()` before closing `mmap` instances in `_send_range`.
- **Graceful Server Shutdown**: Handled `SIGINT` and `SIGTERM` signals for non-blocking server shutdown, connection draining, and clean socket closure.
- **TLS Lifecycle**: Removed the unsafe `SIGHUP` listener rewrapping path; certificate rotation now uses a controlled process restart.

---

## [0.2.0] - 2025-12-27

### Added
- **Performance Monitoring**: New `/__perf__` endpoint provides real-time server metrics including uptime, throughput, requests, and configuration
- **Thread-Safe Metrics**: ServerMetrics class with proper locking for accurate concurrent tracking
- **Request Lifecycle Tracking**: Active and total request counters
- **Error Tracking**: Comprehensive error counting in metrics
- **Performance Tuning Documentation**: Detailed guide for optimizing server performance
- **LAN Usage Tips**: Instructions for maximum speed on local networks
- **Benchmark Command**: New `blaze benchmark` command for testing server performance
- **Enhanced CLI UI**: Improved startup banner with version info and optional performance details
- **Comprehensive Test Suite**: Added 42 tests covering server, CLI, utilities, and edge cases
- **Production Deployment Guide**: Complete guide for systemd, Docker, and reverse proxy setups
- **pytest Configuration**: Modern test configuration with markers and proper organization

### Changed
- **BREAKING**: Default send buffer increased from 64MB to 128MB (`--sock-sndbuf-mb`)
- **BREAKING**: Default chunk size increased from 128MB to 256MB (`--chunk-mb`)
- **BREAKING**: Default receive buffer increased from 32MB to 64MB
- **BREAKING**: Default connection backlog increased from 4096 to 8192
- **Version Bump**: 0.1.0 → 0.2.0
- **Rate Limiter**: Replaced with efficient token bucket algorithm with 2-second burst capacity
- **ZIP Streaming**: Changed to uncompressed (ZIP_STORED) by default for maximum speed
- **I/O Performance**: Optimized sendfile implementation with better partial send handling
- **Version Command**: Enhanced to show Python version, platform, and architecture
- **CLI Description**: Updated with performance highlights

### Fixed
- **sendfile Logic**: Corrected handling of partial sends when rate limiting is enabled
- **Thread Safety**: Fixed race conditions in metrics updates with proper locking
- **Upload Security**: Enhanced path traversal protection in upload endpoint
- **ZIP Security**: Added path validation in ZIP streaming endpoint
- **Error Handling**: Removed unnecessary TypeError catch in upload handler

---

## [0.1.0] - Initial Release

### Added
- Static file serving over HTTP/1.1
- Range and multi-range request support
- Zero-copy sendfile support
- Memory-mapped I/O for efficient file transfers
- Per-connection rate limiting
- Directory listing with automatic index.html
