# Changelog

All notable changes to BlazeServe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2024-12-27

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

### Performance
- **Platform Optimizations**: Auto-enabled SO_REUSEPORT (Linux) for multi-core load balancing
- **TCP Optimizations**: Enabled TCP_QUICKACK (Linux) for reduced ACK delay
- **Network Stack**: TCP_NODELAY enabled by default for lower latency
- **I/O Fast Paths**: Multiple optimization paths (sendfile → mmap → buffered)
- **Speed Test**: Increased chunk size from 4MB to 8MB for better throughput testing

### Documentation
- **README**: Enhanced with performance highlights and ⚡ branding
- **CHANGELOG**: Added comprehensive changelog following Keep a Changelog format
- **DEPLOYMENT**: Complete production deployment guide
- **MANIFEST**: Added for proper package distribution

## [0.1.0] - Initial Release

### Added
- Static file serving over HTTP/1.1
- Range and multi-range request support
- Zero-copy sendfile support
- Memory-mapped I/O for efficient file transfers
- Per-connection rate limiting
- Directory listing with automatic index.html
- Single-file mode
- Streaming ZIP downloads
- File uploads via PUT/POST
- Health check endpoint (`/__health__`)
- Statistics endpoint (`/__stats__`)
- Speed test endpoint (`/__speed__`)
- TLS/HTTPS support
- HTTP Basic Authentication
- CORS support
- Precompressed .gz file serving
- Rich CLI with colorful output
- Cross-platform support (Linux/macOS/Windows)

[0.2.0]: https://github.com/whoisjayd/blazeserve/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/whoisjayd/blazeserve/releases/tag/v0.1.0

