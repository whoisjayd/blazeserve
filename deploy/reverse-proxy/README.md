# Reverse Proxy Integration for BlazeServe

This directory contains tested, production-grade reverse proxy configurations for **Nginx**, **Caddy**, and **Traefik v3**.

## Why Reverse Proxy Buffering Must Be Disabled

BlazeServe is engineered for high-throughput range requests and multi-gigabyte file streaming. Standard reverse proxy defaults buffer response bodies in memory or temporary disk buffers, creating massive latency spikes and double disk I/O.

- **Nginx**: Configured with `proxy_buffering off;` and `proxy_request_buffering off;`.
- **Caddy**: Configured with `flush_interval -1` to immediately stream zero-copy chunks to clients.
- **Traefik**: Configured with direct pass-through and health check probes to `/__live__`.
