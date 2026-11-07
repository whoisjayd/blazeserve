<div align="center">

# BlazeServe

**A fast, safe HTTP file server for large files. One static binary, the same on Linux, Windows and macOS.**

<br />

[![CI](https://img.shields.io/github/actions/workflow/status/whoisjayd/blazeserve/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/whoisjayd/blazeserve/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/whoisjayd/blazeserve?style=flat-square)](https://github.com/whoisjayd/blazeserve/releases)
[![PyPI](https://img.shields.io/pypi/v/blazeserve?style=flat-square&label=pip)](https://pypi.org/project/blazeserve/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20windows%20%7C%20macos-informational?style=flat-square)

<br />

[Quick start](#quick-start) · [Features](#features) · [Command reference](#command-reference) · [Deploy](#deploy) · [Security](#security-model) · [Contributing](CONTRIBUTING.md)

</div>

## Why BlazeServe

Sharing a large file or serving a static folder should not need a runtime, a config file, or a prayer that a dropped connection will not restart a 20 GB transfer. BlazeServe is one binary with no system libraries. It streams with bounded memory, resumes interrupted downloads and uploads, and fails closed on anything that touches the filesystem or credentials.

It is built for:

- **Sharing a file** with a colleague over a LAN or a tunnel, in one command
- **Serving build artifacts, datasets and release mirrors** behind a reverse proxy
- **Receiving uploads** with length and digest verification and atomic publication
- **Operating it properly**, with health endpoints, Prometheus metrics, OpenTelemetry and JSON logs

## Quick start

```bash
pip install blazeserve          # or: uv tool install blazeserve
blaze serve .                   # serve this folder on http://localhost:8000
blaze send ./big.iso            # share one file
blaze get http://host:8000/big.iso   # download it, resuming if interrupted
```

Prefer another install method?

| Method | Command |
| :--- | :--- |
| pip or uv | `pip install blazeserve` or `uv tool install blazeserve` |
| Cargo | `cargo install --git https://github.com/whoisjayd/blazeserve` |
| Binary | Download an archive from [Releases](https://github.com/whoisjayd/blazeserve/releases) and check it against `SHA256SUMS` |
| Container | `docker run --rm -p 8000:8000 -v "$PWD":/data:ro ghcr.io/whoisjayd/blazeserve:latest` |

Archives and wheels cover Linux (x86_64 and aarch64, glibc and musl), Windows x86_64 and macOS (x86_64 and aarch64). Building from source needs Rust 1.88 or newer.

## Features

| Area | What you get |
| :--- | :--- |
| Transfers | Single and multi-range requests, `If-None-Match` and `If-Modified-Since`, `If-Range`, precompressed `.gz` and `.br` assets, streaming ZIP of a file or folder |
| Resumable | `blaze get` continues from a `.part` file; `blaze put` continues an interrupted upload |
| Uploads | Off by default. Create-only, length and digest verified, published atomically, replace only with a matching `If-Match` |
| Access | Basic Auth, TLS 1.2+, CORS, per-client throttling |
| Reliability | HTTP/1.1 and HTTP/2 (TLS ALPN `h2`, cleartext prior-knowledge h2c), Connection limit, header timeout, idle timeout, graceful shutdown, bounded transfer buffers |
| Proxies | Trusted-proxy client identity from `Forwarded` and `X-Forwarded-For` |
| Operations | Liveness and readiness probes, Prometheus metrics, OpenTelemetry traces and metrics, structured JSON logs, `blaze doctor` |
| Browsing | A responsive directory listing with filter and sort, and a JSON listing for scripts |
| Tooling | `checksum`, `benchmark`, and an opt-out anonymous usage report |

## Everyday commands

```bash
blaze serve ./site --host 127.0.0.1 -p 9000      # bind loopback on another port
blaze serve . --rate-mbps 25                     # throttle each client to 25 MB/s
blaze serve . --max-upload-mb 500 --auth-env BLAZE_AUTH   # accept uploads, with auth
blaze serve . --qr                               # print a QR code of the network URL
blaze checksum ./big.iso                         # SHA-256, streamed
blaze doctor ./site                              # check path, port and capabilities
blaze benchmark                                  # loopback self-test
blaze version --json
```

### Authentication and TLS

Prefer `--auth-env` to `--auth` so the credential stays out of process listings.

```powershell
# PowerShell
$env:BLAZE_AUTH = "alice:s3cret"
blaze serve ./site --auth-env BLAZE_AUTH --tls-cert cert.pem --tls-key key.pem
```

```bash
# POSIX
export BLAZE_AUTH='alice:s3cret'
blaze serve ./site --auth-env BLAZE_AUTH --tls-cert cert.pem --tls-key key.pem
```

A named but empty or unset variable is an error; the server never falls back to running unauthenticated. A certificate without a key, or the reverse, is rejected before binding. Certificate rotation needs a restart.

### Resumable transfers

```bash
blaze get http://host:8000/big.iso                       # resumes from big.iso.part
blaze get http://host:8000/big.iso --sha256 <hex>        # also verify the content
blaze get http://host:8000/big.iso -c 8                # eight parallel connections
blaze put ./big.iso http://host:8000/__upload__/big.iso  # resumes from the server's offset
```

`get` continues with a `Range` request, validates it with `If-Range`, retries with backoff, and checks the final size before renaming the file into place. With `--connections N` (1 to 16, default 4) a file of at least 8 MiB is fetched in 8 MiB segments over N connections and written in place, and an interrupted run skips the segments already finished. This needs a known length, `Accept-Ranges: bytes` and a strong `ETag` or a `Last-Modified`; otherwise, or with `--connections 1`, `get` silently uses a single stream. `put` reads the server's `Upload-Offset` and sends the rest in chunks.

### Uploads

Uploads are off until `--max-upload-mb` is a positive number, which is also the size ceiling. They are create-only: an existing file returns `409`. A request replaces a file only when it carries an `If-Match` with the file's current `ETag`; a stale tag returns `412`.

A body is staged next to its destination and published only after the declared length matches and, when sent, the digest matches. `Content-Digest`, `Digest` and `X-Content-SHA256` are accepted, and `Repr-Digest` checks a whole resumed file. Always set `--auth` or `--auth-env` when uploads are enabled on a reachable address.

### Behind a reverse proxy

Pass `--trust-proxy <ip-or-cidr>` (repeatable) so rate limits and logs see the real client. BlazeServe walks `Forwarded`, or `X-Forwarded-For`, from the right and skips trusted hops. The first untrusted address is the client, and headers from any other peer are ignored. The immediate peer is logged separately as `peer_ip`. This is safe only when clients cannot reach BlazeServe directly. Ready-made Nginx, Caddy and Traefik configurations that keep streaming unbuffered are in [deploy/README.md](deploy/README.md#reverse-proxy). Cleartext HTTP/2 (h2c with prior knowledge) is accepted on the same port, so a proxy may speak h2c to BlazeServe.

### Limits

`--max-connections` (default 1024) bounds admitted connections. Beyond it a client receives `503` with `Retry-After: 1`, and the refusal is counted. A client that does not finish its request headers within `--header-timeout` (default 10 seconds) is dropped, and idle connections close after `--timeout`.

## Use from Python and Rust

`pip install blazeserve` installs the `blaze` command and a Python module from one abi3 wheel for Python 3.11 and newer.

```python
import urllib.request
import blazeserve

with blazeserve.Server("./site", port=0, auth="ada:secret") as server:
    print(server.url)            # http://127.0.0.1:<port>/
    ...                          # use any HTTP client against it

print(blazeserve.sha256("big.iso"))
blazeserve.main(["get", "http://host:8000/big.iso"])   # any CLI command, returns the exit status
```

`Server(path=None, host="127.0.0.1", port=0, *, listing, auth, cors, no_cache, max_upload_mb, rate_mbps, tls_cert, tls_key)` binds before the constructor returns. `close()` and leaving the `with` block stop it, and `serve_forever()` blocks until `KeyboardInterrupt`. Configuration errors raise `blazeserve.BlazeError`. The Python server binds loopback by default, unlike `blaze serve`. Resumable download and upload are available through `blazeserve.main` and print their progress like the command does.

In Rust, `blazeserve::config::Config` and `blazeserve::server::start` start a server inside your own tokio runtime, and `blazeserve::cli::main_from` runs the command line from an argument list.

## Endpoints

| Path | Methods | Notes |
| :--- | :--- | :--- |
| `/<path>` | GET, HEAD | Files and listings. `Accept: application/json` returns a JSON listing; `?download=1` sets `Content-Disposition: attachment` |
| `/__upload__/<path>` | PUT, POST, GET, HEAD, DELETE | Only when uploads are enabled. GET and HEAD report `Upload-Offset` for a partial; DELETE discards a partial and never a published file |
| `/__zip__?path=<path>` | GET, HEAD | Streamed ZIP; the connection closes afterwards |
| `/__health__` | GET, HEAD | Status, version, uptime |
| `/__live__` | GET, HEAD | Liveness |
| `/__ready__` | GET, HEAD | Readiness; checks the served root |
| `/__version__` | GET, HEAD | Name, version, platform |
| `/__metrics__`, `/metrics` | GET, HEAD | Prometheus text |
| `/__stats__` | GET, HEAD | Bytes sent |
| `/__perf__` | GET, HEAD | Effective limits and counters |
| `/__speed__?bytes=N` | GET, HEAD | N zero bytes, at most 1000 MiB; used by `blaze benchmark` |

A `Range` header with more than 64 ranges, or ranges that together exceed the file size, is answered with the whole file, so a range request cannot multiply the response. Operational JSON and metrics send `Cache-Control: no-store`. Every response carries `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy`, plus `Strict-Transport-Security` over TLS and an `X-Request-ID`. A client-supplied request ID is echoed only if it is 1 to 64 characters and alphanumeric once hyphens are removed; otherwise 12 hex characters are generated.

## Observability

### Metrics

`/__metrics__` and `/metrics` serve Prometheus text with no labels. Names and types are a public contract.

| Series | Type | Meaning |
| :--- | :--- | :--- |
| `blazeserve_uptime_seconds` | gauge | Time since start |
| `blazeserve_bytes_sent_total` | counter | Response body bytes written |
| `blazeserve_bytes_received_total` | counter | Upload body bytes accepted |
| `blazeserve_requests_total` | counter | Parsed requests; two on one keep-alive connection count twice |
| `blazeserve_requests_active` | gauge | In-flight requests, balanced on every exit |
| `blazeserve_errors_total` | counter | Unexpected server failures; client disconnects are not errors |
| `blazeserve_connections_active` | gauge | Admitted TCP connections |
| `blazeserve_connections_rejected_total` | counter | Connections refused at `--max-connections` |

Byte counters count bytes actually written or read, never declared lengths. Alert rules and a Grafana dashboard are in [deploy/README.md](deploy/README.md#monitoring).

### Logs

With `--log-json` or `BLAZE_LOG_JSON=1`, stdout carries one JSON object per request: `timestamp` (UTC), `level`, `request_id`, `client_ip`, `peer_ip`, `request`, `status` and `size`, plus `trace_id` and `span_id` when tracing is on. `client_ip` is the resolved client and `peer_ip` is the socket peer. Human output moves to stderr. Authorization values, credentials in URLs, `--auth-env` values, TLS keys and content are never logged.

### OpenTelemetry

Traces (one span per request, HTTP server conventions) and metrics (`http.server.request.duration`, `http.server.active_requests`, `http.server.request.body.size`, `http.server.response.body.size`, `blazeserve.connections.rejected`) export over OTLP/HTTP. Export is off until an endpoint is set, with `--otlp-endpoint` or the standard variables. Any OTLP backend works, including the free tiers of hosted services.

`OTEL_EXPORTER_OTLP_HEADERS` usually holds a token, so treat it as a secret: keep it in the environment or a secret store, never on a command line, in a committed file or in a log. The values below are placeholders.

```powershell
# PowerShell
$env:OTEL_EXPORTER_OTLP_ENDPOINT = "https://otlp.example.com"
$env:OTEL_EXPORTER_OTLP_PROTOCOL = "http/protobuf"
$env:OTEL_EXPORTER_OTLP_HEADERS  = "Authorization=Basic <BASE64_INSTANCE_ID_AND_TOKEN>"
$env:OTEL_SERVICE_NAME           = "blazeserve"
blaze serve ./site
```

```bash
# POSIX
export OTEL_EXPORTER_OTLP_ENDPOINT='https://otlp.example.com'
export OTEL_EXPORTER_OTLP_PROTOCOL='http/protobuf'
export OTEL_EXPORTER_OTLP_HEADERS='Authorization=Basic <BASE64_INSTANCE_ID_AND_TOKEN>'
export OTEL_SERVICE_NAME='blazeserve'
blaze serve ./site
```

Only `http/protobuf` is supported. An unreachable collector never slows requests, and shutdown flushes for at most five seconds. For a local stack, `docker compose --profile observability up -d` adds Grafana on `http://localhost:3000` and OTLP on port 4318.

## Deploy

| Target | Where |
| :--- | :--- |
| Docker and Compose | `ghcr.io/whoisjayd/blazeserve`, a `scratch` image running as uid 10001, with a hardened `docker-compose.yml` |
| Kubernetes | A private, single-replica Deployment and ClusterIP Service, with optional Ingress and ServiceMonitor |
| systemd | A hardened unit bound to `127.0.0.1:8000` |
| Reverse proxy | Unbuffered Nginx, Caddy and Traefik configurations |
| Monitoring | Prometheus scrape config, alert rules and a Grafana dashboard |

Everything is in [deploy/README.md](deploy/README.md). The image has no shell and no in-image health check; probe `/__live__` and `/__ready__` from your orchestrator. `Ctrl+C` or `SIGTERM` closes the listener at once and gives in-flight requests a short grace period.

## Command reference

### `blaze serve [PATH]`

| Option | Default | Meaning |
| :--- | :--- | :--- |
| `--host`, `-p/--port` | `0.0.0.0`, `8000` | Bind address (IPv4 or IPv6) and port |
| `--single FILE` | none | Serve exactly this file |
| `--no-listing` | listing on | Disable directory listing |
| `--index NAME` | `index.html`, `index.htm` | Extra index filenames, repeatable |
| `--precompress` / `--no-precompress` | on | Serve `.br` and `.gz` siblings when safe; never for range requests |
| `--no-cache` | off | Send no-store cache headers |
| `--cors` / `--no-cors`, `--cors-origin` | off, `*` | CORS and the allowed origin |
| `--auth USER:PASS`, `--auth-env VAR` | none | Basic Auth |
| `--tls-cert`, `--tls-key` | none | PEM certificate and key, required together |
| `--rate-mbps N` | unlimited | Per-client throttle in MB/s |
| `--max-upload-mb N` | `0` | Enable uploads with this size ceiling; `0` disables them |
| `--max-connections N` | `1024` | Admission limit |
| `--header-timeout S` | `10` | Seconds to receive complete headers |
| `--timeout S` | `1800` | Idle timeout in seconds |
| `--trust-proxy CIDR`, `--max-proxy-hops N` | none, `8` | Trusted proxies and chain depth |
| `--chunk-mb N`, `--sock-sndbuf-mb N`, `--backlog N` | `1`, `4`, `8192` | Transfer chunk, socket send buffer, listen backlog |
| `--log-json` / `--no-log-json` | env `BLAZE_LOG_JSON` | Structured logs |
| `--otlp-endpoint URL` | env `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry export |
| `--open`, `-v/--verbose` | off | Open a browser; show tuning in the banner |

### Other commands

| Command | Purpose |
| :--- | :--- |
| `blaze send FILE` | Share one file. Takes the network, access, limit, proxy and telemetry options of `serve`, with listing off |
| `blaze get URL` | Resumable download. `-o`, `--no-resume`, `--sha256`, `--retries`, `--force`, `--auth`, `--auth-env` |
| `blaze put FILE URL` | Resumable upload; a bare origin uploads under `/__upload__/`. `--chunk-mb` (8), `--retries`, `--auth`, `--auth-env` |
| `blaze checksum FILES...` | Streamed SHA-256 |
| `blaze doctor [PATH]` | Check the path, the port and capabilities; `--json`, exit code 1 on failure |
| `blaze benchmark` | Time a download from a temporary loopback server, or from `--url`; `--size-mb`, `--json`, `--runs`, `--warmup`, `--workload`, `--output`, `--seed`; `benchmark compare A B` |
| `blaze telemetry` | `status`, `enable`, `disable`, `reset`, `preview` |
| `blaze completions SHELL` | Print a completion script for `bash`, `zsh`, `fish`, `powershell` or `elvish` |
| `blaze version` | Version and platform; `--json` |

`blaze help [COMMAND]` and `blaze COMMAND --help` show options with examples. The global `--color auto|always|never` flag overrides detection; `NO_COLOR` and `CLICOLOR_FORCE` are honoured. Progress and status lines go to stderr and appear only on a terminal, so piped output stays clean.

Exit codes are 0 for success, 1 for a runtime failure and 2 for a usage error.

## Security model

BlazeServe assumes an attacker who controls request paths, query strings, headers, upload names and bodies, and connection behaviour, but has no shell. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

- **Paths.** Decoded once, resolved to a canonical path and checked component by component against the canonical root, for reads, uploads and ZIPs. `..`, encoded and double-encoded dots, sibling prefixes such as `/data` and `/data-evil`, symlinks, junctions and cross-drive Windows paths fail closed.
- **Uploads.** Off by default. Files are created exclusively, with mode `0600` on Unix, and published without replacing anything. The length and size ceiling are enforced, staging files are removed on any failure, and nothing is published before a sent digest matches. Early rejections close the connection so a body is never read as the next request.
- **Authentication.** Runs before any filesystem or operational route. Both fields compare in constant time, and malformed or missing credentials fail closed.
- **Connections.** Header and idle timeouts, a connection limit, and bounded transfer buffers of 1 MiB per active transfer by default.
- **Residual risks.** A path check followed by an open is not atomic on every platform, so someone who can already write inside the served root could race a symlink swap. Do not give untrusted users write access to a served root. A compromised trusted proxy can name any client, and a flood from many sources still occupies admitted slots.

## Performance

Speed depends on the operating system, filesystem, storage, network, TLS and any proxy, so measure your own setup. A single timed download:

```bash
blaze benchmark --json --size-mb 100
```

Without `--url` it starts a temporary loopback server on a free port and stops it afterwards; with `--url` it measures an existing server. A run that receives fewer bytes than requested is a failure, not a sample.

For repeatable numbers, any of `--runs`, `--warmup`, `--workload` or `--output` selects the harness:

```bash
blaze benchmark --runs 7 --warmup 2 --workload both --size-mb 512 --output run1.json
blaze benchmark compare run1.json run2.json
```

| Option | Meaning |
| :--- | :--- |
| `--runs N` | Recorded samples per workload |
| `--warmup N` | Discarded samples before the recorded ones (default 1) |
| `--workload` | `full` (whole file), `range` (partial requests) or `both` |
| `--output FILE` | Versioned JSON artifact with the command, server settings, fixture seed and every sample |
| `--seed N` | Seed for the deterministic fixture content |

`blaze benchmark compare A B` prints the median of each workload in both artifacts and the change. It applies no threshold or significance test, so judge the spread yourself.

### Reference measurements

One machine, loopback only, no TLS or proxy: AMD Ryzen 5 5625U, 15 GB RAM, Windows 11, release build of 1.0.0, 512 MiB fixture, 7 samples after 2 warm-ups, three runs.

| Run | `full` median | `range` median |
| :--- | ---: | ---: |
| 1 | 1033 MiB/s | 1334 MiB/s |
| 2 | 1333 MiB/s | 1309 MiB/s |
| 3 | 1317 MiB/s | 1360 MiB/s |

Within a run, the standard deviation is 8 to 15 percent of the median (90 to 200 MiB/s), and run 1 `full` sits about 22 percent below the other two. Treat differences of that size as within the noise of this machine.

The 0.x Python server, measured on the same machine with `blaze benchmark --json --size-mb 512`, five single runs without warm-up: 616, 633, 677, 749 and 759 MiB/s, median 677. The harnesses differ, so read the roughly twofold gap as indicative, not exact. Loopback says little about a real network, where the link usually limits throughput.

When you publish a number include the command, version, OS, CPU, storage and network path.

## Telemetry

BlazeServe sends anonymous usage statistics by default, so the project can see which versions and platforms are in use and which options matter. It is on unless you turn it off.

**Opt out** with any one of `BLAZE_TELEMETRY=0`, `DO_NOT_TRACK=1` or `blaze telemetry disable`. It is also off automatically when `CI` is set. Run `blaze telemetry preview` to print exactly what would be sent, without sending it.

| When | Fields |
| :--- | :--- |
| Every event | `schema_version`, `event` (`start` or `stop`), `version`, `os`, `arch`, `command` (`serve` or `send`), `install_channel` |
| Configuration | Yes or no only: `tls`, `auth`, `uploads_enabled`, `rate_limit`, `cors`, `trust_proxy`, `otlp`, `single_file`, `listing` |
| `stop` only | Bucketed uptime, bucketed request count, bucketed bytes sent, and whether any error occurred |

**Never collected:** paths, filenames, hostnames, IP addresses, ports, URLs, credentials, environment variable values or any request data. No install identifier is generated or sent. The first run prints a short notice to stderr before anything is sent. The relay that receives events is open source in [deploy/telemetry-relay](deploy/telemetry-relay), and release builds send events only if a relay URL was set at build time.

## Upgrading from 0.x

1.0 is a Rust rewrite. Options and the HTTP surface are unchanged except as listed here.

- **Python API removed.** `create_server`, `run_server`, `BlazeHandler`, `ServerMetrics`, `TokenBucket` and the legacy argparse parser are gone. Wheels carry the binary.
- **Uploads are off by default.** `--max-upload-mb 0` now disables them. In 0.x it allowed unlimited, unauthenticated uploads, which was a security defect. Set a positive limit and require authentication to keep uploading.
- **Defaults.** `--chunk-mb` is 1 MiB, down from 256 MiB allocated per connection, and `--sock-sndbuf-mb` is 4 MiB, down from 128 MiB.
- **Atomic uploads.** Files are staged, verified and then published. Replacing one needs a matching `If-Match`.
- **Path decoding.** Paths are decoded once, so `%252e%252e` is a literal name rather than traversal input.
- **Connections.** Bounded by `--max-connections`, with a header timeout. 0.x used one unbounded thread per connection and a 30 minute idle timeout.
- **Monitoring.** The alert `BlazeServeHighActiveConnections` is now `BlazeServeHighActiveRequests`, matching the metric it uses. Two series were added: `blazeserve_connections_active` and `blazeserve_connections_rejected_total`.
- **Container.** The image is `scratch`-based and non-root, with no in-image health check.

## Development

```bash
git clone https://github.com/whoisjayd/blazeserve
cd blazeserve
cargo test
cargo run -- serve .
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Found a bug? [Open an issue](https://github.com/whoisjayd/blazeserve/issues/new/choose). Security concern? See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
