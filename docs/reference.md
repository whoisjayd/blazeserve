# Reference

Every command, option, address and setting in one place. For explanations, use the guides in [docs](README.md). Run `blaze help COMMAND` or `blaze COMMAND --help` to see the same options in your terminal.

## Commands

| Command | What it does |
| :--- | :--- |
| `blaze serve [PATH]` | Serve a folder or a file |
| `blaze send FILE` | Share one file, with the folder listing off. Accepts the network, access, limit, proxy and telemetry options of `serve` |
| `blaze get URL` | Download with resume |
| `blaze put FILE URL` | Upload with resume. A bare server address uploads under `/__upload__/` |
| `blaze checksum FILES...` | SHA-256 of one or more files |
| `blaze doctor [PATH]` | Check the folder, the port and system capabilities |
| `blaze benchmark` | Time a download. See [Performance](performance.md) |
| `blaze telemetry` | `status`, `enable`, `disable`, `reset` or `preview` |
| `blaze completions SHELL` | Print a shell completion script for `bash`, `zsh`, `fish`, `powershell` or `elvish` |
| `blaze version` | Version and platform. Add `--json` for scripts |

The global `--color auto|always|never` option controls colour. `NO_COLOR` and `CLICOLOR_FORCE` are respected. Progress bars and status lines go to standard error and only appear in a terminal, so piped output stays clean.

## Exit codes

| Code | Meaning |
| :--- | :--- |
| 0 | Success |
| 1 | Something failed while running |
| 2 | The command was used incorrectly |

## `blaze serve` options

| Option | Default | Meaning |
| :--- | :--- | :--- |
| `PATH` | `.` | Folder or file to serve |
| `--host`, `-p/--port` | `0.0.0.0`, `8000` | Address (IPv4 or IPv6) and port |
| `--single FILE` | none | Serve exactly this file |
| `--no-listing` | listing on | Turn off the folder listing |
| `--index NAME` | `index.html`, `index.htm` | Extra index file names; repeatable |
| `--hide GLOB` | none | Hide matching entries from listings and ZIPs, and answer `404` for them; repeatable |
| `--precompress`, `--no-precompress` | on | Send `.br` and `.gz` copies when safe; never for range requests |
| `--no-cache` | off | Tell browsers not to cache |
| `--cors`, `--no-cors`, `--cors-origin` | off, `*` | Allow other websites, and which |
| `--auth USER:PASS`, `--auth-env VAR` | none | Require a password |
| `--tls-cert`, `--tls-key` | none | PEM certificate and key; give both |
| `--no-http2` | HTTP/2 on | Serve HTTP/1.1 only |
| `--rate-mbps N` | unlimited | Speed limit per client, in MB/s |
| `--max-upload-mb N` | `0` | Turn on uploads with this size limit; `0` means off |
| `--max-connections N` | `1024` | Most connections admitted at once |
| `--header-timeout S` | `10` | Seconds a client has to send its request |
| `--timeout S` | `1800` | Idle connection timeout in seconds |
| `--trust-proxy CIDR` | none | Believe forwarded addresses from this proxy; repeatable |
| `--max-proxy-hops N` | `8` | How far down a forwarded chain to look |
| `--chunk-mb N` | `1` | Transfer chunk size |
| `--sock-sndbuf-mb N` | `4` | Socket send buffer |
| `--backlog N` | `8192` | Waiting-connection queue size |
| `--log-json`, `--no-log-json` | from `BLAZE_LOG_JSON` | JSON log lines |
| `--otlp-endpoint URL` | from `OTEL_EXPORTER_OTLP_ENDPOINT` | Send traces and metrics here |
| `--qr` | off | Print a QR code of the network address |
| `--open` | off | Open a browser |
| `-v`, `--verbose` | off | Show tuning details at startup |

## `blaze get` options

| Option | Default | Meaning |
| :--- | :--- | :--- |
| `-o`, `--output FILE` | last part of the URL | Where to save |
| `--resume`, `--no-resume` | resume | Continue a partial download, or start over |
| `--sha256 HEX` | none | Verify the finished file |
| `--retries N` | `5` | Failed attempts in a row before giving up |
| `--force` | off | Replace an existing file |
| `-c`, `--connections N` | `4` | Parallel connections, 1 to 16 |
| `--limit-rate RATE` | none | Total speed cap in bytes per second, with optional `K`, `M` or `G` |
| `--auth USER:PASS`, `--auth-env VAR` | none | Password for the server |

## `blaze put` options

| Option | Default | Meaning |
| :--- | :--- | :--- |
| `--chunk-mb N` | `8` | Size of each request |
| `--retries N` | `5` | Failed attempts in a row before giving up |
| `--auth USER:PASS`, `--auth-env VAR` | none | Password for the server |

## Other options

| Command | Options |
| :--- | :--- |
| `blaze doctor` | `-p/--port` (default 8000), `--json` |
| `blaze benchmark` | `--url`, `--size-mb`, `--json`, `--runs`, `--warmup`, `--workload`, `--output`, `--seed`; `benchmark compare A B` |

## Endpoints

| Address | Methods | Notes |
| :--- | :--- | :--- |
| `/<path>` | GET, HEAD | Files and folder listings. Send `Accept: application/json` for a JSON listing. `?download=1` makes browsers save the file |
| `/<path>?hash` | GET, HEAD | SHA-256 of a file as JSON (`path`, `size`, `sha256`) plus a `Repr-Digest` header. Folders answer `400`. Results are cached per path, size and modification time, and at most four files are hashed at once |
| `/__upload__/<path>` | PUT, POST, GET, HEAD, DELETE | Only when uploads are on. GET and HEAD report `Upload-Offset` for a partial upload. DELETE discards a partial upload, never a finished file |
| `/__zip__?path=<path>` | GET, HEAD | A ZIP made on the fly. The connection closes afterwards |
| `/__health__` | GET, HEAD | Status, version, uptime |
| `/__live__` | GET, HEAD | Is the process alive? |
| `/__ready__` | GET, HEAD | Ready to serve; checks the served folder |
| `/__version__` | GET, HEAD | Name, version, platform |
| `/__metrics__`, `/metrics` | GET, HEAD | Prometheus metrics |
| `/__stats__` | GET, HEAD | Bytes sent |
| `/__perf__` | GET, HEAD | Effective limits and counters |
| `/__speed__?bytes=N` | GET, HEAD | N zero bytes, at most 1000 MiB. Used by `blaze benchmark` |

`HEAD` returns the same status and headers as `GET`, without a body.

### Status codes you may see

| Code | When |
| :--- | :--- |
| 200, 206 | A whole file, or one range of it. Several ranges produce a `multipart/byteranges` reply |
| 304 | The browser's copy is still current. `If-None-Match` is checked before `If-Modified-Since` |
| 400 | A malformed request, or `?hash` on a folder |
| 401 | A password is needed |
| 404 | Not found, hidden, or outside the served folder |
| 409, 412, 413 | Upload conflicts: the file exists, the `If-Match` tag is stale, or the upload is too large |
| 416 | A valid range that does not exist in the file. `Content-Range: bytes */<size>` says how big it is |
| 429 | An HTTP/2 connection opened requests too fast; `Retry-After` is set |
| 503 | The server is at `--max-connections`; `Retry-After: 1` is set |

A range request with an `If-Range` that no longer matches gets the whole file. Syntax errors in a `Range` header are ignored.

### Headers on every response

`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` and `X-Request-ID`, plus `Strict-Transport-Security` over HTTPS. Status pages and metrics are marked `Cache-Control: no-store`.

## Environment variables

| Variable | Used for |
| :--- | :--- |
| `BLAZE_AUTH` (any name you choose) | The `USER:PASS` that `--auth-env` reads |
| `BLAZE_LOG_JSON` | `1` turns on JSON logs |
| `BLAZE_TELEMETRY` | `0` turns off the usage report |
| `DO_NOT_TRACK` | `1` turns off the usage report |
| `CI` | When set, the usage report is off |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME` | OpenTelemetry export. See [Monitoring](monitoring.md) |
| `NO_COLOR`, `CLICOLOR_FORCE` | Colour control |
| `BLAZE_TELEMETRY_URL` | Where usage reports are sent. Set when building a release; a build without it sends nothing |
