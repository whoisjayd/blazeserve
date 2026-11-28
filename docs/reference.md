# Reference

Every command, option, address and setting in one place. For explanations, use the guides in [docs](README.md). Run `blaze help COMMAND` or `blaze COMMAND --help` to see the same options in your terminal.

## Commands

| Command | What it does |
| :--- | :--- |
| `blaze serve [PATH]` | Serve a folder or a file |
| `blaze send FILE` | Share one file, with the folder listing off. Accepts the network, access, limit, proxy and telemetry options of `serve`, plus `--expires-after DURATION` |
| `blaze get URL` | Download with resume |
| `blaze put FILE URL` | Upload with resume. A bare server address uploads under `/__upload__/` |
| `blaze status [JOB]` | Show background jobs. `--watch` refreshes, `--json` prints one snapshot, `--all` adds finished jobs |
| `blaze stop JOB` | Stop a background job after confirmation. `--yes` skips the question |
| `blaze checksum FILES...` | SHA-256 of one or more files |
| `blaze doctor [PATH]` | Check the folder, the port and system capabilities |
| `blaze benchmark` | Time a download. See [Performance](performance.md) |
| `blaze telemetry` | `status`, `enable`, `disable`, `reset` or `preview` |
| `blaze upgrade` | Check for a newer release and install it the way BlazeServe was installed |
| `blaze completions SHELL` | Print a shell completion script for `bash`, `zsh`, `fish`, `powershell` or `elvish` |
| `blaze version` | Version and platform. Add `--json` for scripts |

The global `--color auto|always|never` option controls colour. `NO_COLOR` and `CLICOLOR_FORCE` are respected. Progress bars and status lines go to standard error and only appear in a terminal, so piped output stays clean. While `serve` or `send` runs in a terminal, one status line under the startup banner shows active and total requests, bytes sent and the current speed. It is not drawn with `--verbose`, `--log-json` or OpenTelemetry export, which write their own lines.

## Exit codes

| Code | Meaning |
| :--- | :--- |
| 0 | Success |
| 1 | Something failed while running |
| 2 | The command was used incorrectly |
| 3 | Not enough free disk space, before or while writing (`get`) |
| 4 | Integrity failure: a SHA-256, size or archive check did not pass, or the server rejected an upload's checksum (`get`, `put`) |
| 5 | The server refused the credentials, HTTP 401 or 403 (`get`, `put`) |

Codes 3 to 5 let a script tell a full disk, corrupt data and a wrong password apart from a network problem, which stays at 1. The code follows the error that is printed.

## `blaze serve` options

| Option | Default | Meaning |
| :--- | :--- | :--- |
| `PATH` | `.` | Folder or file to serve |
| `--host`, `-p/--port` | `0.0.0.0`, `8000` | Address (IPv4 or IPv6) and port |
| `--single FILE` | none | Serve exactly this file |
| `--no-listing` | listing on | Turn off the folder listing |
| `--index NAME` | `index.html`, `index.htm` | Extra index file names; repeatable |
| `--hide GLOB` | none | Hide matching entries from listings and ZIPs, and answer `404` for them, including under `/__upload__/`; repeatable |
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
| `--background` | off | Run as a [background job](background-jobs.md) and print its job ID. Also for `send` |
| `--qr` | off | Print a QR code of the network address |
| `--open` | off | Open a browser |
| `-v`, `--verbose` | off | Show tuning details at startup |

## `blaze get` options

| Option | Default | Meaning |
| :--- | :--- | :--- |
| `-o`, `--output FILE` | server-suggested name, else last part of the URL | Where to save |
| `--resume`, `--no-resume` | resume | Continue a partial download, or start over |
| `--sha256 HEX` | none | Verify the finished file |
| `--verify server-sha256` | off | Ask the BlazeServe server for the file's SHA-256 (`?hash`) and verify against it; fails if unavailable or different. Cannot be combined with `--sha256` |
| `--retries N` | `5` | Failed attempts in a row before giving up |
| `--force` | off | Replace an existing file |
| `-c`, `--connections N` | `4` | Parallel connections, 1 to 128, or `max` for 128 |
| `--limit-rate RATE` | none | Total speed cap in bytes per second, with optional `K`, `M` or `G` |
| `--connect-timeout TIME` | `15s` | Give up if the connection is not made in time. `off` waits as long as the system allows |
| `--idle-timeout TIME` | `off` | Give up when no data moves for this long |
| `--max-time TIME` | `off` | Give up when the whole command, retries and waits included, takes longer than this |
| `--background` | off | Run as a [background job](background-jobs.md) and print its job ID |
| `--extract` | off | After the download, extract the archive in place (zip, 7z, tar, `.tar.gz`, `.tar.bz2`, `.tar.xz`) |
| `--keep-archive` | off | With `--extract`, keep the archive instead of consuming it as files come out |
| `--no-verify-first` | off | With `--extract`, skip the check of the whole archive that runs before it is consumed |
| `--keep-free SIZE` | `1G` | With `--extract`, free space to leave untouched, with optional `K`, `M` or `G` |
| `--auth USER:PASS`, `--auth-env VAR` | none | Password for the server |

`get` and `put` honour `Retry-After` on `429` and `503` (seconds or HTTP date), up to 5 minutes. See [Passwords and retries](sharing-files.md#passwords-and-retries).

When the server reports the file's size (`Content-Length` or `Content-Range`), `get` checks free disk space before creating `.part` and exits with code `3` if the remaining bytes to fetch do not fit. Plain downloads reserve no extra margin (`--keep-free` applies only with `--extract`).

## `blaze put` options

| Option | Default | Meaning |
| :--- | :--- | :--- |
| `--chunk-mb N` | `8` | Size of each request |
| `--retries N` | `5` | Failed attempts in a row before giving up |
| `--connect-timeout TIME` | `15s` | Give up if the connection is not made in time. `off` waits as long as the system allows |
| `--idle-timeout TIME` | `off` | Give up when no data moves for this long |
| `--max-time TIME` | `off` | Give up when the whole command, retries and waits included, takes longer than this |
| `--if-match ETAG` | none | Replace an existing file only if its current quoted `ETag` equals this value. `*` and weak tags are refused |
| `--limit-rate RATE` | none | Cap on upload speed in bytes per second, with optional `K`, `M` or `G` (minimum `1K`), as for `get` |
| `--background` | off | Run as a [background job](background-jobs.md) and print its job ID |
| `--auth USER:PASS`, `--auth-env VAR` | none | Password for the server |

`--limit-rate` limits the speed of the request body, for example `blaze put backup.tar http://host:8000 --limit-rate 2M`. Bytes sent again after a retry count against the limit. Bytes the server already holds from an earlier attempt are not sent and do not. It is not an exact cap on TLS and TCP overhead.

Without `--if-match`, an existing file is never replaced. With it, every request carries the tag. A stale tag or a missing file exits with an error (HTTP `412`) and leaves the file alone. The client never fetches a newer tag and tries again.

## `blaze upgrade` options

| Option | Meaning |
| :--- | :--- |
| `--check` | Show the installed and the latest version and change nothing. Exits 0 whether or not a newer release exists |
| `--json` | With `--check`, print JSON: `current`, `latest`, `update_available`, `channel`, `status` |
| `--version X.Y.Z` | Install this exact version instead of the latest. Needed to go back to an older version or to pick a pre-release |
| `-y`, `--yes` | Do not ask first. Without a terminal, an upgrade refuses to run unless you pass this |

Pre-releases are never chosen by default, and an older release is never installed unless you name it with `--version`. The command contacts the network only when you run it, and sends no usage report. What it does depends on how BlazeServe was installed:

| Install | What `blaze upgrade` does |
| :--- | :--- |
| Downloaded binary | Downloads the archive for this system, checks its SHA-256 against the release `SHA256SUMS`, and replaces itself. The old program is restored if anything fails |
| pip | Runs `python -m pip install --upgrade blazeserve` with the Python that started `blaze` |
| Cargo | Runs `cargo install blazeserve --locked --force` |
| Container | Prints the `docker pull` command and changes nothing |
| Homebrew, Scoop, winget, Nix, pipx, uv or a system package | Prints the command for that tool and changes nothing |

Both `pip` and `cargo` ask first. The install is read from `BLAZE_INSTALL_CHANNEL`, then from the Python that launched `blaze`, then from where the program lives. The command exits 0 when it only prints instructions.

## Other options

| Command | Options |
| :--- | :--- |
| `blaze doctor` | `--host` (default 127.0.0.1), `-p/--port` (default 8000), `--json` |
| `blaze benchmark` | `--url`, `--size-mb`, `--json`, `--runs`, `--warmup`, `--workload`, `--output`, `--seed`; `benchmark compare A B` |

`doctor --host` takes the same values as `serve --host` and binds the address `serve` would pick, then releases it at once. Text and JSON name the address that was tested. If a name resolves to several addresses, only the one `serve` would choose is checked. The result is a point-in-time check, not a reservation, and says nothing about firewalls or remote reachability. The JSON report has an additive `host` field with the value you passed.

```console
blaze doctor ./shared --host ::1 --port 8000 --json
blaze serve ./shared --host ::1 --port 8000
```

## Endpoints

| Address | Methods | Notes |
| :--- | :--- | :--- |
| `/<path>` | GET, HEAD | Files and folder listings. Send `Accept: application/json` for a JSON listing. `?download=1` makes browsers save the file |
| `/<path>?hash` | GET, HEAD | SHA-256 of a file as JSON (`path`, `size`, `sha256`) plus a `Repr-Digest` header. Folders answer `400`. Results are cached per path, size and modification time, and at most four files are hashed at once |
| `/__upload__/<path>` | PUT, POST, GET, HEAD, DELETE | Only when uploads are on. GET and HEAD report `Upload-Offset` for a partial upload. A finished file answers with `Upload-Complete: ?1` and its size in `Upload-Offset`, and an unknown name answers `404`; the folder page uses this to check an upload after a dropped connection. DELETE discards a partial upload, never a finished file. See [Uploads](uploads.md#upload-from-the-browser) for the page's cancel and retry controls |
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
| 429 | An HTTP/2 connection opened requests too fast; `Retry-After` is set. The response carries the usual security headers and `X-Request-ID`, and counts as a request |
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
| `BLAZE_STATE_DIR` | Where background job records live: `<folder>/jobs`. Defaults to the per-user state folder. See [Background jobs](background-jobs.md) |
| `BLAZE_TELEMETRY_URL` | Where usage reports are sent. Set when building a release; a build without it sends nothing |
| `BLAZE_UPGRADE_API`, `BLAZE_UPGRADE_DOWNLOADS` | Where `blaze upgrade` looks for releases. They exist for mirrors and tests. `https://` is required, except for a loopback address |
| `BLAZE_INSTALL_CHANNEL` | `pip`, `cargo`, `docker` or `binary`. Tells `blaze upgrade` how this copy was installed, and is set by the container image |
| `BLAZE_PYTHON` | The Python that started `blaze`. The Python package sets it, so `blaze upgrade` runs that Python's pip |
