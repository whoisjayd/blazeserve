# AGENTS.md

A handbook for contributors and coding agents working on BlazeServe, a Rust HTTP/1.1 and HTTP/2 file server and command-line tool for large static transfers.

## Scope and precedence

- This file covers the whole repository. A more specific `AGENTS.md` overrides it for files below its own directory.
- System, maintainer and direct task instructions come first. Follow the higher-precedence source, and report the conflict in your handoff.
- Executable configuration (`Cargo.toml`, `Cargo.lock`, `pyproject.toml`, `Makefile`, workflows, tests) wins over prose when they disagree. Do not guess which is right.
- Keep the diff to the behaviour you were asked to change. Do not mix a fix with unrelated cleanup, formatting, dependency upgrades, version bumps or deployment changes.
- Preserve the public CLI, the documented HTTP surface, metric names and types, and JSON log fields unless the task deliberately changes a contract. These are documented in `docs/reference.md` and `docs/monitoring.md`.
- Reuse existing modules, helpers and errors. Do not add a parallel abstraction.

## Product boundaries

- `blaze benchmark` without `--url` starts a temporary loopback server and cleans it up. With `--url` it measures an existing server and must not start another.
- BlazeServe opens its own socket. systemd socket activation is not supported.
- Changing a TLS certificate needs a restart. There is no reload inside the process.
- The default Kubernetes deployment is private and has one replica, backed by a pod-local `emptyDir`. Ingress and ServiceMonitor are optional and are not part of the Kustomize base.
- Compose and Kubernetes mount served data read-only. Uploads are off by default, and need authentication and storage that is deliberately writable.
- Performance depends on the operating system, filesystem, storage, network, TLS and proxy. Publish a figure only together with its command, workload, machine and comparison method.

## Repository map

| Path | Owns |
| :--- | :--- |
| `src/lib.rs` | The module list, `VERSION`, `AppState`, `PeerInfo` and `Body` |
| `src/config.rs` | Typed settings and their validation, the single source of truth for every entry point |
| `src/cli/`, `src/main.rs` | Commands, help text, progress output and input checks. `cli::main_from` runs the CLI for embedders. `cli/transfer/` holds resumable `get` (one stream in `download`, parallel segments in `segmented`) and `put`. `cli/bench/` holds the benchmark harness |
| `src/server/` | `bind` and `tls` set up the listener, `accept` applies admission control, `connection` and `idle` serve one connection, `prefixed` sniffs the HTTP/2 preface, `budget` limits how fast one HTTP/2 connection opens streams, `proxy` works out the trusted client identity, and `mod.rs` owns start and shutdown |
| `src/handler/`, `src/range.rs`, `src/cache.rs` | HTTP behaviour: ranges, validators, status routes, CORS, authentication, headers. `handler/mod.rs` routes; `auth`, `ops`, `resolve`, `files`, `pump`, `response` and `scope` each own one concern |
| `src/upload/`, `src/zip_stream/` | Uploads (`request`, `target`, `stream`, `publish`, `plain`, `resumable`) and streaming ZIPs (`writer`, `crc32`, `archive`) |
| `src/security.rs` | Canonical path containment, race-resistant file creation, request IDs |
| `src/limiter.rs`, `src/metrics.rs`, `src/logging.rs`, `src/ui.rs` | Throttling, counters, logs, the directory listing page |
| `src/telemetry/`, `src/usage/` | OpenTelemetry export (`settings`, `transport`, `exporter`) and the anonymous usage report (`payload`, `gate`, `settings`, `session`) |
| `src/python.rs`, `python/blazeserve/`, `tests_py/` | PyO3 bindings (feature `python`), the thin Python package with its type stubs, and the pytest suite run against the built wheel |
| `pyproject.toml` | maturin metadata for the abi3 wheels and the `blaze` console script |
| `tests/` | Integration tests against a live server. Unit tests sit in `#[cfg(test)]` modules |
| `docs/` | The user guides, and `assets/` with the logo, social preview, README demo animation and the VHS tapes that record it. `README.md` is the front page and links to them |
| `.github/workflows/` | `ci.yml` and `release.yml`, the authoritative gates |
| `Dockerfile`, `docker-compose.yml` | The `scratch` image, running as uid and gid 10001 |
| `deploy/` | Kubernetes, systemd, proxy, monitoring, Linux tuning and the telemetry relay. Start at `deploy/README.md` |

Dependencies point downward and never form cycles:

```text
cli -> config, server, logging, usage
server -> handler, limiter, metrics, config, telemetry
handler -> security, upload, zip_stream, ui, range, cache, limiter, metrics, config, telemetry
upload, zip_stream -> security, metrics, config
config, security, limiter, metrics, logging, ui, range, cache, usage -> leaves
```

- CLI concerns stay in `cli`. Startup, sockets, TLS, admission and shutdown stay in `server`. Protocol behaviour stays in `handler`.
- Filesystem trust checks live in `security.rs` and cover reads, uploads and ZIPs.
- Counters go through `Metrics`. Throttling goes through `TokenBucket` and `IpLimiterPool`. Both are shared across tasks.
- Rendering stays in `ui.rs`. Lower layers never import `cli`.

## Behaviour that must not change

HTTP and transfers:

- HTTP/1.1 and HTTP/2, with an accurate `Content-Length` on persistent responses. `HEAD` returns the same status and representation headers as GET, with no body, including on status routes.
- Keep `/__health__`, `/__live__`, `/__ready__`, `/__version__`, `/__metrics__`, `/metrics`, `/__stats__`, `/__perf__`, `/__speed__` and `/__zip__`. Writes exist only below `/__upload__/`.
- `If-None-Match` uses weak comparison and is checked before `If-Modified-Since`. A match returns `304` with the validators and cache policy.
- One range returns `206` with the right `Content-Range`. Several ranges return `multipart/byteranges` with an exact length. A valid but unsatisfiable range returns `416` with `Content-Range: bytes */<size>`. Malformed range syntax is ignored.
- An `If-Range` mismatch returns the full representation. A precompressed sibling (`.br`, `.gz`) is never chosen for a range request. `Vary` stays correct for encoding and CORS.
- Status JSON and metrics are `no-store`. ZIP responses close the connection because their length is unknown.

Authentication, TLS and filesystem safety:

- Authenticate GET, HEAD, PUT, POST and DELETE before any filesystem or status-route dispatch. Compare both Basic Auth fields in constant time. Malformed or missing credentials fail closed.
- A named auth environment variable that is missing or empty is an error, never permission to start without authentication.
- The TLS certificate and key belong together. Reject an incomplete pair before binding, require TLS 1.2 or newer, and close the listener if TLS setup fails.
- Every read, upload and ZIP candidate must stay under the canonical root, checked component by component. `..`, sibling prefixes, symlinked parents, junctions and cross-drive Windows paths fail closed. Percent-decode a path exactly once.
- Uploads never overwrite. They are created exclusively (mode `0600` on Unix), staged beside the destination, verified, and published without replacing anything. Replacement needs a matching `If-Match`. Staging files are removed on any failure, and an early rejection closes the connection so an unread body is never parsed as the next request.
- Escape displayed file names and percent-encode path components in listings. Never put raw names into HTML, URLs or scripts.
- Keep `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy` and `Permissions-Policy`. Send HSTS only on a TLS connection.
- Accept `X-Request-ID` only when it is 1 to 64 characters and alphanumeric once hyphens are removed. Otherwise generate 12 hex characters. Always echo the result.
- Trust forwarded client identity only from a configured proxy. Ignore these headers from any other peer.

Concurrency and lifecycle:

- State is per server (`AppState`). Never move request configuration into process-wide mutable state.
- Metrics, token buckets and the per-IP pool are shared across tasks. Keep locks short, never hold one across `.await` or I/O, and keep the LRU bounded.
- The active-request gauge falls exactly once on every exit, including a dropped response body, and never below zero. Uptime uses a monotonic clock.
- Contain expected disconnects only at network write and cleanup boundaries. Unexpected errors stay visible and increase the error counter.
- Transfers read in bounded chunks. Never hold a whole file or upload in memory, and release file handles before a transfer ends so Windows can reopen, rename or delete the file.
- `Ctrl+C` works on every platform and `SIGTERM` on Unix. Shutdown closes the listener at once, gives in-flight work a bounded grace period, and flushes telemetry for at most five seconds.
- Address resolution prefers IPv4 on dual-family hosts, supports IPv6-only hosts, and falls back to IPv4 when lookup fails.

## How to work

1. Read the module that owns the behaviour, its callers and the nearest tests.
2. Reproduce a defect with the narrowest command and record the failure.
3. Add a regression test that fails for the intended reason. Do not test source text, field forwarding or mock echoes.
4. Make the smallest fix that addresses the root cause, and update every affected caller.
5. Run the focused test, then the neighbouring tests, then the gates below.
6. Remove temporary scripts, captures, servers and generated files.

Tests:

- Live tests start the server through the shared helper on loopback port `0` and shut it down in every outcome. Never use fixed ports or sleeps. Assert what a client sees: status, headers, bytes, cleanup and state.
- Skip a test only for a capability that is genuinely absent, and give a reason. Never skip an operating system to hide a bug.
- Focused runs: `cargo test --lib`, `cargo test --test <name>`, `cargo test <test_name> -- --nocapture`.

## Quality gates

Run these on your platform before handing off:

```console
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

CI also enforces 80 percent line coverage with `cargo llvm-cov`, runs `cargo deny check`, smoke-tests the wheel on all three operating systems, and builds the container and probes `/__live__`, `/__ready__` and `/__metrics__`. A packaging, metadata or release change also needs `uvx maturin build --release --out dist` and `pipx run twine check dist/*`.

## Conventions

- Windows, Linux and macOS are all first-class. Use `std::path`, never split paths by hand, and never assume separators, drive letters, case sensitivity, symlink support or POSIX permissions. Guard Unix-only code with `cfg`, tolerate unsupported socket options, and keep `TCP_QUICKACK` Linux-only.
- The crate has no system-library dependencies and TLS uses rustls. A new dependency must build on all three platforms without system libraries. Prefer the standard library or an existing dependency.
- Commit `Cargo.toml` and `Cargo.lock` together and never edit the lock by hand. Run `cargo deny check` after dependency changes, and review action, Docker base and pre-commit pins as separate supply-chain changes.
- Do not replace a transfer path without measurements on the affected platforms.
- Keep proxy buffering off for streaming: Nginx request and response buffering off, Caddy `flush_interval -1`.
- In JSON mode, stdout carries only JSON records and human output goes to stderr. Keep the fields `timestamp` (UTC), `level`, `request_id`, `client_ip`, `peer_ip`, `request`, `status` and `size`.
- Never log `Authorization`, URLs with credentials, TLS keys, auth environment values, telemetry headers or content.
- Count only bytes actually sent or accepted, and count parsed requests, not connections. Metric names and types are public contracts. Changing one needs a review of monitoring and documentation.
- Use deliberate HTTP statuses or CLI errors for user and configuration failures. Fail closed for authentication, TLS, paths and uploads. No `unwrap` or `expect` on a path driven by requests.
- Comment only to explain a reason that is not obvious from the code.

## Documentation to update with a change

Write documentation for people, in plain language. Keep it accurate and keep the examples runnable.

| Change | Update |
| :--- | :--- |
| CLI command, option, default or output | `docs/reference.md` and the relevant guide in `docs/`, `README.md` if it shows the command, the tests, and `CONTRIBUTING.md` if contributor commands change |
| HTTP endpoint, method, status, header, cache, auth, upload or range behaviour | The endpoint tables in `docs/reference.md`, the relevant guide, and the integration tests |
| Startup, shutdown, TLS, bind or health | `deploy/README.md`, `deploy/systemd/`, `Dockerfile`, Compose and the Kubernetes probes |
| Container identity, port, path or writable state | `Dockerfile`, Compose, `deploy/README.md`, `deploy/k8s/` |
| Proxy transport or identity | Every affected file in `deploy/reverse-proxy/`, `deploy/README.md` and `docs/serving-files.md` |
| Metric name, type or meaning | The metric table in `docs/monitoring.md`, the `deploy/monitoring/` config, alerts and dashboard |
| Usage telemetry field | `docs/telemetry.md`, the telemetry summary in `README.md`, `src/usage/payload.rs`, `tests/usage_payload.rs` and `deploy/telemetry-relay/` |
| Gate commands | `Makefile`, pre-commit, `CONTRIBUTING.md`, this file and the workflows |

## Commits

- Keep your changes separate from changes the user already had. Never discard or rewrite unrelated work.
- Stage explicit paths and never use `git add .`. Review before committing:

```console
git status --short
git diff -- <path> [<path> ...]
git diff --check
git add <path> [<path> ...]
git diff --cached --check
git diff --cached --stat
```

- Every commit message is a single line in Conventional Commits form, `type(scope): summary`. The scope is optional. The types are `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci` and `chore`. Use the imperative mood, lowercase, no trailing period, and at most 72 characters. Example: `git commit -m "fix(range): preserve content length on 206"`.
- No body, no footer and no trailers. Do not add `Co-Authored-By` or any other attribution line to commits. Put context and issue links in the pull request.
- Commits are atomic: one coherent change with the tests and docs that belong to it, which builds and passes on its own. Keep a fix separate from unrelated cleanup, formatting, renames and dependency changes.
- Leave out distributions, caches and generated files.
- Do not amend, rebase, force-push, tag, publish or push unless explicitly authorised. History already on `main` is never rewritten.

## Versions and releases

Keep every hard-coded release version in sync: `version` in `Cargo.toml` and `pyproject.toml`, the BlazeServe entry in the regenerated `Cargo.lock`, the image tag in `deploy/k8s/deployment.yaml`, and any test that checks the version.

Do not bump versions, create or reuse tags, push, publish or start release workflows unless explicitly authorised.

The release workflow needs its manual version or `v*` tag to equal `Cargo.toml` and `pyproject.toml`, needs the commit to be on `main`, and rejects a manual tag that already exists. Gates, binaries, wheels and the container come before publication, and the GitHub release is created only after both PyPI and GHCR succeed. PyPI versions are immutable. `PYPI_API_TOKEN` is a repository or `pypi` environment secret, `BLAZE_TELEMETRY_URL` is a repository variable, and GHCR uses `GITHUB_TOKEN`.

## Secrets and generated files

- Never commit tokens, passwords, auth pairs, private keys, certificates, real user paths or production data. Redact them from logs, fixtures, examples, screenshots, issues and reviews.
- Respect `.gitignore`: `.env`, `data/`, `certificates/`, `*.pem`, `*.key`, `*.crt`, `*.log`, `*.pid` and agent or session files stay local.
- `Cargo.lock` is tracked. `target/`, `dist/`, wheels, archives and coverage output are never source.

## Ownership

- The maintainer who submits a change owns it: they understand it, have tested it, and answer review.
- Commits and pull requests carry no tool attribution, disclosure statement or `Co-Authored-By` line. Describe the change, the compatibility impact and the linked issues.
- Pull requests that are generated and opened autonomously by someone outside the maintainer team are not accepted.

## Handoff

Report the following, without claiming more certainty than you have:

- The requested behaviour is complete and no unrelated file changed.
- Affected callers, tests, docs, deployment files and version locations were updated, or judged unchanged.
- The focused test and the relevant gates passed, with the exact commands and results.
- Cross-platform path, shell, signal and socket behaviour was considered, and any platform or deployment surface you could not verify is named.
- HTTP, authentication, traversal, cleanup, lifecycle, telemetry, logging and allocation rules still hold.
- No temporary process, script, cache, report, distribution, secret or local data remains.
- The paths you changed.
