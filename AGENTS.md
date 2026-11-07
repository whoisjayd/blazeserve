# AGENTS.md

Handbook for contributors and coding agents working on BlazeServe, a Rust HTTP/1.1 file server and CLI for large static transfers.

## Scope and precedence

- This file covers the whole repository. A more specific `AGENTS.md` overrides it for files below its directory.
- System, maintainer and direct task instructions come first. Follow the higher-precedence source and report any conflict in the handoff.
- Executable configuration (`Cargo.toml`, `Cargo.lock`, `pyproject.toml`, `Makefile`, workflows, tests) beats prose when they disagree. Do not guess.
- Keep the diff to the requested behavior. Do not mix a fix with unrelated cleanup, formatting, dependency upgrades, version bumps or deployment changes.
- Preserve the public CLI, the documented HTTP surface, metric names and types, and JSON log fields unless the task changes a contract. The README documents them.
- Reuse existing modules, helpers and errors. Do not add a parallel abstraction.

## Product boundaries

- `blaze benchmark` without `--url` starts and cleans up a temporary loopback server. With `--url` it measures an existing origin and must not start another server.
- BlazeServe binds its own socket. systemd socket activation is not supported.
- TLS certificate rotation needs a restart. There is no in-process reload.
- The default Kubernetes deployment is private and single-replica, backed by pod-local `emptyDir`. Ingress and ServiceMonitor are optional and excluded from Kustomize.
- Compose and Kubernetes mount served data read-only. Uploads are off by default and need authentication and deliberately writable storage.
- Performance depends on OS, filesystem, storage, network, TLS and proxy. Publish a figure only with its command, workload, machine and comparison method.

## Repository map

| Path | Owns |
| :--- | :--- |
| `src/lib.rs` | Module list, `VERSION`, `AppState`, `PeerInfo`, `Body` |
| `src/config.rs` | Typed configuration and validation, the single source of truth for every entry point |
| `src/cli/`, `src/main.rs` | Commands, help, progress output and input validation; `cli::main_from` runs the CLI for embedders |
| `src/server.rs` | Bind, socket options, TLS, admission control, proxy identity, shutdown |
| `src/handler.rs`, `src/range.rs`, `src/cache.rs` | HTTP semantics, ranges, validators, operational routes, CORS, auth, headers |
| `src/upload.rs`, `src/zip_stream.rs` | Uploads and streaming ZIPs |
| `src/security.rs` | Canonical containment, race-resistant file creation, request IDs |
| `src/limiter.rs`, `src/metrics.rs`, `src/logging.rs`, `src/ui.rs` | Throttling, counters, logs, directory listing |
| `src/telemetry.rs`, `src/usage.rs` | OpenTelemetry export, anonymous usage report |
| `tests/` | Live-server integration tests; unit tests sit in `#[cfg(test)]` modules |
| `.github/workflows/` | `ci.yml` and `release.yml`, the authoritative gates |
| `Dockerfile`, `docker-compose.yml` | `scratch` image running as uid and gid 10001 |
| `deploy/` | Kubernetes, systemd, proxy, monitoring, Linux tuning, the telemetry relay; start at `deploy/README.md` |
| `src/python.rs`, `python/blazeserve/`, `tests_py/` | PyO3 bindings (feature `python`), the thin Python package with stubs, and the pytest suite run against the built wheel |
| `pyproject.toml` | maturin metadata for the abi3 wheels and the `blaze` console script |

Dependencies point downward and never form cycles:

```text
cli -> config, server, logging, usage
server -> handler, limiter, metrics, config, telemetry
handler -> security, upload, zip_stream, ui, range, cache, limiter, metrics, config, telemetry
upload, zip_stream -> security, metrics, config
config, security, limiter, metrics, logging, ui, range, cache, usage -> leaves
```

- CLI concerns stay in `cli`. Startup, sockets, TLS, admission and shutdown stay in `server.rs`. Protocol semantics stay in `handler.rs`.
- Filesystem trust checks live in `security.rs` and cover reads, uploads and ZIPs.
- Counters go through `Metrics`. Throttling goes through `TokenBucket` and `IpLimiterPool`. Both are shared across tasks.
- Rendering stays in `ui.rs`. Lower layers never import `cli`.

## Behavior invariants

HTTP and transfers:

- HTTP/1.1 with an accurate `Content-Length` on persistent responses. `HEAD` returns the GET status and representation headers without a body, including operational routes.
- Keep `/__health__`, `/__live__`, `/__ready__`, `/__version__`, `/__metrics__`, `/metrics`, `/__stats__`, `/__perf__`, `/__speed__` and `/__zip__`. Writes exist only below `/__upload__/`.
- `If-None-Match` uses weak comparison and is evaluated before `If-Modified-Since`. A match returns `304` with the validators and cache policy.
- One range returns `206` with the right `Content-Range`. Several ranges return `multipart/byteranges` with an exact length. A valid but unsatisfiable range returns `416` with `Content-Range: bytes */<size>`. Malformed range syntax is ignored.
- An `If-Range` mismatch returns the full representation. A precompressed sibling (`.br`, `.gz`) is never chosen for a range request. `Vary` stays correct for encoding and CORS.
- Operational JSON and metrics are `no-store`. ZIP responses close the connection because their length is unknown.

Authentication, TLS and filesystem safety:

- Authenticate GET, HEAD, PUT, POST and DELETE before any filesystem or operational dispatch. Compare both Basic Auth fields in constant time. Malformed or missing credentials fail closed.
- A named auth environment variable that is missing or empty is an error, never permission to start unauthenticated.
- The TLS certificate and key are inseparable. Reject an incomplete pair before binding, require TLS 1.2 or newer, and close the listener if TLS setup fails.
- Every read, upload and ZIP candidate must stay under the canonical root, checked component by component. `..`, sibling prefixes, symlinked parents, junctions and cross-drive Windows paths fail closed. Percent-decode a path exactly once.
- Uploads never overwrite. They are created exclusively (mode `0600` on Unix), staged beside the destination, verified, and published without replacing anything. Replacement needs a matching `If-Match`. Staging files are removed on any failure, and an early rejection closes the connection so an unread body is never parsed as the next request.
- Escape displayed filenames and percent-encode path components in listings. Never interpolate raw names into HTML, URLs or scripts.
- Keep `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy` and `Permissions-Policy`. Send HSTS only on a TLS connection.
- Accept `X-Request-ID` only when it is 1 to 64 characters and alphanumeric once hyphens are removed. Otherwise generate 12 hex characters. Always echo the result.
- Forwarded client identity is trusted only from a configured proxy. Any other peer's headers are ignored.

Concurrency and lifecycle:

- State is per server (`AppState`). Never move request configuration into process-global mutable state.
- Metrics, token buckets and the per-IP pool are shared across tasks. Keep locks short, never hold one across `.await` or I/O, and keep the LRU bounded.
- The active-request gauge falls exactly once on every exit, including a dropped response body, and never below zero. Uptime uses a monotonic clock.
- Contain expected disconnects only at network write and cleanup boundaries. Unexpected errors stay observable and increment the error counter.
- Transfers read in bounded chunks. Never hold a whole file or upload in memory, and release file handles before a transfer ends so Windows can reopen, rename or delete the file.
- `Ctrl+C` works on every platform and `SIGTERM` on Unix. Shutdown closes the listener at once, gives in-flight work a bounded grace period, and flushes telemetry for at most five seconds.
- Address resolution prefers IPv4 on dual-family hosts, supports IPv6-only hosts, and falls back to IPv4 when lookup fails.

## Working method

1. Read the owning module, its callers and the nearest tests.
2. Reproduce a defect with the narrowest command and record the failure.
3. Add a regression test that fails for the intended behavioral reason. Do not test source text, field forwarding or mock echoes.
4. Make the smallest root-cause fix and migrate every affected caller.
5. Run the focused test, then adjacent tests, then the gates below.
6. Remove temporary scripts, captures, servers and generated files.

Tests:

- Live tests start the server through the shared helper on loopback port `0` and shut it down in every outcome. Never use fixed ports or sleeps. Assert client-visible status, headers, bytes, cleanup and state.
- Skip a test only for a capability that is genuinely absent, with a reason. Never skip an operating system to hide a bug.
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

- Windows, Linux and macOS are first-class. Use `std::path`, never split paths by hand, and never assume separators, drive letters, case sensitivity, symlink support or POSIX permissions. Guard Unix-only code with `cfg`, tolerate unsupported socket options, and keep `TCP_QUICKACK` Linux-only.
- The crate has no system-library dependencies; TLS uses rustls. A new dependency must build on all three platforms without system libraries. Prefer the standard library or an existing dependency.
- Commit `Cargo.toml` and `Cargo.lock` together and never hand-edit the lock. Run `cargo deny check` after dependency changes, and review action, Docker base and pre-commit pins as separate supply-chain changes.
- Do not replace a transfer path without measurements on the affected platforms.
- Keep proxy buffering off for streaming: Nginx request and response buffering off, Caddy `flush_interval -1`.
- In JSON mode stdout carries only JSON records and human output goes to stderr. Keep the fields `timestamp` (UTC), `level`, `request_id`, `client_ip`, `peer_ip`, `request`, `status` and `size`.
- Never log `Authorization`, credential-bearing URLs, TLS keys, auth environment values, telemetry headers or content.
- Count only bytes actually sent or accepted, and count parsed requests, not connections. Metric names and types are public contracts; changing one needs a review of monitoring and documentation.
- Use deliberate HTTP statuses or CLI errors for user and configuration failures. Fail closed for authentication, TLS, paths and uploads. No `unwrap` or `expect` on a request-driven path.
- Comment only to explain a reason that is not obvious from the code.

## Documentation to update with a change

| Change | Update |
| :--- | :--- |
| CLI command, option, default or output | `README.md`, the relevant tests, `CONTRIBUTING.md` if contributor commands change |
| HTTP endpoint, method, status, header, cache, auth, upload or range behavior | README endpoint table and integration tests |
| Startup, shutdown, TLS, bind or health | `deploy/README.md`, `deploy/systemd/`, `Dockerfile`, Compose and Kubernetes probes |
| Container identity, port, path or writable state | `Dockerfile`, Compose, `deploy/README.md`, `deploy/k8s/` |
| Proxy transport or identity | Every affected file in `deploy/reverse-proxy/` and `deploy/README.md` |
| Metric name, type or meaning | README metric table, `deploy/monitoring/` config, alerts and dashboard |
| Usage telemetry field | README telemetry table, `src/usage.rs`, `tests/usage_payload.rs`, `deploy/telemetry-relay/` |
| Gate commands | `Makefile`, pre-commit, `CONTRIBUTING.md`, this file, the workflows |

## Commits

- Keep your changes separate from pre-existing user changes. Never discard or rewrite unrelated work.
- Stage explicit paths and never use `git add .`. Review before committing:

```console
git status --short
git diff -- <path> [<path> ...]
git diff --check
git add <path> [<path> ...]
git diff --cached --check
git diff --cached --stat
```

- Every commit message is a single line in Conventional Commits form, `type(scope): summary`. The scope is optional. Types are `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci` and `chore`. Use the imperative mood, lowercase, no trailing period, at most 72 characters. Example: `git commit -m "fix(range): preserve content length on 206"`.
- No body, no footer and no trailers. Do not add `Co-Authored-By` or other attribution lines to commits. Put context and issue links in the pull request.
- Commits are atomic: one coherent change with the tests and docs that belong to it, building and passing on its own. Split a fix from unrelated cleanup, formatting, renames or dependency changes.
- Exclude distributions, caches and generated files.
- Do not amend, rebase, force-push, tag, publish or push unless explicitly authorized. History already on `main` is never rewritten.

## Versions and releases

Keep every hard-coded release version in sync: `version` in `Cargo.toml` and `pyproject.toml`, the BlazeServe entry in the regenerated `Cargo.lock`, the image tag in `deploy/k8s/deployment.yaml`, and any test that asserts the version.

Do not bump versions, create or reuse tags, push, publish or dispatch release workflows unless explicitly authorized.

The release workflow requires its manual version or `v*` tag to equal `Cargo.toml` and `pyproject.toml`, requires the commit to be on `main`, and rejects a manual tag that already exists. Gates, binaries, wheels and the container come before publication, and the GitHub release is created only after PyPI and GHCR both succeed. PyPI versions are immutable. `PYPI_API_TOKEN` is a repository or `pypi` environment secret, `BLAZE_TELEMETRY_URL` is a repository variable, and GHCR uses `GITHUB_TOKEN`.

## Secrets and generated files

- Never commit tokens, passwords, auth pairs, private keys, certificates, real user paths or production data. Redact them from logs, fixtures, examples, screenshots, issues and reviews.
- Respect `.gitignore`: `.env`, `data/`, `certificates/`, `*.pem`, `*.key`, `*.crt`, `*.log`, `*.pid` and agent or session files stay local.
- `Cargo.lock` is tracked. `target/`, `dist/`, wheels, archives and coverage output are never source.

## Ownership

- The maintainer who submits a change owns it: they understand it, tested it, and answer review.
- Commits and pull requests carry no tool attribution, disclosure statement or `Co-Authored-By` line. Describe the change, the compatibility impact and the linked issues.
- Unsolicited autonomous or agent-generated pull requests from outside the maintainer team are not accepted.

## Handoff

Report these without overstating certainty:

- The requested behavior is complete and no unrelated file changed.
- Affected callers, tests, docs, deployment files and version locations were updated or judged unchanged.
- The focused test and the relevant gates passed, with the exact commands and results.
- Cross-platform path, shell, signal and socket behavior was considered, and any platform or deployment surface you could not verify is named.
- HTTP, authentication, traversal, cleanup, lifecycle, telemetry, logging and allocation invariants still hold.
- No temporary process, script, cache, report, distribution, secret or local data remains.
- The paths you changed.
