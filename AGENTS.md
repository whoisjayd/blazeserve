# BlazeServe contributor and agent handbook

## 1. Instruction precedence and scope

- This file applies to the entire repository. A more specific `AGENTS.md` overrides it only for files below its directory.
- System, maintainer, and direct task instructions take precedence. Follow the higher-precedence source and report any conflict in the handoff.
- Treat executable repository configuration (`pyproject.toml`, `uv.lock`, `Makefile`, workflows, and tests) as authoritative when prose differs. Do not guess.
- Keep the diff limited to the requested behavior. Do not combine a fix with unrelated cleanup, dependency upgrades, formatting, versions, or deployment changes.
- Preserve public CLI and Python APIs unless the task explicitly changes a contract. `blazeserve.server.__all__`, its legacy parser, and `_RateLimiter` are compatibility surfaces.
- Reuse established modules, fixtures, and errors; do not create a parallel abstraction beside an existing one.

## 2. Product purpose and boundaries

BlazeServe is a Python HTTP/1.1 file server and CLI optimized for large static transfers. It serves directories or one file with ranges, conditional caching, precompressed assets, Basic Auth, TLS, CORS, throttling, uploads, streaming ZIPs, health endpoints, Prometheus metrics, and structured logs.

- `blaze benchmark` without `--url` launches and cleans up a temporary loopback server. An explicit `--url` benchmarks an existing origin and must not start another server.
- BlazeServe binds its own socket; the supplied systemd unit does not support socket activation.
- TLS certificate rotation requires a controlled process restart; there is no in-process certificate reload.
- The default Kubernetes deployment is private, single-replica, and backed by pod-local `emptyDir`. Ingress and ServiceMonitor are optional and excluded from Kustomize.
- Compose and Kubernetes mount served data read-only. Production uploads require authenticated clients and deliberately writable storage.
- Performance varies with OS, filesystem, storage, network, TLS, and proxy. Publish figures only with the command, workload, machine, and comparison method.

## 3. Supported runtime and platforms

- Package metadata supports CPython 3.10-3.13. CI tests all four versions on Ubuntu, Windows, and macOS.
- Ruff and Mypy target the Python 3.10 compatibility floor.
- CI quality/package jobs use Python 3.12; release quality/package jobs and the production image use Python 3.13.
- The package is OS-independent. Linux-only systemd, tuning, and container hardening must not leak into portable Python paths.

## 4. Repository map

- `blazeserve/__init__.py`: public `__version__`.
- `blazeserve/cli.py`: Rich-Click commands (`serve`, `send`, `checksum`, `version`, `doctor`, `benchmark`) and input validation.
- `blazeserve/server.py`: address selection, socket tuning, TLS context, handler configuration, factory, and lifecycle.
- `blazeserve/handlers.py`: HTTP protocol, static/range transfers, caching, uploads, ZIPs, operational routes, CORS, auth, and headers.
- `blazeserve/security.py`: canonical containment, race-resistant upload creation, and request IDs.
- `blazeserve/limiter.py`: thread-safe token buckets and bounded per-IP LRU pool.
- `blazeserve/metrics.py`: thread-safe counters/gauges and Prometheus exposition.
- `blazeserve/logging.py`: Rich/JSON logging and credential redaction.
- `blazeserve/ui.py`: escaped and URL-quoted HTML directory listing.
- `blazeserve/utils.py`: hashes, sizes, Basic Auth parsing, and compatibility `TokenBucket` export.
- `tests/unit/`, `tests/integration/`, `tests/e2e/`: isolated logic, live HTTP behavior, and Click workflows.
- `tests/conftest.py`: `test_dir`, `server_factory`, `server`, and `wait_for_port`; the factory binds port `0` and guarantees teardown.
- `pyproject.toml`: build metadata, dependencies, entry point, pytest markers, coverage, Ruff, and Mypy. `uv.lock` is the reproducible resolution.
- `Makefile` and `.pre-commit-config.yaml`: optional wrappers and hook definitions.
- `.github/workflows/ci.yml` and `release.yml`: authoritative CI and publication gates.
- `Dockerfile` and `docker-compose.yml`: Python 3.13 multi-stage image and hardened runtime as uid/gid `10001`.
- `deploy/k8s/`: Deployment, ClusterIP Service, Kustomize base, optional Ingress, and optional ServiceMonitor.
- `deploy/systemd/`: hardened Linux service bound to `127.0.0.1:8000`.
- `deploy/reverse-proxy/`: unbuffered Nginx, Caddy, and Traefik configurations.
- `deploy/monitoring/`: Prometheus scrape config, alerts, and Grafana dashboard.
- `deploy/linux-tuning/`: check/dry-run/apply script, sysctl settings, and descriptor limits.
- `README.md`, `DEPLOYMENT.md`, `CONTRIBUTING.md`, `RELEASE.md`, `CHANGELOG.md`, `SECURITY.md`: user, operator, contributor, release, history, and disclosure docs.

## 5. Module ownership and dependency direction

```text
cli -> logging, server, utils, package version
server -> handlers, limiter, metrics
handlers -> security, limiter, ui, utils, package version
ui -> utils
utils -> limiter (compatibility export)
security, limiter, metrics, logging -> leaves
```

- Keep CLI concerns in `cli.py`; reusable startup/serving behavior belongs in `server.py`.
- Keep socket ownership, address selection, TLS, and shutdown in `server.py`; protocol semantics belong in `handlers.py`.
- Centralize filesystem trust checks in `security.py` for reads, uploads, and ZIPs.
- Mutate telemetry through `ServerMetrics` and throttling through `TokenBucket`/`IPRateLimiterPool`; both are shared by request threads.
- Rendering stays in `ui.py`. Lower layers must not import `cli.py`, and package modules must not form cycles.

## 6. Critical behavior invariants

### HTTP and transfers

- Keep HTTP/1.1 and accurate `Content-Length` on persistent responses. `HEAD` returns GET-equivalent status and representation headers without a body, including operational routes.
- Preserve `/__health__`, `/__live__`, `/__ready__`, `/__version__`, `/__metrics__`, `/metrics`, `/__stats__`, `/__perf__`, `/__speed__`, and `/__zip__`. PUT/POST uploads exist only below `/__upload__/`.
- `If-None-Match` uses weak comparison and precedes `If-Modified-Since`; matching validators return `304` with validators and cache policy.
- One range returns `206` and correct `Content-Range`; multiple ranges use `multipart/byteranges` with exact length. Valid-but-unsatisfiable ranges return `416` plus `Content-Range: bytes */<size>`; malformed syntax is ignored.
- An `If-Range` mismatch falls back to the full representation. A `.gz` sibling is never selected for a range request. Keep `Vary` correct for encoding and CORS.
- Operational JSON and metrics are `no-store`. ZIP responses close the connection because their length is not known up front.

### Authentication, TLS, and filesystem safety

- Authenticate GET, HEAD, PUT, and POST before filesystem or operational dispatch. Compare both Basic Auth fields with `hmac.compare_digest`; malformed or absent credentials fail closed.
- A requested auth environment variable that is absent/empty is an error, not permission to start unauthenticated.
- TLS certificate and key are inseparable. Reject an incomplete pair before binding, require TLS 1.2+, and close the listener if TLS setup fails.
- Every read, upload, and ZIP candidate must remain under the root after `realpath`. Keep `commonpath` checks so `..`, sibling prefixes, symlinked parents, and cross-drive Windows paths fail closed.
- Upload creation never overwrites. Preserve `O_EXCL`, mode `0600`, `O_NOFOLLOW` where available, post-parent containment, and partial-file deletion after premature EOF/I/O failure.
- Escape displayed filenames and URL-quote path components in directory listings; never interpolate raw names into HTML or URLs.
- Preserve `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Permissions-Policy`. Send HSTS only on an actual TLS socket.
- Accept `X-Request-ID` only when it is 1-64 characters and alphanumeric after hyphens are removed; otherwise generate 12 hex characters. Echo the result.

### Concurrency and lifecycle

- `create_server` creates a handler subclass per server. Do not move request configuration into shared mutable state across instances.
- `ServerMetrics`, token buckets, and the per-IP pool are multithreaded; preserve locking and bounded LRU eviction.
- Active requests decrement exactly once on every exit and never below zero. Uptime uses a monotonic clock.
- Expected disconnects may be contained only at network write/cleanup boundaries. Unexpected exceptions stay observable and increment server errors.
- Preserve full-file `socket.sendfile`, then windowed `mmap`, then buffered fallback. Release every `memoryview` before closing its mmap to avoid Windows file locks.
- `run_server` calls `on_bound` only after bind, restores handlers it installed, and closes the listener in `finally`, including callback failure. Request threads stay daemonized.
- Foreground shutdown is `Ctrl+C`. POSIX installs restorable SIGINT/SIGTERM handling; Windows must unwind `KeyboardInterrupt` and close. Do not make blanket claims that Unix-named signals are absent on Windows.
- Address resolution prefers IPv4 for dual-family hosts, supports IPv6-only hosts, and falls back to IPv4 after lookup failure.

## 7. Local setup with uv

Install a supported Python and uv, then run from the repository root:

```console
uv sync --locked --all-extras --dev
```

Use `uv run`; activation is unnecessary. If activation is specifically needed:

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

```bash
# POSIX shell
. .venv/bin/activate
```

GNU Make is optional and is not assumed on Windows. Use backticks for PowerShell continuations, backslashes for POSIX, `$env:NAME` in PowerShell, and `NAME=value`/`$NAME` in POSIX examples.

## 8. TDD and debugging workflow

1. Read the owning module, direct callers, and closest tests.
2. Reproduce a defect with the narrowest command and record the failure.
3. Add/adjust a regression test that fails for the intended behavioral reason; do not test source text, field forwarding, or mock echoes.
4. Make the smallest root-cause fix. Migrate all affected callers; retain compatibility only for documented public APIs.
5. Rerun the focused test, then adjacent subsystem tests, then section 10 gates.
6. Remove temporary scripts, captures, servers, and generated artifacts.

For live HTTP debugging, use `server_factory`, not fixed ports or sleeps. It binds an ephemeral port, waits for readiness, and joins all servers. Assert client-visible status, headers, bytes, cleanup, and state.

## 9. Test taxonomy, placement, and focused commands

`pyproject.toml` registers `unit`, `integration`, `e2e`, and `slow`; `--strict-markers` rejects misspellings.

- `tests/unit/`: parsing, utilities, security, metrics, limiter, UI, and server internals. Avoid live listeners; temporary file I/O is valid when under test.
- `tests/integration/`: real HTTP behavior via `server_factory` and `test_dir`.
- `tests/e2e/`: user-visible command invocation, output, and exit contracts, normally through `CliRunner`.
- Add `slow` alongside the functional category for expensive cases. Add shared fixtures to `tests/conftest.py` only when multiple modules benefit; guarantee resource/environment cleanup.

```console
uv run pytest tests/unit/test_security.py -q
uv run pytest tests/integration/test_range_requests.py -q
uv run pytest tests/e2e/test_cli_commands.py -q
uv run pytest tests/integration/test_http_serving.py::test_serve_file -q
uv run pytest -m unit -q
uv run pytest -m "integration and not slow" -q
```

Ownership: caching/headers use `test_caching_and_headers.py`; ranges use `test_range_requests.py`; uploads use `test_upload.py` and `test_upload_edges.py`; operations/metrics use `test_operational_endpoints.py`; lifecycle/platform uses `test_server_coverage.py`.

## 10. Quality, coverage, build, and hook gates

Before handing off code, run:

```console
uv run ruff check .
uv run ruff format --check .
uv run mypy blazeserve
uv run pytest -n auto -q --cov=blazeserve --cov-report=xml --cov-report=term-missing
```

Coverage is branch-aware and must remain at least 85%. Ruff uses 100 columns and configured E/F/W/I/N/UP/B/A/C4/T20/SIM rules. Mypy checks typed code and untyped function bodies.

Package, metadata, entry-point, dependency, or release changes also require:

```console
uv run python -m build
uv run twine check dist/*
```

Mirror hooks with `uv run pre-commit run --all-files`. Optional equivalents are `make test`, `make lint`, `make typecheck`, `make check`, `make build`, and `make pre-commit`. CI additionally builds the container and probes `/__live__`, `/__ready__`, and `/__metrics__`.

## 11. Portability and performance checklist

- Use `pathlib`/`os.path`; never manually split paths or assume separators, drive letters, case sensitivity, symlink support, or POSIX permissions.
- Use loopback and port `0` in tests. Skip only a genuinely absent capability, never an OS to hide a bug.
- Guard optional socket flags with `hasattr`, tolerate unsupported `setsockopt`, and keep `TCP_QUICKACK` Linux-only.
- Label shell-specific snippets and provide an activation-free `uv run` form.
- Never load an entire served file/upload into memory. Keep transfer/hash work chunked and bounded, reuse buffers, and avoid per-chunk copies on hot paths.
- Do not replace sendfile/mmap fallbacks without measurements on affected OSes. Keep locks short and never hold metrics/limiter locks during I/O.
- Proxy buffering stays disabled for streaming: Nginx request/response buffering off and Caddy `flush_interval -1`.

## 12. Logging, metrics, and errors

- Rich owns human output; JSON mode owns stdout JSON. `_print_status` must not put banners into a JSON stream.
- `--log-json` and `BLAZE_LOG_JSON=1` are supported controls. Preserve UTC timestamp, level, request ID, client IP, request, status, and size.
- Never log Authorization, credential-bearing URLs, TLS keys, auth environment values, or content. Preserve redaction in messages and exceptions.
- Count only bytes actually sent/accepted. Count parsed keep-alive requests, not TCP connections; balance the active gauge.
- Names/types from `ServerMetrics.to_prometheus()` are public operational contracts and require monitoring/documentation review when changed.
- Use Click errors or deliberate HTTP statuses for user/config failures. Fail closed for auth, TLS, paths, and uploads; never broadly catch programming errors.

## 13. Dependencies and lockfile

- Runtime requirements belong in `[project].dependencies`; developer tools belong in `[project.optional-dependencies].dev`.
- Prefer the standard library or an existing dependency over new runtime weight.
- After dependency or package-metadata changes run:

```console
uv lock
uv sync --locked --all-extras --dev
```

- Commit `pyproject.toml` and `uv.lock` together. Never hand-edit lock entries, hashes, versions, or markers.
- Such changes require normal gates plus package validation. Review Docker uv pins, pre-commit revisions, and Action pins as separate supply-chain changes.

## 14. Documentation and deployment update matrix

- CLI command/option/default/output: `README.md`, relevant e2e tests, and `CONTRIBUTING.md` if contributor commands change.
- HTTP endpoint/method/status/header/cache/auth/upload/range behavior: README endpoint table and relevant integration tests.
- Startup/shutdown/TLS/bind/health: `DEPLOYMENT.md`, `deploy/systemd/`, `Dockerfile`, Compose, and Kubernetes probes.
- Container identity/port/path/health/permissions/writable state: `Dockerfile`, Compose, `DEPLOYMENT.md`, and matching `deploy/k8s/` files.
- Proxy transport: all affected `deploy/reverse-proxy/` files and its README; preserve unbuffered streaming.
- Metric name/type/meaning: monitoring Prometheus, alerts, dashboard, monitoring README, and endpoint docs.
- Kernel/socket defaults: Linux tuning, systemd limits, CLI defaults, `/__perf__`, and deployment docs.
- Tool/gate commands: align `pyproject.toml`, `Makefile`, pre-commit, `CONTRIBUTING.md`, this file, and workflows.
- User-visible behavior goes in `CHANGELOG.md` only when the task includes release preparation.

## 15. Safe atomic Conventional Commit workflow

- Separate pre-existing user changes from yours; never discard or rewrite unrelated work.
- Review intended paths and stage explicitly. Never use `git add .`.

```console
git status --short
git diff -- <path> [<path> ...]
git diff --check
git add <path> [<path> ...]
git diff --cached --check
git diff --cached --stat
```

- Use documented prefixes: `feat:`, `fix:`, `chore:`, `docs:`, or `ci:`. Example: `git commit -m "fix: preserve range response length"`.
- One commit is one coherent behavior plus tests/docs. Exclude distributions, caches, broad formatting, and unrelated refactors.
- Do not amend, rebase, force-push, tag, publish, or push unless explicitly authorized.

## 16. Version and release safety

Synchronize every hard-coded release version:

- `[project].version` in `pyproject.toml`;
- `blazeserve.__version__` in `blazeserve/__init__.py`;
- the directory-listing footer in `blazeserve/ui.py`;
- the image tag in `deploy/k8s/deployment.yaml`;
- assertions in `tests/unit/test_version.py` and `tests/integration/test_operational_endpoints.py`;
- BlazeServe's editable package version in regenerated `uv.lock`;
- the dated heading and notes in `CHANGELOG.md`.

Do not bump versions, edit release notes, create/reuse tags, push, publish, or dispatch release workflows unless explicitly authorized. Follow `RELEASE.md`.

The release workflow requires its manual version or `v*` tag to equal `pyproject.toml`, requires the commit on `main`, and rejects an existing manual tag. Quality, Python 3.10-3.13 tests, package validation, and container probes precede PyPI/GHCR publication; GitHub release/tag creation waits for both publications. Manual dispatch from `main` is preferred because validation occurs before tag creation.

PyPI versions are immutable. `PYPI_API_TOKEN` belongs in the repository or `pypi` environment secret; this workflow uses token publication, not OIDC. GHCR uses `GITHUB_TOKEN`.

## 17. Secrets and generated artifacts

- Never commit tokens, passwords, auth pairs, private keys, certificates, credentials, real user paths, or production data. Redact them from logs, fixtures, examples, screenshots, issues, and reviews.
- Respect `.gitignore`: `.env`, `.venv`, `data/`, `certificates/`, `*.pem`, `*.key`, `*.crt`, `*.log`, `*.pid`, and agent/session files are local.
- Exclude `build/`, `dist/`, `*.egg-info/`, coverage outputs, caches, `__pycache__/`, and bytecode.
- `uv.lock` is tracked only for dependency/package metadata; wheels and sdists are never source.

## 18. Final handoff

- Requested behavior is complete; no unrelated files changed.
- Affected callers, exports, tests, docs, deployment assets, and version locations were updated or explicitly judged unchanged.
- Focused reproduction/test and relevant full gates passed.
- Cross-platform path, shell, signal, socket, and mmap behavior was considered.
- HTTP, auth, traversal, cleanup, lifecycle, telemetry, logging, and allocation invariants remain intact.
- No temporary process, script, cache, report, distribution, secret, or local data remains.
- Report changed paths, exact verification commands/results, and any unverified platform/deployment surface without overstating certainty.
