# Contributing to BlazeServe

Thanks for helping. Bug reports, fixes, tests and documentation are all welcome.

## Before you start

1. Search the [issues](https://github.com/whoisjayd/blazeserve/issues), then open a bug report or feature request. Start a usage question's title with "Question".
2. For anything larger than a small fix, comment on the issue first so the work is not duplicated. Claiming an issue does not reserve it.
3. Never put credentials, tokens, private keys or exploit details in a public issue, pull request or log. Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Set up

Install Rust 1.88 or newer with [rustup](https://rustup.rs/). `rust-toolchain.toml` selects the stable toolchain with `clippy` and `rustfmt`. There are no system-library dependencies on any supported platform.

```bash
git clone https://github.com/whoisjayd/blazeserve
cd blazeserve
cargo test
cargo run -- serve .
```

Run one test binary with `cargo test --test <name>`, or one test with `cargo test <name> -- --nocapture`.

## Checks

CI runs these on Linux, Windows and macOS, so run them before you push:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

CI also enforces 80 percent line coverage with `cargo llvm-cov` and runs `cargo deny check`. To build a wheel locally, run `uvx maturin build --release --out dist`.

## Project layout

| Path | Owns |
| :--- | :--- |
| `src/config.rs` | Typed configuration and validation shared by every entry point |
| `src/cli/` | The `blaze` commands |
| `src/server.rs` | Sockets, TLS, connection limit, proxy identity, shutdown |
| `src/handler/`, `src/range.rs`, `src/cache.rs` | HTTP semantics, ranges, validators, operational routes |
| `src/upload.rs`, `src/zip_stream.rs`, `src/security.rs` | Uploads, ZIP streaming, path containment |
| `src/limiter.rs`, `src/metrics.rs`, `src/logging.rs`, `src/telemetry/`, `src/usage.rs`, `src/ui.rs` | Throttling, metrics, logs, OpenTelemetry, usage report, directory listing |
| `tests/` | Integration tests against a live server; unit tests sit beside the code |
| `deploy/` | Container, Kubernetes, systemd, proxy and monitoring files, and the telemetry relay |

## Writing code

- Format with `cargo fmt` and keep `cargo clippy -D warnings` clean.
- Do not `unwrap` or `expect` on a request-driven path. Return an error or a deliberate HTTP status.
- Hold locks for arithmetic only, never across `.await` or I/O.
- Never load a whole served file or upload into memory. Transfers are chunked and bounded.
- Fail closed on authentication, TLS, paths and uploads.
- Keep portability in mind: build paths from components, guard Unix-only code with `cfg`, and never skip a test by operating system. Skip only a capability that is genuinely absent, with a reason.
- Comment only to explain a reason that is not obvious from the code.

Live HTTP tests bind port `0` on loopback through the shared helper. Do not use fixed ports or sleeps. A bug fix needs a test that fails without it.

## Pull requests

- Branch from `main` and keep the change focused. Do not mix a fix with unrelated cleanup or dependency changes.
- Link the issue with a closing keyword such as `Fixes #123`.
- Describe the behavior change, the compatibility impact and the platforms you tested, and include the commands you ran.
- Update the README or `deploy/README.md` when commands, endpoints, options or deployment guidance change. Label shell-specific snippets as PowerShell or POSIX.
- Do not hand-edit `Cargo.lock`.
- Write each commit as a single [Conventional Commits](https://www.conventionalcommits.org/) line, `type(scope): summary`, with no body or trailers. Types are `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci` and `chore`. Keep commits atomic: one coherent change with its tests and docs, and no unrelated cleanup mixed in. Put context and issue links in the pull request.

## Ownership and review

Whoever opens a pull request owns it. You should understand the whole change, have tested it, and be ready to answer review and revise the work yourself. Unsolicited autonomous or agent-generated pull requests are not accepted.

Commits and pull request descriptions need no tool attribution or disclosure statement. Say what changed, why, and what it means for compatibility.

## Conduct

Everyone is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
