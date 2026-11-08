# Contributing to BlazeServe

Thanks for helping. Bug reports, fixes, tests and better documentation are all welcome.

## Before you start

1. Look through the [issues](https://github.com/whoisjayd/blazeserve/issues), then open a bug report or feature request if yours is new. If you have a usage question, start the title with "Question".
2. For anything bigger than a small fix, comment on the issue first so two people do not do the same work. Commenting does not reserve the issue.
3. Never put passwords, tokens, private keys or exploit details in a public issue, pull request or log. Report security problems privately, as described in [SECURITY.md](SECURITY.md).

## Set up

Install Rust 1.88 or newer with [rustup](https://rustup.rs/). The `rust-toolchain.toml` file picks the stable toolchain with `clippy` and `rustfmt`. BlazeServe needs no system libraries on any supported platform.

```bash
git clone https://github.com/whoisjayd/blazeserve
cd blazeserve
cargo test
cargo run -- serve .
```

To run one test file, use `cargo test --test <name>`. To run a single test, use `cargo test <name> -- --nocapture`.

## Checks to run before you push

CI runs these on Linux, Windows and macOS:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

CI also requires 80 percent line coverage (`cargo llvm-cov`) and runs `cargo deny check`. To build a Python wheel locally, run `uvx maturin build --release --out dist`. To test the Python bindings, install that wheel in a clean virtual environment with `pytest` and run `python -m pytest tests_py`. The `python` Cargo feature is only for wheel builds, so ordinary `cargo` commands do not need it.

## How the code is organised

| Path | What lives there |
| :--- | :--- |
| `src/config.rs` | Settings and their validation, shared by every entry point |
| `src/cli/` | The `blaze` commands |
| `src/server/` | Sockets, TLS, connection limits, proxy identity, shutdown |
| `src/handler/`, `src/range.rs`, `src/cache.rs` | HTTP behaviour: ranges, caching headers, status pages |
| `src/upload/`, `src/zip_stream/`, `src/security.rs` | Uploads, ZIP streaming, keeping paths inside the served folder |
| `src/limiter.rs`, `src/metrics.rs`, `src/logging.rs`, `src/telemetry/`, `src/usage/`, `src/ui.rs` | Speed limits, metrics, logs, OpenTelemetry, the usage report, the folder listing page |
| `src/python.rs`, `python/`, `tests_py/` | The Python bindings, the Python package and its tests |
| `tests/` | Tests that start a real server. Smaller unit tests sit next to the code |
| `deploy/` | Container, Kubernetes, systemd, proxy and monitoring files, and the telemetry relay |
| `docs/` | The user guides |

[AGENTS.md](AGENTS.md) has a more detailed map and the rules each part must keep.

## Writing code

- Format with `cargo fmt` and keep `cargo clippy -D warnings` clean.
- Do not use `unwrap` or `expect` on a path that handles requests. Return an error or a deliberate HTTP status.
- Hold locks only for quick work, never across `.await` or file or network I/O.
- Never read a whole file or upload into memory. Transfers are chunked and bounded.
- When in doubt about authentication, TLS, paths or uploads, refuse.
- Keep it portable: build paths from components, guard Unix-only code with `cfg`, and never skip a test for one operating system. You may skip a test only for a capability that is truly missing, and you should say why.
- Comment only to explain a reason that is not obvious from the code.

Tests that start a server bind port `0` on the loopback address through the shared helper. Do not use fixed ports or sleeps. A bug fix needs a test that fails without the fix.

## Pull requests

- Branch from `main` and keep the change focused. Do not mix a fix with unrelated cleanup or dependency updates.
- Link the issue with a closing keyword such as `Fixes #123`.
- Describe what changed for users, whether anything breaks, which platforms you tested, and the commands you ran.
- Update the matching documentation. A new or changed option, command or address belongs in [docs/reference.md](docs/reference.md) and the relevant guide. Deployment changes belong in [deploy/README.md](deploy/README.md). Label shell snippets as PowerShell or POSIX when they differ.
- Do not edit `Cargo.lock` by hand.
- Write each commit message as a single [Conventional Commits](https://www.conventionalcommits.org/) line, `type(scope): summary`, with no body and no trailers. The types are `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci` and `chore`. Keep each commit to one change, with its tests and docs. Put the background and issue links in the pull request.

## Ownership and review

Whoever opens a pull request owns it. You should understand the whole change, have tested it, and be ready to answer questions in review and revise it yourself. Pull requests that are generated and opened autonomously by tools, without a maintainer behind them, are not accepted.

Commits and pull request descriptions do not need any tool credit or disclosure statement. Say what changed, why, and what it means for compatibility.

## Conduct

Everyone is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
