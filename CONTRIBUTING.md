# Contributing to BlazeServe

Thanks for your interest in BlazeServe. Contributions are welcome, whether you are reporting a bug, improving documentation, or changing the server. Start with the guidance below so work is easy to review and safe to merge.

## Ways to contribute

- Report reproducible bugs and request actionable features through the appropriate [issue form](https://github.com/whoisjayd/blazeserve/issues/new/choose).
- Improve HTTP behavior, performance, security, observability, deployment examples, documentation, or tests.
- Help triage issues, reproduce reports, review pull requests, and improve examples.

## Before you start

1. Search existing [issues](https://github.com/whoisjayd/blazeserve/issues) before opening a request.
2. Use the issue form that best matches the work: bug reports, feature requests, documentation corrections, or questions.
3. External contributors must obtain issue approval before implementation as described below. Open the issue first and wait for a maintainer to apply `approved-for-work`.
4. Never include credentials, tokens, private keys, or exploit details in a public issue, pull request, or log. Use [SECURITY.md](SECURITY.md) for vulnerabilities.

New contributors can browse the [`good first issue`](https://github.com/whoisjayd/blazeserve/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) and [`help wanted`](https://github.com/whoisjayd/blazeserve/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) lists. Comment on an issue before starting, and release the issue if you are no longer working on it; claiming an issue does not reserve it indefinitely.
## Approval and AI-assisted contributions

Pull requests from contributors without repository write access must use a closing keyword (for example, `Fixes #123`) to link at least one issue labeled `approved-for-work`. Obtain that label before opening the pull request. The automated gate exempts Dependabot and authors whose association is `OWNER`, `MEMBER`, or `COLLABORATOR`.

Unsolicited autonomous or agent-generated pull requests are not accepted. AI-assisted contributions are welcome only when a named human contributor:

- discloses the assistance and tools used in both the originating issue and pull request;
- understands the entire change, tests it, and remains accountable for its correctness; and
- responds to review and revises the work personally.

AI disclosure is a review-risk signal, not an attempt to detect AI use. Maintainers apply `ai-assisted` so the change receives careful human review.


## Repository map

The main implementation and test areas are:

- `blazeserve/cli.py`: CLI commands and input validation.
- `blazeserve/server.py`: address selection, socket and TLS setup, configuration, and lifecycle.
- `blazeserve/handlers.py`: HTTP protocol, transfers, caching, uploads, ZIPs, operational routes, CORS, authentication, and headers.
- `blazeserve/security.py`: filesystem containment, safe upload creation, and request IDs.
- `blazeserve/limiter.py`: token buckets and the per-IP rate-limit pool.
- `blazeserve/metrics.py`: counters, gauges, and Prometheus output.
- `blazeserve/logging.py`: human/JSON logging and credential redaction.
- `blazeserve/ui.py`: escaped and URL-quoted directory listings.
- `blazeserve/utils.py`: hashes, sizes, authentication parsing, and compatibility exports.
- `tests/unit/`: isolated logic and module-level behavior.
- `tests/integration/`: live HTTP behavior through the shared server fixtures.
- `tests/e2e/`: user-visible Click workflows and command contracts.

## Development setup

1. Fork and clone the repo.
2. Install uv using the [official instructions](https://docs.astral.sh/uv/getting-started/installation/), then sync the project environment and development dependencies:

```console
uv sync --locked --all-extras --dev
```

uv creates and manages `.venv`. You do not need to activate it when using `uv run`. If you choose to activate it, use the command for your shell:

```bash
# POSIX shell
. .venv/bin/activate
```

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

3. Run the focused checks relevant to your change. These commands work without Make, including on Windows:

```console
uv run pytest tests/unit/test_security.py -q
uv run pytest tests/integration/test_range_requests.py -q
uv run pytest tests/e2e/test_cli_commands.py -q
uv run pytest tests/integration/test_http_serving.py::test_serve_file -q
uv run pytest -m unit -q
uv run pytest -m "integration and not slow" -q
```

Run the full quality gate before handoff:

```console
uv run ruff check .
uv run ruff format --check .
uv run mypy blazeserve
uv run pytest -n auto -q --cov=blazeserve --cov-report=xml --cov-report=term-missing
```

Coverage is branch-aware and must remain at least 85%. Behavior changes should include tests where practical. Use `uv run pre-commit run --all-files` when pre-commit is available. To install the optional hooks, run `uv run pre-commit install`. GNU Make is optional; the existing `make install`, `make test`, `make lint`, `make typecheck`, `make check`, `make build`, `make pre-commit`, and `make clean` shortcuts are available where supported. The uv commands above work without Make, including on Windows.

## Pull requests

- Create a feature branch from `main` and keep the change focused.
- Follow the approval and disclosure policy above. Use `Fixes #<issue>` so GitHub records the approved issue as a closing issue.
- Describe concrete user-visible behavior, compatibility implications, and platform impact.
- Include focused tests and the exact commands/results used as evidence. Run the full quality gate above before opening the PR.
- Update user-facing documentation when behavior, commands, endpoints, deployment, or operational guidance changes. Label shell-specific commands as PowerShell or POSIX and use portable relative paths where either shell works.
- Review changes involving paths, uploads, authentication, TLS, logging, network writes, or secrets for data-handling and security implications. Never include secrets in examples or logs.
- Expect review for correctness, security, portability, maintainability, tests, documentation, and fit with the project's purpose. Required CI checks must pass before merge.

Dependency-update pull requests are expected to pass the same CI, quality, coverage, and package gates as human-authored pull requests. Review dependency and lockfile changes as supply-chain changes; do not hand-edit `uv.lock`.

## Commit messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` New features or capabilities
- `fix:` Bug fixes and corrections
- `chore:` Dependencies, git hygiene, and tooling
- `docs:` Documentation improvements
- `ci:` GitHub Actions and release automation

## Code style

The codebase adheres to:

- Python ≥ 3.10
- `ruff` for linting and code formatting (line length 100)
- `mypy` checks annotated code and the bodies of unannotated functions; annotations are not globally required
- Google-style docstrings on public APIs

## Labels

Use `area:*` labels to identify the affected subsystem and `platform:*` labels for OS-specific behavior. They may be combined with a workflow or status label such as `bug`, `enhancement`, `documentation`, `question`, `needs-triage`, or `help wanted`. Maintainers use `approved-for-work` to authorize external implementation and `ai-assisted` to flag disclosed AI assistance for careful human review. `priority: high` and `blocked` are maintainer-applied labels: the former marks urgent compatibility, security, or release impact, and the latter marks work waiting on an external decision or dependency.

## Community and project policies

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Support](SUPPORT.md)
- [Governance](GOVERNANCE.md)
- [Security policy](SECURITY.md)
