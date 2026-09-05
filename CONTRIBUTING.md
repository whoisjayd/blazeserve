# Contributing to BlazeServe

Thanks for your interest! This project welcomes issues, discussions, and pull requests.

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

3. Run tests, lint, and type-check:

```console
uv run pytest -n auto -q --cov=blazeserve --cov-report=xml --cov-report=term-missing
uv run ruff check .
uv run ruff format --check .
uv run mypy blazeserve
```

### Makefile shortcuts

GNU Make is optional. After running `uv sync --locked --all-extras --dev`, Make users can use these self-contained shortcuts:

```text
make install       # Install the package and development dependencies
make test          # Run the test suite with coverage
make lint          # Run Ruff lint and format checks
make typecheck     # Run Mypy
make check         # Run tests, lint, and type checks
make build         # Build and validate distribution packages
make pre-commit    # Run all configured pre-commit hooks
make clean         # Remove Python build and cache artifacts
```

The uv commands above work without Make, including on Windows.

4. (Optional) Install pre-commit hooks to run checks automatically:

```console
uv run pre-commit install
```

## Pull requests

- Create a feature branch from `main`.
- Keep PRs focused and small when possible.
- Include tests for changed behavior where practical.
- Update the relevant documentation. Label shell-specific commands as PowerShell or POSIX, and use portable relative paths when either shell works.
- Run the full commands from Development setup before opening the PR.

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
