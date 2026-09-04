# Contributing to BlazeServe

Thanks for your interest! This project welcomes issues, discussions, and pull requests.

## Development setup

1. Fork and clone the repo.
2. Install uv using the [official instructions](https://docs.astral.sh/uv/getting-started/installation/), then sync the project environment and development dependencies:

```bash
uv sync --all-extras --dev
```

uv creates and manages the project virtual environment in `.venv`. Activation is optional when using `uv run`; if you prefer an activated environment, use `. .venv/bin/activate` (Windows: `.venv\Scripts\activate`).

3. Run tests, lint, and type-check:

```bash
uv run pytest -n auto -v --cov=blazeserve
uv run ruff check .
uv run ruff format --check .
uv run mypy blazeserve
```

### Makefile shortcuts

GNU Make is optional. After running `uv sync --all-extras --dev`, Make users can use these self-contained shortcuts:

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

```bash
uv run pre-commit install
```

## Pull requests

-   Create a feature branch from `main`.
-   Keep PRs focused and small when possible.
-   Include tests for new behavior where practical.
-   Update docs where needed.
-   Make sure `uv run pytest`, `uv run ruff`, and `uv run mypy` pass locally.

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
