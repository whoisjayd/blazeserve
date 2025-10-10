# Contributing to BlazeServe

Thanks for your interest! This project welcomes issues, discussions, and pull requests.

## Development setup

1. Fork and clone the repo.
2. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -U pip
pip install -e ".[dev]"
```

3. Run tests, lint, and type-check:

```bash
pytest -q
ruff check .
mypy blazeserve
```

4. (Optional) Install pre-commit hooks to run checks automatically:

```bash
pip install pre-commit
pre-commit install
```

## Pull requests

-   Create a feature branch from `main`.
-   Keep PRs focused and small when possible.
-   Include tests for new behavior where practical.
-   Update docs where needed.
-   Make sure `pytest`, `ruff`, and `mypy` pass locally.

## Commit messages

Use clear, descriptive messages. If your change fixes an issue, include `Fixes #123` in the description.

## Code style

The codebase prefers:

-   Python ≥ 3.9
-   `ruff` for linting
-   `mypy` for type hints (best effort)
