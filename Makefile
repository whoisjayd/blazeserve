.PHONY: install test lint typecheck check build pre-commit clean

install:
	uv sync --all-extras --dev

test:
	uv run pytest -n auto -q --cov=blazeserve --cov-report=xml --cov-report=term-missing

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy blazeserve

check: test lint typecheck

build:
	uv run python -m build
	uv run twine check dist/*

pre-commit:
	uv run pre-commit run --all-files

clean:
	uv run python -c "from pathlib import Path; import shutil; root=Path('.'); excluded={'.git','.venv'}; [shutil.rmtree(root/name, ignore_errors=True) for name in ('build','dist','.pytest_cache','.mypy_cache','.ruff_cache','.tox','.nox','.cache','htmlcov','pip-wheel-metadata') if (root/name).is_dir() and not (root/name).is_symlink()]; [shutil.rmtree(path, ignore_errors=True) for path in root.rglob('__pycache__') if path.is_dir() and not path.is_symlink() and not excluded.intersection(path.parts)]; [shutil.rmtree(path, ignore_errors=True) for path in root.rglob('*.egg-info') if path.is_dir() and not path.is_symlink() and not excluded.intersection(path.parts)]; [path.unlink() for pattern in ('*.pyc','*.pyo') for path in root.rglob(pattern) if path.is_file() and not excluded.intersection(path.parts)]; [path.unlink() for path in root.glob('.coverage*') if path.is_file()]; [path.unlink() for path in (root/'coverage.xml',) if path.is_file()]"
