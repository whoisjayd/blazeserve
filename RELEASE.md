# Release Process

BlazeServe releases are produced by `.github/workflows/release.yml`. The workflow does not release every push to `main`; it runs only for a manual dispatch or a pushed `v*` tag.

## Prerequisites

1. Merge the intended release commit into `main`.
2. Set `[project].version` in `pyproject.toml` to the release version and update `CHANGELOG.md`.
3. Confirm the normal CI workflow succeeds on that commit.
4. Configure a PyPI Trusted Publisher for this repository, workflow `release.yml`, and GitHub environment `pypi`. No PyPI API token is used.
5. Configure any required reviewers on the GitHub `pypi` environment.

## Recommended release

From **Actions → Release → Run workflow**, select `main` and enter the exact version from `pyproject.toml` (for example, `0.3.0`).

The release workflow:

1. Rejects a requested version that differs from `project.version`.
2. Rejects a commit that is not contained in `main`, or a manual release whose tag already exists.
3. Runs Ruff and Mypy, tests Python 3.10 through 3.13, validates wheel and source distributions, and builds and probes the container.
4. Publishes the validated distributions to PyPI through OIDC Trusted Publishing.
5. Publishes `ghcr.io/<owner>/<repository>:v<version>` and `:latest`.
6. Creates the `v<version>` tag and GitHub release only after both publications succeed.

The package and container publication jobs depend on every release gate. Tag creation happens inside the same workflow, so publishing does not rely on a second workflow being triggered by `GITHUB_TOKEN`.

## Tag-triggered release

Maintainers may instead push a tag that exactly matches the package metadata:

```bash
git tag v0.3.0
git push origin v0.3.0
```

The tag commit must be contained in `main`, and `v0.3.0` must match `project.version = "0.3.0"`. The same gates and OIDC publication jobs run before the GitHub release is created. Manual dispatch is preferred because it avoids creating a tag before the gates complete.

## Failure handling

- A validation or gate failure publishes nothing. Fix the release commit, update the version if necessary, and dispatch again.
- A PyPI or GHCR failure prevents GitHub release creation. Inspect the failed job before retrying; package versions on PyPI are immutable.
- If OIDC authentication fails, verify the PyPI Trusted Publisher owner, repository, workflow filename, and `pypi` environment exactly match the workflow.
- Do not create or reuse a tag for different package contents.

## Versioning

BlazeServe follows Semantic Versioning:

- **MAJOR**: incompatible API or behavior changes.
- **MINOR**: backward-compatible features.
- **PATCH**: backward-compatible fixes.
