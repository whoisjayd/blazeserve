# Release Process

This document describes how to publish a new version of BlazeServe to PyPI.

## Prerequisites

- All tests must pass on the main branch
- CHANGELOG.md must be updated with the new version and release notes
- Version in pyproject.toml must be updated

## Publishing to PyPI

The package is automatically published to PyPI when a version tag is pushed to GitHub.

### Steps to Release

1. **Update Version**
   
   Edit `pyproject.toml` and update the version number:
   ```toml
   version = "0.2.0"
   ```

2. **Update CHANGELOG**
   
   Edit `CHANGELOG.md` and add release notes for the new version with the current date.

3. **Commit Changes**
   
   ```bash
   git add pyproject.toml CHANGELOG.md
   git commit -m "Bump version to 0.2.0"
   git push origin main
   ```

4. **Create and Push Tag**
   
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

5. **Verify Publication**
   
   Once the tag is pushed, GitHub Actions will automatically:
   - Run all tests
   - Build the package
   - Publish to PyPI (if `PYPI_API_TOKEN` secret is configured)
   
   Check the [Actions tab](https://github.com/whoisjayd/blazeserve/actions) to monitor the workflow.

## GitHub Actions Workflow

The CI workflow (`.github/workflows/ci.yml`) includes a `publish` job that:

- Triggers only when a tag starting with `v` is pushed (e.g., `v0.2.0`)
- Requires all tests to pass first
- Builds the distribution packages
- Publishes to PyPI using the `PYPI_API_TOKEN` secret

## Troubleshooting

### Package Not Published

If the package doesn't publish after pushing a tag:

1. **Check Workflow Run**: Visit the [Actions tab](https://github.com/whoisjayd/blazeserve/actions) and check if the workflow ran
2. **Verify Tag Format**: Tag must start with `v` (e.g., `v0.2.0`, not `0.2.0`)
3. **Check Secret**: Ensure `PYPI_API_TOKEN` is configured in repository secrets
4. **Review Logs**: Check the workflow logs for any errors

### Tests Failed

If tests fail during the publish workflow:

1. Fix the failing tests on the main branch
2. Delete the tag: `git tag -d v0.2.0 && git push origin :refs/tags/v0.2.0`
3. Fix the issues and create a new tag

## Version Numbering

BlazeServe follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

## Post-Release

After a successful release:

1. Create a [GitHub Release](https://github.com/whoisjayd/blazeserve/releases/new)
2. Copy the changelog entries for the release notes
3. Announce the release (if applicable)

## Current Status

**Version**: 0.2.0  
**Status**: Ready for release  
**Action Required**: Create and push tag `v0.2.0` to publish to PyPI
