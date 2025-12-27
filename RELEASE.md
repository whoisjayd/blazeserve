# Release Process

This document describes how to publish a new version of BlazeServe to PyPI.

## Prerequisites

- All tests must pass on the main branch
- CHANGELOG.md must be updated with the new version and release notes
- Version in pyproject.toml must be updated

## Publishing to PyPI

BlazeServe uses **automated release workflows** to streamline the release process.

### Automated Release (Recommended)

When you push changes to the main branch, the release workflow automatically:

1. Detects the version from `pyproject.toml`
2. Checks if a tag for that version exists
3. If not, creates the tag and GitHub release with changelog notes
4. The tag creation triggers the PyPI publish workflow

**Steps:**

1. **Update Version**
   
   Edit `pyproject.toml` and update the version number:
   ```toml
   version = "0.2.0"
   ```

2. **Update CHANGELOG**
   
   Edit `CHANGELOG.md` and add release notes for the new version with the current date.

3. **Commit and Push to Main**
   
   ```bash
   git add pyproject.toml CHANGELOG.md
   git commit -m "Bump version to 0.2.0"
   git push origin main
   ```

4. **Automated Steps**
   
   GitHub Actions will automatically:
   - Create tag `v0.2.0`
   - Create GitHub Release with changelog notes
   - Trigger PyPI publish workflow
   - Run all tests
   - Build the package
   - Publish to PyPI (if `PYPI_API_TOKEN` secret is configured)
   
   Check the [Actions tab](https://github.com/whoisjayd/blazeserve/actions) to monitor the workflow.

### Manual Release

You can also trigger a release manually:

1. **Via GitHub Actions UI**
   - Go to [Actions → Release Automation](https://github.com/whoisjayd/blazeserve/actions/workflows/release.yml)
   - Click "Run workflow"
   - Optionally specify a version (otherwise uses `pyproject.toml`)

2. **Via Git Commands**
   
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```
   
   Then manually create the GitHub release from the tag.

## GitHub Actions Workflows

### Release Automation (`.github/workflows/release.yml`)

Automatically creates tags and GitHub releases:

- **Triggers**: On push to main branch or manual dispatch
- **Actions**:
  1. Extracts version from `pyproject.toml`
  2. Checks if tag already exists
  3. If new version, creates tag and GitHub release
  4. Extracts changelog notes for release body
  5. Tag creation triggers the CI publish workflow

### CI and PyPI Publishing (`.github/workflows/ci.yml`)

Runs tests and publishes to PyPI:

- **Triggers**: On tag push (e.g., `v0.2.0`)
- **Actions**:
  1. Runs all tests across Python 3.9-3.12
  2. Builds distribution packages
  3. Publishes to PyPI using `PYPI_API_TOKEN` secret

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

After a successful automated release:

1. ✅ GitHub Release is created automatically with changelog notes
2. ✅ Tag is created and pushed automatically
3. ✅ PyPI publish workflow is triggered automatically
4. Optionally announce the release

## Current Status

**Version**: 0.2.0  
**Status**: Ready for automated release  
**Action Required**: Push version bump to main branch to trigger automated release
