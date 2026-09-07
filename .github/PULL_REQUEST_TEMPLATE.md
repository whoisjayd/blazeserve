## What changed / why

<!-- Summarize the focused change and the problem or user need it addresses. -->

- **Change:**
- **Why:**

## Linked issue

<!-- External contributors: use a closing keyword to link an issue labeled `approved-for-work` (for example, `Fixes #123`). -->

Fixes #
## AI assistance disclosure

<!-- AI assistance is a review-risk signal, not a determination of authorship. Unsolicited autonomous or agent-generated PRs are not accepted. -->

- [ ] No AI assistance was used.
- [ ] AI assistance was used and disclosed in the linked issue; the `ai-assisted` label should be applied.
- **Tools and use:** Name the tools and explain what they generated or changed, or write "None."
- **Accountable human:** Name the contributor who understands the complete change, tested it, and will respond to review.


## Behavior, compatibility, and platform impact

- **User-visible behavior:** What will users observe after this change?
- **Compatibility implications:** Does this affect supported APIs, configuration, data, or upgrade paths? If not, say so.
- **Platform impact:** Note any Linux, Windows, macOS, Docker, Kubernetes, reverse-proxy, or cross-platform considerations.

## Evidence and tests

<!-- List the exact commands you ran and their results. Include focused tests and relevant manual/smoke evidence. -->

- [ ] Focused tests: `command` — result
- [ ] Relevant checks: `command` — result
- [ ] Full quality/coverage gate (when applicable): `uv run pytest -n auto -q --cov=blazeserve --cov-report=term-missing` — coverage remains at least 85%

## Security and data handling

<!-- Complete this section when the change involves paths, uploads, authentication, TLS, logging, network writes, or secrets. Otherwise mark not applicable. -->

- [ ] Security/data-handling review completed for affected paths, uploads, authentication, TLS, logging, network writes, or secrets.
- [ ] Credentials, tokens, keys, private data, and sensitive logs are not committed or exposed.
- [ ] Not applicable: this change does not touch security-sensitive or data-handling behavior.

## Documentation and release impact

<!-- Update only the documents that the changed behavior requires; do not force irrelevant edits. -->

- [ ] README updated if user-facing usage or behavior changed.
- [ ] CONTRIBUTING.md updated if contributor workflow or commands changed.
- [ ] DEPLOYMENT.md updated if startup, shutdown, TLS, bind, health, container, proxy, or deployment behavior changed.
- [ ] Endpoint documentation updated if HTTP routes, methods, statuses, headers, caching, auth, uploads, or ranges changed.
- [ ] CHANGELOG.md updated only when release preparation or user-visible release notes are in scope.
- [ ] No documentation update is required; the changed behavior does not affect these documents.

## Maintainer review

<!-- Maintainers: confirm the following before merge. -->

- [ ] Scope is focused and fits the documented project purpose.
- [ ] Compatibility and cross-platform impact were reviewed.
- [ ] Tests and evidence are sufficient, and required CI checks pass.
- [ ] Required documentation and release impact were reviewed.
- [ ] Security and data-handling implications were reviewed where applicable.
- [ ] AI-assisted work is disclosed in both the linked issue and this PR, labeled `ai-assisted`, and has received careful human review; or no AI assistance was used.

## Reviewer notes

<!-- Anything specific that reviewers should inspect, test, or discuss? -->
