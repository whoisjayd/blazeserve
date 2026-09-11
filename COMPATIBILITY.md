# Compatibility and Deprecation Policy

This policy defines how BlazeServe evaluates compatibility for released behavior.
It is normative for maintainers and contributors. It does not change a current
interface, version, release gate, or deployment contract.

For release mechanics, use [RELEASE.md](RELEASE.md); for contribution review, use
[CONTRIBUTING.md](CONTRIBUTING.md); for operations, use
[DEPLOYMENT.md](DEPLOYMENT.md). Those documents remain canonical for their
respective subjects.

## Scope of a compatibility commitment

The following released, documented surfaces are public compatibility commitments:

| Surface | Commitment | Primary evidence |
| --- | --- | --- |
| CLI | `blaze` commands, options, argument validation, exit behavior, and observable human or machine-readable output documented for users. | [`pyproject.toml`](pyproject.toml), [`blazeserve/cli.py`](blazeserve/cli.py), [`tests/e2e/`](tests/e2e/) |
| Python API | Names explicitly exported through a module's `__all__`, including the package version export and `blazeserve.server` exports. | [`blazeserve/__init__.py`](blazeserve/__init__.py), [`blazeserve/server.py`](blazeserve/server.py) |
| HTTP contract | Documented request methods, paths, status codes, response headers, representations, and authentication behavior. | [`blazeserve/handlers.py`](blazeserve/handlers.py), [`tests/integration/`](tests/integration/) |
| Metrics and logs | Documented Prometheus metric names/types and structured JSON log field names. | [`blazeserve/metrics.py`](blazeserve/metrics.py), [`blazeserve/logging.py`](blazeserve/logging.py), [`DEPLOYMENT.md`](DEPLOYMENT.md) |
| Package metadata | Project name, version, Python requirement, console-script entry point, runtime dependency bounds, and published wheel/source distribution identity. | [`pyproject.toml`](pyproject.toml), [release workflow](.github/workflows/release.yml) |
| Container tags | Published `ghcr.io/<owner>/<repository>:v<version>` and `:latest` tag meanings and the image entrypoint/health behavior documented by the release assets. | [`RELEASE.md`](RELEASE.md), [release workflow](.github/workflows/release.yml), [`Dockerfile`](Dockerfile) |
| Documented deployment contracts | The explicitly documented behavior and prerequisites of checked-in Docker, Compose, Kubernetes, systemd, monitoring, and reverse-proxy assets, subject to the support matrix below. | [`DEPLOYMENT.md`](DEPLOYMENT.md), [`docker-compose.yml`](docker-compose.yml), [`deploy/`](deploy/) |

A user-facing surface is not exempt merely because it is simple or has no type
annotation. A documented output field, endpoint, option, metric, or tag is public
when users can reasonably automate against it.

The following are **not** compatibility commitments unless they are expressly
exported or documented as public:

- private names and implementation details, including leading-underscore helpers
  that are not explicitly exported;
- internal module layout, call graphs, dynamic classes, data structures, locks,
  and implementation-specific performance techniques;
- test fixtures, test-only helpers, and development tooling behavior;
- examples, snippets, or deployment combinations that have no stated validation
  evidence; and
- an operator's local configuration, credentials, content, proxy controller,
  storage provider, or kernel tuning result.

Changing an excluded implementation detail must still preserve every public
observable behavior it affects.

## Versioning intent and compatibility window

BlazeServe follows the Semantic Versioning intent stated in
[RELEASE.md](RELEASE.md): patch releases are backward-compatible fixes, minor
releases are backward-compatible features, and a major release is the normal place
for incompatible public behavior. While the project is pre-1.0, a release remains
stable enough for operators to rely on the public surfaces in this policy, but the
project does **not** promise a fixed number of supported releases, months, or
calendar duration.

For a planned incompatibility before 1.0, maintainers MUST choose and document a
reasonable compatibility window based on user impact, adoption evidence, security
risk, and feasible migration. The window begins with the release that first
announces the deprecation and ends no earlier than the removal release stated in
that notice. A minor version alone does not waive the requirements below.

A change may be released without a deprecation window only under the documented
exception process. A removal is not retroactively compatible because a changelog
mentions it after the fact.

## Deprecation process

Unless an approved exception applies, a public-surface deprecation proceeds through
these stages:

1. **Proposal and evidence.** The issue and pull request identify the affected
   public surface, current and replacement behavior, affected platforms/artifacts,
   compatibility risk, focused evidence, and the planned removal release or
   condition.
2. **Announcement.** The release notes and affected canonical documentation mark
   the old behavior as deprecated, name the replacement, and give a concrete
   migration path. Documentation must not leave two conflicting interfaces equally
   canonical.
3. **Warning or migration aid.** When an interface is invoked by an interactive
   user or application code, provide an actionable warning or compatible migration
   path where technically safe. A warning MUST identify the replacement and MUST
   NOT disclose secrets or make machine-readable output unusable. For a network,
   metric, log, or container surface where runtime warning is inappropriate, the
   documented announcement and migration instructions are the notice mechanism.
4. **Supported overlap.** Keep the old behavior working for the announced window;
   preserve its documented contract and test the migration boundary where a
   plausible regression exists.
5. **Removal.** Remove the obsolete behavior, compatibility aliases, obsolete
   documentation, and tests that solely preserve it. Update canonical documents,
   release notes, and migration instructions so the replacement is the only
   current path. Record the removal and its compatibility impact in the release
   notes.

A deprecation notice MUST state what changes, who is affected, the replacement,
how to migrate, the planned removal release or condition, and any material
platform/deployment limitation. A deprecation MUST NOT silently change defaults,
status codes, metric/log field names, output formats, or container-tag meaning.

## Exceptions

A maintainer may approve a shorter window or immediate change only for a credible
security issue, legal requirement, data-loss/corruption risk, severe operational
hazard, or an objectively impossible compatibility path. The approval MUST be
recorded in the linked issue and pull request, with:

- the public surface and reason the ordinary process is unsafe or infeasible;
- the affected releases, users, platforms, and artifacts;
- the evidence supporting urgency;
- the mitigation or replacement path; and
- the release-note wording.

The maintainer has final responsibility for compatibility under
[GOVERNANCE.md](GOVERNANCE.md). Security-sensitive details follow the private
process in [SECURITY.md](SECURITY.md); public release notes should disclose only
what is safe to disclose.

## Evidence standard

A support or compatibility claim MUST be traceable to current repository evidence.
Use direct source and focused tests for behavior; package metadata for interpreter
and package claims; CI/release workflow jobs for tested combinations and artifacts;
and deployment assets plus their documentation for operational examples. Do not
upgrade a claim from “example” to “supported” because a file is checked in.

Evidence must identify its limitation. For example, a package classifier establishes
portability intent, not a successful test on every host; an Ubuntu container probe
does not validate Docker Desktop, Kubernetes, or every proxy.

## Support matrix

| Surface or artifact | Current scope | Evidence | Limitation and review trigger |
| --- | --- | --- | --- |
| Python package portability | Python `>=3.10`; classifiers identify Python 3.10–3.13 and OS-independent portability. | [`pyproject.toml`](pyproject.toml) | Metadata expresses package portability intent. It is not proof of every interpreter implementation, OS release, architecture, or environment. Review when Python requirements, classifiers, dependencies, or packaging change. |
| Tested CPython/OS combinations | CPython 3.10, 3.11, 3.12, and 3.13 on Ubuntu, Windows, and macOS. | [CI matrix](.github/workflows/ci.yml) | CI tests this 3×4 matrix; it does not create a universal claim for other Python implementations or operating-system versions. Review when the matrix, platform-sensitive code, or supported Python range changes. |
| Release package artifact | Wheel and source distribution are built and checked on Ubuntu with Python 3.12 in CI; release package gate uses Ubuntu with Python 3.13. | [CI workflow](.github/workflows/ci.yml), [release workflow](.github/workflows/release.yml) | Artifact build validation is Ubuntu-only; runtime testing remains the separate CPython/OS matrix. Review when build backend, package metadata, or release workflow changes. |
| Docker image and published tags | Dockerfile image is built and liveness/readiness probes are exercised in Ubuntu CI; release publishes `:v<version>` and `:latest`. | [`Dockerfile`](Dockerfile), [CI workflow](.github/workflows/ci.yml), [release workflow](.github/workflows/release.yml), [`RELEASE.md`](RELEASE.md) | Docker image build/probe coverage is Ubuntu CI only. This does not claim Docker/Desktop/engine portability on every host or orchestrator. Review when Dockerfile, probes, entrypoint, tags, or release workflow changes. |
| Docker Compose example | Checked-in Compose service defines a hardened single service, read-only data mount, JSON logging, and a liveness healthcheck. | [`docker-compose.yml`](docker-compose.yml), [`DEPLOYMENT.md`](DEPLOYMENT.md) | An operational example, not a separately validated universal support target in CI; the default mount is read-only, so production uploads require an explicitly configured writable volume and authentication per `DEPLOYMENT.md`. Review when Compose configuration, documented command, mounts, or health behavior changes. |
| Kubernetes manifests | Default Kustomize assets define one hardened pod and internal ClusterIP Service; ingress and ServiceMonitor are optional. | [`deploy/k8s/README.md`](deploy/k8s/README.md), [`deploy/k8s/`](deploy/k8s/), [`DEPLOYMENT.md`](DEPLOYMENT.md) | Checked-in operational examples; CI does not prove a Kubernetes-version, ingress-controller, storage-provider, or Prometheus-operator support matrix. Review when manifests, probes, volume semantics, or documented prerequisites change. |
| systemd, reverse proxy, and monitoring assets | Checked-in Linux systemd unit, Nginx/Caddy/Traefik blueprints, and monitoring configurations document their required assumptions. | [`deploy/systemd/README.md`](deploy/systemd/README.md), [`deploy/reverse-proxy/`](deploy/reverse-proxy/), [`deploy/monitoring/`](deploy/monitoring/), [`DEPLOYMENT.md`](DEPLOYMENT.md) | Operational examples with differing host/controller dependencies; they are not universal support claims or CI-validated deployment combinations. Review when an asset, required prerequisite, bind address, endpoint, or proxy behavior changes. |

## Contribution, pull-request, and release checklist

### Issue and pull request

For any change that may affect a public surface, the author MUST:

- identify the affected surface from this policy and whether the change is
  compatible, deprecated, removed, or excluded;
- link direct evidence for the current behavior and state the affected
  Python/OS/container/deployment row from the support matrix;
- document user-visible migration, warnings, output/HTTP/metric/log changes, and
  exception approval when applicable;
- update the canonical documentation and focused tests appropriate to the changed
  contract; and
- state the compatibility implication and platform impact in the pull request,
  consistent with the repository's [pull-request template](.github/PULL_REQUEST_TEMPLATE.md).

### Release review

Before releasing a change with compatibility impact, maintainers MUST confirm that
its deprecation notice or exception is recorded, migration instructions are current,
and release notes describe the user-visible change. Follow the required release
commands and gates in [RELEASE.md](RELEASE.md); this policy does not duplicate
those mechanics.

## Worked scenario: retiring a CLI option

Suppose a future release replaces a public `blaze serve --old-option` with
`--new-option`. This example does not deprecate either option today.

1. The proposal identifies `--old-option` as a CLI compatibility surface, links the
   current Click command and e2e evidence, and states which CPython/OS and
   container/deployment matrix rows could be affected.
2. The deprecation release continues to accept `--old-option`, documents
   `--new-option` as its replacement, emits an actionable warning without
   corrupting `--json` output, and states the planned removal release or condition
   in the changelog and CLI documentation.
3. During the announced overlap, focused tests cover both the existing option and
   the migration behavior; release review carries the notice into release notes.
4. At the stated removal point, the implementation, alias, old-option docs, and
   old-only tests are removed together. The release notes identify the removal and
   point users to `--new-option`.

An analogous HTTP endpoint retirement preserves the old method/path/status and
representation during the announced window, publishes the replacement endpoint
and migration instructions, and records any immediate removal as an approved
exception.
