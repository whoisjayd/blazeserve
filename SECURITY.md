# Security policy

## Report a vulnerability

Email **[contactjaydeepsolanki@gmail.com](mailto:contactjaydeepsolanki@gmail.com)** with:

- the affected version and platform
- what you found and the impact you expect
- the smallest steps or request that reproduce it

Please do not open a public issue or pull request, and do not post credentials, keys, exploit details or sensitive logs anywhere public. Receipt is acknowledged within 72 hours, and a fix timeline follows initial triage.

## What happens next

We validate the report, fix it, and release. Please keep the details private until a fix is out and users have had reasonable time to update.

## Supported versions

| Version | Supported |
| :--- | :--- |
| 1.x | Yes |
| Earlier than 1.0 | No. The Python implementation is end of life |

## Scope

In scope: the BlazeServe binary, its published wheels, archives and container images, and the telemetry relay in `deploy/telemetry-relay`. Report issues in third-party dependencies upstream.

The threat model and the defenses behind it are described in the [README](README.md#security-model). Release artifacts carry build-provenance attestations; verify one with `gh attestation verify <file> --repo whoisjayd/blazeserve`.
