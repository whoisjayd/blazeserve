# Security policy

## Reporting a vulnerability

If you think you have found a security problem, please tell us privately. Email **[contactjaydeepsolanki@gmail.com](mailto:contactjaydeepsolanki@gmail.com)** and include:

- the version and platform you tested
- what you found and what you think the impact is
- the smallest set of steps or the smallest request that reproduces it

Please do not open a public issue or pull request, and do not post passwords, keys, exploit details or sensitive logs anywhere public. We will confirm that we received your report within 72 hours and give you a timeline once we have looked into it.

## What happens next

We check the report, work on a fix and publish a release. Please keep the details private until the fix is out and people have had a fair chance to update.

## Supported versions

| Version | Supported |
| :--- | :--- |
| 1.x | Yes |
| Earlier than 1.0 | No. The old Python version is no longer maintained |

## What is covered

This policy covers the BlazeServe program, its published Python wheels, release archives and container images, and the telemetry relay in `deploy/telemetry-relay`. If the problem is in a library BlazeServe depends on, please report it to that project.

To see what BlazeServe is designed to defend against, and what it is not, read the [security guide](docs/security.md). Release files come with build provenance. You can check one with `gh attestation verify <file> --repo whoisjayd/blazeserve`.
