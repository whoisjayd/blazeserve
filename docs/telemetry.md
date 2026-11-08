# Telemetry

BlazeServe sends a small anonymous usage report by default. It helps the project learn which versions and platforms people use and which options matter. This page lists everything that is sent, and how to turn it off.

## Turn it off

Any one of these is enough:

- set the environment variable `BLAZE_TELEMETRY=0`
- set `DO_NOT_TRACK=1`
- run `blaze telemetry disable`

It is also off automatically when the `CI` environment variable is set. The first time it would send something, BlazeServe prints a short notice to standard error so you know.

## See what would be sent

```bash
blaze telemetry preview
```

This prints the exact report without sending it. Other subcommands are `status`, `enable` and `reset`.

## What is sent

A report is sent when `blaze serve` or `blaze send` starts, and another when it stops. Nothing is sent by other commands.

| When | What |
| :--- | :--- |
| Every report | Schema version, whether it is a `start` or `stop`, BlazeServe version, operating system, CPU architecture, the command (`serve` or `send`), and how it was installed |
| Configuration | Only yes or no for each of: TLS, password, uploads enabled, speed limit, CORS, trusted proxy, OpenTelemetry, single-file mode, folder listing |
| Stop reports only | Uptime, number of requests and bytes sent, each rounded into a coarse range, plus whether any error happened |

## What is never sent

File names and paths, host names, IP addresses, ports, URLs, passwords, the values of environment variables, and anything from a request. BlazeServe does not create or send an install ID, so reports cannot be linked together.

## Where it goes

Reports go to a small relay that checks them against a strict list of allowed fields and forwards them to a metrics backend. It never stores the sender's address. Its code is in [deploy/telemetry-relay](../deploy/telemetry-relay/README.md). Release builds only send reports if a relay address was built in. A build without one never sends anything.
