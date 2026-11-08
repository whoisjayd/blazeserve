# Monitoring

BlazeServe tells you how it is doing in four ways: health endpoints, Prometheus metrics, structured logs and OpenTelemetry. You can use any of them, or none.

## Health checks

| Address | Use it for |
| :--- | :--- |
| `/__live__` | Is the process running? |
| `/__ready__` | Can it serve right now? This also checks that the served folder is reachable |
| `/__health__` | A readable summary with status, version and uptime |
| `/__version__` | Name, version and platform |

Point your load balancer, Kubernetes probes or uptime monitor at `/__live__` and `/__ready__`. The Docker image has no shell, so it has no built-in health check and relies on these.

## Metrics

Prometheus can scrape `/__metrics__` (also available as `/metrics`). The series have no labels, and their names and types are stable, so you can build dashboards and alerts on them.

| Series | Type | Meaning |
| :--- | :--- | :--- |
| `blazeserve_uptime_seconds` | gauge | Time since the server started |
| `blazeserve_bytes_sent_total` | counter | Bytes of response bodies actually written |
| `blazeserve_bytes_received_total` | counter | Bytes of upload bodies accepted |
| `blazeserve_requests_total` | counter | Requests handled. Two requests on one connection count twice |
| `blazeserve_requests_active` | gauge | Requests being handled right now |
| `blazeserve_errors_total` | counter | Unexpected server failures. A client hanging up is not an error |
| `blazeserve_connections_active` | gauge | Connections currently admitted |
| `blazeserve_connections_rejected_total` | counter | Connections turned away at `--max-connections` |

Byte counters count what was really sent or received, not what was promised, so a cancelled download only counts the part that went out.

Two simpler views exist for quick checks: `/__stats__` for bytes sent, and `/__perf__` for the effective limits and counters.

Keep the metrics address away from untrusted networks. The `deploy/monitoring/` folder has a Prometheus scrape config, alert rules and a Grafana dashboard. See [deploy/README.md](../deploy/README.md#monitoring).

## Logs

Normal output is readable text. For machines, switch to JSON:

```bash
blaze serve ./site --log-json
```

You can also set `BLAZE_LOG_JSON=1`. Each request becomes one JSON line on standard output with these fields: `timestamp` (UTC), `level`, `request_id`, `client_ip`, `peer_ip`, `request`, `status` and `size`. When tracing is on there are also `trace_id` and `span_id`.

`client_ip` is the visitor as BlazeServe understands them, taking trusted proxies into account. `peer_ip` is whoever actually connected to the socket. In JSON mode, human-readable messages go to standard error so the output stays clean for tools.

Every response carries an `X-Request-ID`. If a client sends one, BlazeServe echoes it when it is 1 to 64 letters, digits or hyphens. Otherwise it makes up a 12-character one. This lets you match a user's report to a log line.

BlazeServe never logs passwords, `Authorization` headers, credentials in URLs, TLS keys or file contents.

## OpenTelemetry

BlazeServe can send traces (one per request) and metrics to any OpenTelemetry collector or hosted service over OTLP/HTTP. It stays off until you set an endpoint:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT='https://otlp.example.com'
export OTEL_EXPORTER_OTLP_PROTOCOL='http/protobuf'
export OTEL_EXPORTER_OTLP_HEADERS='Authorization=Basic <your-token>'
export OTEL_SERVICE_NAME='blazeserve'
blaze serve ./site
```

On Windows PowerShell, use `$env:NAME = "value"` instead of `export`. You can also pass `--otlp-endpoint`.

The headers usually contain a secret token. Keep it in the environment or a secret store, never in a command line, a committed file or a log.

Only the `http/protobuf` protocol is supported. If the collector is unreachable, requests are not slowed down, and on shutdown BlazeServe waits at most five seconds for pending data to be sent.

The OpenTelemetry metrics use the standard `http.server.*` names, such as `http.server.request.duration`, plus `blazeserve.connections.rejected`. They are separate from the `blazeserve_*` Prometheus series above.

To try this on your own machine, `docker compose --profile observability up -d` starts a local Grafana at `http://localhost:3000` that accepts OTLP on port 4318.
