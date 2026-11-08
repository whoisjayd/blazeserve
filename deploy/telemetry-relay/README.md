# Telemetry relay

This is a small Cloudflare Worker. It receives BlazeServe's anonymous usage reports, checks them against a strict list of allowed fields, and passes them on to a metrics backend. It exists so the backend password stays on a server. The released program only knows this Worker's public address.

You only need this if you publish your own build of BlazeServe. For what users see, read the [telemetry guide](../../docs/telemetry.md).

## What it does and does not do

- It accepts `POST /v1/event` only, with a body of at most 2 KB.
- It rejects any field that is not on the list, any value outside the allowed sets, and any extra or missing key. The list lives in `worker.js` and mirrors `src/usage/payload.rs`.
- It never stores the sender's address or user agent. The address is used for a moment to rate-limit and is then dropped. Only the attributes below are forwarded.
- It does not use an install identifier, because the program does not send one.
- It answers `204` on success, `400` for an invalid report, `413` if too large, `429` if rate limited, `502` if the backend fails, and `503` if the Worker is not configured.

## What it writes

One OpenTelemetry log record per report, sent to `/v1/logs`. Each record has the attributes `event`, `version`, `os`, `arch`, `command`, `install_channel` and a `feature.<name>` yes or no value for each feature. Stop reports add `uptime_bucket`, `requests_bucket`, `bytes_sent_bucket` and `had_errors`. Because each report is its own record, the Worker keeps no counters.

Logs are used because a Worker with no memory between requests cannot keep the running totals that cumulative counters need, and Grafana Cloud does not accept delta counters. In Grafana, query the Loki data source, for example `sum by (os) (count_over_time({service_name="blazeserve-usage"}[24h]))`. The access token needs the `logs:write` scope.

## Deploy it

You need a Cloudflare account and Node.js.

1. Edit `wrangler.toml` and set `OTLP_ENDPOINT` to your backend's OTLP base address, without `/v1/logs`. Replace the `<region>` placeholder.
2. Log in and store the credential as a Worker secret. The value is the whole `Authorization` header your backend expects, for example `Basic <base64 of instanceID:token>`. Paste it at the prompt, and never put it in a file or on a command line.

   ```console
   npx wrangler login
   npx wrangler secret put OTLP_AUTH
   npx wrangler deploy
   ```

3. Note the address Wrangler prints, for example `https://blazeserve-telemetry-relay.<account>.workers.dev`.
4. Build release binaries with that address built in.

   Linux and macOS:

   ```console
   BLAZE_TELEMETRY_URL=https://blazeserve-telemetry-relay.example.workers.dev cargo build --release
   ```

   Windows PowerShell:

   ```powershell
   $env:BLAZE_TELEMETRY_URL = 'https://blazeserve-telemetry-relay.example.workers.dev'
   cargo build --release
   ```

   A build without this variable never sends anything. Users can still override it at run time with the same variable.

The `ratelimit` binding in `wrangler.toml` allows 20 reports per minute per address. If you remove it, the Worker falls back to a counter that resets whenever Cloudflare recycles the Worker, which is a weaker limit.

## Check that it works

Replace the address with yours. A valid report returns `204`.

Linux and macOS:

```console
URL=https://blazeserve-telemetry-relay.example.workers.dev/v1/event
BODY='{"schema_version":1,"event":"start","version":"1.0.0","os":"linux","arch":"x86_64","command":"serve","install_channel":"unknown","features":{"tls":false,"auth":false,"uploads_enabled":false,"rate_limit":false,"cors":false,"trust_proxy":false,"otlp":false,"single_file":false,"listing":true}}'
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'content-type: application/json' -d "$BODY" "$URL"
curl -s -o /dev/null -w '%{http_code}\n' -X POST -d '{"path":"/home/x"}' "$URL"
curl -s -o /dev/null -w '%{http_code}\n' "$URL"
```

Windows PowerShell:

```powershell
$url = 'https://blazeserve-telemetry-relay.example.workers.dev/v1/event'
$body = '{"schema_version":1,"event":"start","version":"1.0.0","os":"linux","arch":"x86_64","command":"serve","install_channel":"unknown","features":{"tls":false,"auth":false,"uploads_enabled":false,"rate_limit":false,"cors":false,"trust_proxy":false,"otlp":false,"single_file":false,"listing":true}}'
curl.exe -s -o NUL -w '%{http_code}`n' -X POST -H 'content-type: application/json' -d $body $url
curl.exe -s -o NUL -w '%{http_code}`n' -X POST -d '{"path":"/home/x"}' $url
curl.exe -s -o NUL -w '%{http_code}`n' $url
```

You should see `204`, then `400` for the extra field, then `405` for the GET.

## Test it locally

You only need Node.js 20 or newer:

```console
node --test deploy/telemetry-relay/worker.test.mjs
```

The Rust tests also fail if the allowed values in `worker.js` drift away from `src/usage/payload.rs`.
