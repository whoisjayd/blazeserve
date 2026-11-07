# Telemetry relay

A small Cloudflare Worker that receives BlazeServe's anonymous usage events, validates them
against a strict allowlist, and forwards them to an OTLP/HTTP logs endpoint. It exists so
the backend credential stays on the server: the released binary only knows this Worker's
public URL.

What it does and does not do:

- Accepts `POST /v1/event` only, with a body of at most 2 KB.
- Rejects any field outside the allowlist, any value outside the enumerated sets, and any
  extra or missing key. The allowlist lives in `worker.js` and mirrors `src/usage/payload.rs`.
- Never stores the client address or user agent. The address is used for a moment as the
  rate-limit key and then dropped. Only the attributes below are forwarded.
- Does not use or forward an install identifier. The client does not send one.
- Returns `204` on success, `400` invalid, `413` too large, `429` rate limited, `502` backend
  failure and `503` when the Worker is not configured.

## What it writes

One OTLP log record per event, sent to `/v1/logs`. Each record has the attributes `event`,
`version`, `os`, `arch`, `command`, `install_channel` and a `feature.<name>` boolean for each
feature. Stop events add `uptime_bucket`, `requests_bucket`, `bytes_sent_bucket` and
`had_errors`. Records are individual events, so the Worker holds no counter state.

Logs are used because a stateless Worker cannot keep the running total that cumulative
counters need, and Grafana Cloud rejects delta counters. In Grafana, query the Loki data
source, for example `sum by (os) (count_over_time({service_name="blazeserve-usage"}[24h]))`.
The access policy token needs the `logs:write` scope.

## Deploy

You need a Cloudflare account and Node.js.

1. Edit `wrangler.toml` and set `OTLP_ENDPOINT` to your backend's OTLP base URL, without
   `/v1/logs`. Replace the `<region>` placeholder.
2. Log in and set the credential as a Worker secret. The value is the whole `Authorization`
   header your backend expects, for example `Basic <base64 of instanceID:token>`. Paste it at
   the prompt. Never put it in a file or on a command line.

   ```console
   npx wrangler login
   npx wrangler secret put OTLP_AUTH
   npx wrangler deploy
   ```

3. Note the URL Wrangler prints, for example `https://blazeserve-telemetry-relay.<account>.workers.dev`.
4. Build release binaries with that URL baked in:

   POSIX shell:

   ```console
   BLAZE_TELEMETRY_URL=https://blazeserve-telemetry-relay.example.workers.dev cargo build --release
   ```

   PowerShell:

   ```powershell
   $env:BLAZE_TELEMETRY_URL = 'https://blazeserve-telemetry-relay.example.workers.dev'
   cargo build --release
   ```

   A build without this variable is inert: it never sends anything. Users can still override
   it at run time with the same variable.

The `ratelimit` binding in `wrangler.toml` allows 20 events per minute per address. If you
remove it, the Worker falls back to a per-isolate counter that resets whenever the isolate is
evicted, which is a weaker limit.

## Check it

Replace the URL with yours. A valid event returns `204`.

POSIX shell:

```console
URL=https://blazeserve-telemetry-relay.example.workers.dev/v1/event
BODY='{"schema_version":1,"event":"start","version":"1.0.0","os":"linux","arch":"x86_64","command":"serve","install_channel":"unknown","features":{"tls":false,"auth":false,"uploads_enabled":false,"rate_limit":false,"cors":false,"trust_proxy":false,"otlp":false,"single_file":false,"listing":true}}'
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'content-type: application/json' -d "$BODY" "$URL"
curl -s -o /dev/null -w '%{http_code}\n' -X POST -d '{"path":"/home/x"}' "$URL"
curl -s -o /dev/null -w '%{http_code}\n' "$URL"
```

PowerShell:

```powershell
$url = 'https://blazeserve-telemetry-relay.example.workers.dev/v1/event'
$body = '{"schema_version":1,"event":"start","version":"1.0.0","os":"linux","arch":"x86_64","command":"serve","install_channel":"unknown","features":{"tls":false,"auth":false,"uploads_enabled":false,"rate_limit":false,"cors":false,"trust_proxy":false,"otlp":false,"single_file":false,"listing":true}}'
curl.exe -s -o NUL -w '%{http_code}`n' -X POST -H 'content-type: application/json' -d $body $url
curl.exe -s -o NUL -w '%{http_code}`n' -X POST -d '{"path":"/home/x"}' $url
curl.exe -s -o NUL -w '%{http_code}`n' $url
```

Expected: `204`, then `400` for the extra field, then `405` for the GET.

## Test locally

No dependencies are needed beyond Node.js 20 or newer:

```console
node --test deploy/telemetry-relay/worker.test.mjs
```

The Rust test suite also fails if the allowed values in `worker.js` drift from `src/usage/payload.rs`.
