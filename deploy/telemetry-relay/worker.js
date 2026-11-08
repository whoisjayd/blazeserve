const MAX_BODY_BYTES = 2048;
const RATE_PER_MINUTE = 20;
const UPSTREAM_TIMEOUT_MS = 8000;
const RETRY_DELAY_MS = 250;

const ENUMS = {
  event: ["start", "stop"],
  os: ["windows", "linux", "macos", "other"],
  arch: ["x86_64", "aarch64", "other"],
  command: ["serve", "send"],
  install_channel: ["pip", "cargo", "docker", "binary", "unknown"],
  uptime_bucket: ["<1m", "1-10m", "10-60m", "1-24h", ">24h"],
  requests_bucket: ["0", "1-9", "10-99", "100-999", "1k-9k", "10k-99k", "100k-999k", "1M+"],
  bytes_sent_bucket: [
    "0",
    "<1MiB",
    "1-10MiB",
    "10-100MiB",
    "100MiB-1GiB",
    "1-10GiB",
    "10-100GiB",
    ">100GiB",
  ],
};

const FEATURE_KEYS = [
  "tls",
  "auth",
  "uploads_enabled",
  "rate_limit",
  "cors",
  "trust_proxy",
  "otlp",
  "single_file",
  "listing",
];
const COMMON_KEYS = [
  "schema_version",
  "event",
  "version",
  "os",
  "arch",
  "command",
  "install_channel",
  "features",
];
const STOP_KEYS = ["uptime_bucket", "requests_bucket", "bytes_sent_bucket", "had_errors"];
const VERSION_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}(-[0-9A-Za-z.]{1,16})?$/;

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

export function validate(event) {
  if (!isPlainObject(event)) return "body must be an object";
  const stop = event.event === "stop";
  const allowed = new Set(stop ? [...COMMON_KEYS, ...STOP_KEYS] : COMMON_KEYS);
  for (const key of Object.keys(event)) {
    if (!allowed.has(key)) return `unexpected field: ${key.slice(0, 32)}`;
  }
  for (const key of allowed) {
    if (!(key in event)) return `missing field: ${key}`;
  }
  if (event.schema_version !== 1) return "unsupported schema_version";
  if (typeof event.version !== "string" || !VERSION_RE.test(event.version)) {
    return "invalid version";
  }
  for (const [key, values] of Object.entries(ENUMS)) {
    if (key in event && !values.includes(event[key])) return `invalid ${key}`;
  }
  if (!isPlainObject(event.features)) return "features must be an object";
  if (Object.keys(event.features).length !== FEATURE_KEYS.length) return "invalid features";
  for (const key of FEATURE_KEYS) {
    if (typeof event.features[key] !== "boolean") return `invalid feature: ${key}`;
  }
  if (stop && typeof event.had_errors !== "boolean") return "invalid had_errors";
  return null;
}

const str = (key, value) => ({ key, value: { stringValue: value } });
const bool = (key, value) => ({ key, value: { boolValue: value } });

export function toOtlp(event, nowMs = Date.now()) {
  const nowNano = String(BigInt(nowMs) * 1000000n);
  const attributes = [
    str("event", event.event),
    str("version", event.version),
    str("os", event.os),
    str("arch", event.arch),
    str("command", event.command),
    str("install_channel", event.install_channel),
    ...FEATURE_KEYS.map((k) => bool(`feature.${k}`, event.features[k])),
  ];
  if (event.event === "stop") {
    attributes.push(
      str("uptime_bucket", event.uptime_bucket),
      str("requests_bucket", event.requests_bucket),
      str("bytes_sent_bucket", event.bytes_sent_bucket),
      bool("had_errors", event.had_errors),
    );
  }
  return {
    resourceLogs: [
      {
        resource: { attributes: [str("service.name", "blazeserve-usage")] },
        scopeLogs: [
          {
            scope: { name: "blazeserve.relay" },
            logRecords: [
              {
                timeUnixNano: nowNano,
                observedTimeUnixNano: nowNano,
                severityNumber: 9,
                severityText: "INFO",
                body: { stringValue: `usage ${event.event}` },
                attributes,
              },
            ],
          },
        ],
      },
    ],
  };
}

const unquote = (value) => String(value ?? "").trim().replace(/^["']+|["']+$/g, "").trim();

// Accepts the header value in the shapes people actually paste: the full "Basic <base64>",
// "Authorization=Basic <base64>" as printed by the Grafana setup page, or the bare base64.
export function normalizeAuth(raw) {
  let value = unquote(raw).replace(/^authorization\s*[=:]\s*/i, "").trim();
  if (/^(basic|bearer)\s+\S/i.test(value)) return value;
  if (/^[A-Za-z0-9+/]+=*$/.test(value)) value = `Basic ${value}`;
  return value;
}

// Accepts the OTLP base address with or without a scheme, a trailing slash, a signal path
// such as /v1/logs, or a missing /otlp on a Grafana Cloud gateway.
export function normalizeEndpoint(raw) {
  let value = unquote(raw);
  if (!value) return "";
  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
  value = value.replace(/\/+$/, "").replace(/\/v1\/(logs|traces|metrics)$/i, "");
  try {
    const url = new URL(value);
    if (url.hostname.endsWith(".grafana.net") && (url.pathname === "/" || url.pathname === "")) {
      return `${url.origin}/otlp`;
    }
  } catch {
    return "";
  }
  return value;
}

// Best-effort fallback for when the Workers rate limiting binding is not configured.
// State is per isolate and resets on eviction.
const windows = new Map();
function localLimit(key, now) {
  const minute = Math.floor(now / 60000);
  const entry = windows.get(key);
  if (!entry || entry.minute !== minute) {
    if (windows.size > 5000) windows.clear();
    windows.set(key, { minute, count: 1 });
    return true;
  }
  entry.count += 1;
  return entry.count <= RATE_PER_MINUTE;
}

async function allowed(request, env) {
  // The address is only a transient rate-limit key. It is never stored or forwarded.
  const key = request.headers.get("cf-connecting-ip") || "unknown";
  if (env.RATE_LIMITER && typeof env.RATE_LIMITER.limit === "function") {
    const { success } = await env.RATE_LIMITER.limit({ key });
    return success;
  }
  return localLimit(key, Date.now());
}

const reply = (status, extra = {}) =>
  new Response(null, { status, headers: { "cache-control": "no-store", ...extra } });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function attempt(url, auth, payload) {
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: auth },
      body: payload,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
    if (response.ok) return { ok: true, status: response.status, detail: "" };
    const detail = (await response.text().catch(() => "")).slice(0, 300);
    return { ok: false, status: response.status, detail };
  } catch (error) {
    return { ok: false, status: 0, detail: String(error?.message ?? error).slice(0, 200) };
  }
}

// Retries once for a network failure, a timeout, a rate limit or a server error. A rejected
// credential (401, 403) or a bad request is final. Only the status and the backend's own
// error text are logged, never the Authorization value.
async function forward(event, endpoint, auth) {
  const url = `${endpoint}/v1/logs`;
  const payload = JSON.stringify(toOtlp(event));
  let result = await attempt(url, auth, payload);
  if (!result.ok && (result.status === 0 || result.status === 429 || result.status >= 500)) {
    await sleep(RETRY_DELAY_MS);
    result = await attempt(url, auth, payload);
  }
  if (!result.ok) {
    console.error(
      `relay: backend refused ${event.event} report: status=${result.status} ${result.detail}`,
    );
  }
  return result;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname !== "/v1/event") return reply(404);
    if (request.method !== "POST") return reply(405);
    if (!(await allowed(request, env))) return reply(429);

    const declared = Number(request.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return reply(413);
    const text = await request.text();
    if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) return reply(413);

    let event;
    try {
      event = JSON.parse(text);
    } catch {
      return reply(400);
    }
    if (validate(event) !== null) return reply(400);

    const endpoint = normalizeEndpoint(env.OTLP_ENDPOINT);
    const auth = normalizeAuth(env.OTLP_AUTH);
    if (!endpoint || !auth) {
      console.error("relay: OTLP_ENDPOINT or OTLP_AUTH is missing or empty");
      return reply(503);
    }

    // The client may hang up before the backend answers. waitUntil lets the forward finish anyway.
    const forwarded = forward(event, endpoint, auth);
    ctx?.waitUntil?.(forwarded);
    const result = await forwarded;
    return result.ok ? reply(204) : reply(502, { "x-upstream-status": String(result.status) });
  },
};
