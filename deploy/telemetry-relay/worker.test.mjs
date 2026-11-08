import assert from "node:assert/strict";
import { test } from "node:test";
import worker, { toOtlp, validate } from "./worker.js";

const features = {
  tls: false,
  auth: false,
  uploads_enabled: false,
  rate_limit: false,
  cors: false,
  trust_proxy: false,
  otlp: false,
  single_file: false,
  listing: true,
};
const start = {
  schema_version: 1,
  event: "start",
  version: "1.0.0",
  os: "linux",
  arch: "x86_64",
  command: "serve",
  install_channel: "pip",
  features,
};
const stop = {
  ...start,
  event: "stop",
  uptime_bucket: "1-10m",
  requests_bucket: "10-99",
  bytes_sent_bucket: "1-10GiB",
  had_errors: false,
};
const env = { OTLP_ENDPOINT: "https://otlp.example/otlp", OTLP_AUTH: "Basic placeholder" };

let counter = 0;
const post = (body, headers) =>
  new Request("https://relay.test/v1/event", {
    method: "POST",
    headers: headers ?? { "cf-connecting-ip": `203.0.113.${(counter += 1) % 250}` },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

test("valid events pass validation", () => {
  assert.equal(validate(start), null);
  assert.equal(validate(stop), null);
});

test("extra, missing and malformed fields are rejected", () => {
  assert.notEqual(validate({ ...start, path: "/home/x" }), null);
  assert.notEqual(validate({ ...start, uptime_bucket: "1-10m" }), null);
  const { features: _omitted, ...noFeatures } = start;
  assert.notEqual(validate(noFeatures), null);
  assert.notEqual(validate({ ...start, os: "plan9" }), null);
  assert.notEqual(validate({ ...start, version: "1.0.0\n" }), null);
  assert.notEqual(validate({ ...start, features: { ...features, extra: true } }), null);
  assert.notEqual(validate({ ...start, features: { ...features, tls: "yes" } }), null);
  assert.notEqual(validate({ ...stop, had_errors: 0 }), null);
  assert.notEqual(validate([]), null);
});

test("otlp conversion carries no identifiers", () => {
  const payload = JSON.stringify(toOtlp(stop, 1700000000000));
  assert.match(payload, /usage stop/);
  assert.match(payload, /bytes_sent_bucket/);
  assert.doesNotMatch(payload, /203\.0\.113|install_id/);
});

test("accepts a valid event, forwards it, and returns 204", async () => {
  const seen = [];
  globalThis.fetch = async (url, init) => {
    seen.push({ url, init });
    return new Response("{}", { status: 200 });
  };
  const res = await worker.fetch(post(start), env);
  assert.equal(res.status, 204);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, "https://otlp.example/otlp/v1/logs");
  assert.equal(seen[0].init.headers.authorization, "Basic placeholder");
  assert.deepEqual(Object.keys(seen[0].init.headers).sort(), ["authorization", "content-type"]);
});

test("rejects bad routes, methods, size and json", async () => {
  globalThis.fetch = async () => assert.fail("must not forward");
  assert.equal((await worker.fetch(new Request("https://relay.test/other"), env)).status, 404);
  assert.equal((await worker.fetch(new Request("https://relay.test/v1/event"), env)).status, 405);
  assert.equal((await worker.fetch(post("x".repeat(3000)), env)).status, 413);
  assert.equal((await worker.fetch(post("{not json"), env)).status, 400);
  assert.equal((await worker.fetch(post({ ...start, extra: 1 }), env)).status, 400);
});

test("upstream failure and missing config are not reported as success", async () => {
  globalThis.fetch = async () => new Response("no", { status: 500 });
  assert.equal((await worker.fetch(post(start), env)).status, 502);
  globalThis.fetch = async () => {
    throw new Error("network");
  };
  assert.equal((await worker.fetch(post(start), env)).status, 502);
  assert.equal((await worker.fetch(post(start), {})).status, 503);
});

test("the fallback limiter throttles one address", async () => {
  globalThis.fetch = async () => new Response("{}", { status: 200 });
  const same = { "cf-connecting-ip": "198.51.100.7" };
  let limited = 0;
  for (let i = 0; i < 30; i += 1) {
    if ((await worker.fetch(post(start, same), env)).status === 429) limited += 1;
  }
  assert.ok(limited >= 10);
});
