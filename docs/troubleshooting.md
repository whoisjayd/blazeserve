# Troubleshooting

When something does not work, start with this:

```bash
blaze doctor ./site --port 8000
```

It checks the folder, the port and what your system supports, and exits with code 1 if something is wrong. Add `--json` for output a script can read.

## The server will not start

**The port is taken.** Another program is using port 8000. Pick another with `--port`, or stop the other program. `doctor` reports this.

**It complains about `--auth-env`.** The environment variable you named is not set, or it is empty. BlazeServe refuses to start rather than run without a password. Set it as `USER:PASS`, and in PowerShell remember that `$env:BLAZE_AUTH = "alice:s3cret"` only lasts for that window.

**It complains about the certificate.** `--tls-cert` and `--tls-key` must be given together, and both must be PEM files.

## I cannot reach the server

- From another computer: check the firewall on the machine running BlazeServe. If you started it with `--host 127.0.0.1`, only that machine can connect. The default for `blaze serve` is every interface.
- From Python: `blazeserve.Server` listens on loopback by default. Pass `host="0.0.0.0"` if you want it reachable from the network.
- With HTTPS: use `https://` in the address. A browser will warn about a self-signed certificate.

## A file shows `404 Not Found`

Check these in order:

1. Is the name spelled correctly, including capital letters on Linux?
2. Does a `--hide` pattern match it? Hidden files answer `404` as if they did not exist.
3. Is it a symbolic link that points outside the served folder? Those are refused on purpose.

## I get `401 Unauthorized`

The server wants a password and did not receive a valid one. In a browser, enter it when prompted. With `blaze get` or `blaze put`, use `--auth-env` or `--auth`.

## Uploads do not work

- Uploads are off until you start the server with `--max-upload-mb` set above zero.
- `409 Conflict` means the file already exists. Uploads never overwrite by accident.
- `412 Precondition Failed` means you tried to replace a file with an out-of-date `If-Match` tag. Fetch the file's current `ETag` and try again.
- `413` means the upload is bigger than `--max-upload-mb`.
- In the example Docker, Compose and Kubernetes files, the data folder is mounted read-only. Mount a writable volume to receive files. See [Uploads](uploads.md).

## Downloads start over instead of resuming, or use only one connection

`blaze get` can only resume or split a file when the server supports byte ranges and gives the file a stable identity (an `ETag` or `Last-Modified`). Some servers and proxies do not. BlazeServe then falls back to a single stream, and if the file changed on the server, it starts over so that you never end up with a mix of versions. Files under 8 MiB are always fetched in a single stream.

## Clients get `503` or `429`

`503` with a retry hint means the server is at `--max-connections`. If this is normal traffic, raise the limit. `429` on HTTP/2 means one connection opened new requests faster than 128 per second after its initial burst of 256. Well-behaved clients do not hit this.

## Downloads through a proxy are slow or use a lot of disk

Your proxy is probably buffering. Turn buffering off: `proxy_buffering off;` and `proxy_request_buffering off;` in Nginx, and `flush_interval -1` in Caddy. The example configurations in `deploy/reverse-proxy/` already do this.

## Logs show the proxy's address for every visitor

BlazeServe has to be told which proxy to trust: `--trust-proxy 127.0.0.1/32`, or the address of your proxy. See [Serving files](serving-files.md#behind-a-reverse-proxy).

## A renewed certificate is not used

Certificates are read when the server starts. Restart it after renewing.

## Still stuck?

Search the [issues](https://github.com/whoisjayd/blazeserve/issues), and if you do not find an answer, open a new one with the version (`blaze version`), your operating system, and the command you ran. Remove any passwords or tokens first. For security problems, use the private route in [SECURITY.md](../SECURITY.md).
