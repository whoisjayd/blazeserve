# Serving files

This guide goes through the options you are likely to use when running `blaze serve` for other people. The full list of options is in the [reference](reference.md).

## What is served

```bash
blaze serve ./site
```

Everything inside `./site` is available, including subfolders. Browsers get a listing for folders, and scripts can ask for the same listing as JSON by sending `Accept: application/json`. Add `?download=1` to a file address to make browsers save it instead of showing it.

A few variations:

| You want | Use |
| :--- | :--- |
| No folder listing | `--no-listing` |
| Another landing page, such as `home.html` | `--index home.html` (can be repeated) |
| Exactly one file | `--single ./report.pdf`, or `blaze send` |
| A folder download as one ZIP | Open `/__zip__?path=docs`; BlazeServe builds the ZIP as it sends it |

If a file has a compressed copy next to it (`app.js.gz` or `app.js.br`), BlazeServe sends that to browsers that accept it. It never does this for partial downloads. Turn it off with `--no-precompress`.

## Hide files you do not want to share

```bash
blaze serve ./site --hide '*.env' --hide .git --hide 'secrets/**'
```

Hidden entries disappear from listings and ZIP downloads, and asking for one directly gives a `404`. A pattern without a slash matches that name anywhere in the tree, such as `.git` or `*.env`. A pattern with a slash starts at the folder you are serving. Matching ignores upper and lower case on Windows and macOS, and respects it on Linux.

## Require a password

```bash
export BLAZE_AUTH='alice:s3cret'
blaze serve ./site --auth-env BLAZE_AUTH
```

Prefer `--auth-env` over `--auth user:pass`, because command-line arguments are visible to other users on the machine. If you name a variable that is missing or empty, BlazeServe refuses to start. It will never quietly run without a password.

Basic Auth sends the password with every request, so use it together with HTTPS unless you are on a network you trust.

## Use HTTPS

```bash
blaze serve ./site --tls-cert cert.pem --tls-key key.pem
```

You need both files, and BlazeServe stops with an error if only one is given. TLS 1.2 or newer is required. Certificates are read once at startup, so restart the server after renewing one. In production many people let a reverse proxy handle HTTPS instead, which is covered in [deploy/README.md](../deploy/README.md).

HTTP/2 works on the same port, both over HTTPS and as plain HTTP/2 for clients that ask for it directly. If you want HTTP/1.1 only, add `--no-http2`.

## Limit speed

```bash
blaze serve ./site --rate-mbps 25
```

Each client is held to 25 MB/s, so one person cannot use all of your bandwidth.

## Let browsers on other sites use your files

```bash
blaze serve ./site --cors                       # any website may fetch the files
blaze serve ./site --cors --cors-origin https://example.com
```

CORS is off by default.

## Control caching

Browsers are allowed to cache files and are told when a file has changed, using the usual `ETag` and `Last-Modified` headers. Add `--no-cache` while you are developing and always want the latest version.

## Protect the server from overload

You rarely need to change these, but it helps to know they exist.

| Setting | Default | What it does |
| :--- | :--- | :--- |
| `--max-connections` | 1024 | Beyond this, new clients get a `503` that asks them to retry after a second |
| `--header-timeout` | 10 s | A client that is slow to send its request is dropped |
| `--timeout` | 1800 s | Idle connections are closed |
| `--chunk-mb` | 1 | How much of a file is read into memory per active download |

On HTTP/2, one connection may open at most 128 new requests per second after an initial burst of 256. Beyond that it gets `429 Too Many Requests`. This stops a client from flooding the server by opening and cancelling requests in a loop.

## Behind a reverse proxy

If a proxy such as Nginx or Caddy sits in front, every request appears to come from the proxy. Tell BlazeServe which proxy to trust so that logs and speed limits see the real visitor:

```bash
blaze serve /srv/files --host 127.0.0.1 --trust-proxy 127.0.0.1/32
```

You can repeat `--trust-proxy` for several proxies. BlazeServe only believes the forwarding headers when the connection really comes from one of them. Read the proxy section of [deploy/README.md](../deploy/README.md) before relying on this, because it also depends on how the proxy is set up.

## Stopping

`Ctrl+C` works everywhere and `SIGTERM` works on Linux and macOS. BlazeServe stops accepting new connections right away and gives running downloads a short grace period to finish.
