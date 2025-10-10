# BlazeServe

Fast, dependable HTTP file server for sharing files and folders. Supports byte-range and multi-range downloads, TLS, Basic Auth, throttling, uploads, streaming ZIP, optional CORS, and a modern, colorful CLI.

## Features

- Static file serving over HTTP/1.1 with strong ETag, Last-Modified, and If-Range
- Range and multi-range responses
- Zero-copy sendfile fast path, windowed mmap, and buffered fallback
- Per-connection rate limiting
- Optional directory listing with automatic index.html
- One-file mode for quick shares
- Streaming ZIP for files or directories (`/__zip__?path=...`)
- Uploads via `PUT`/`POST /__upload__/path/to/file`
- Simple stats (`/__stats__`), health check (`/__health__`), and speed test (`/__speed__?bytes=...`)
- Optional CORS (including preflight OPTIONS)
- Optional cache disable
- Optional serving of precompressed `.gz` assets when safe
- TLS (PEM cert and key)
- Rich CLI built on click and rich-click
- Cross-platform (Linux/macOS/Windows), Python 3.9+

## Install

```bash
pip install blazeserve
```

## Quick start

```bash
blaze serve .
```

Open your browser to:

- Local: `http://localhost:8000/`
- LAN: shown in the startup banner

## CLI

### `serve`

```
blaze serve [PATH]

Options:
  --host TEXT                      Bind address. [default: 0.0.0.0]
  -p, --port INTEGER               Port. [default: 8000]
  --single PATH                    Serve exactly this file.
  --no-listing                     Disable directory listing.
  --chunk-mb INTEGER               mmap/read window size. [4..4096] [default: 128]
  --sock-sndbuf-mb INTEGER         SO_SNDBUF (MB). [1..2048] [default: 64]
  --timeout INTEGER                Per-connection timeout (s). [60..86400]
  --rate-mbps FLOAT                Throttle to MB/s.
  --auth USER:PASS                 Enable HTTP Basic Auth.
  --auth-env NAME                  Read USER:PASS from env var NAME.
  --tls-cert PATH                  TLS certificate (PEM).
  --tls-key PATH                   TLS private key (PEM).
  --cors / --no-cors               Enable CORS. [default: no-cors]
  --cors-origin TEXT               CORS allow origin. [default: *]
  --no-cache                       Disable HTTP caching.
  --index TEXT                     Extra index filenames (repeatable).
  --backlog INTEGER                Listen backlog. [default: 4096]
  --precompress / --no-precompress Serve .gz when safe. [default: precompress]
  --max-upload-mb INTEGER          Max upload size (0 = unlimited). [default: 0]
  --open                           Open the URL in a browser at start.
  -v, --verbose                    Verbose startup banner.
  -h, --help                       Show help.
```

### `send`

```
blaze send FILE

Options:
  --host TEXT
  -p, --port INTEGER
  --rate-mbps FLOAT
  --auth USER:PASS
  --auth-env NAME
  --tls-cert PATH
  --tls-key PATH
  --cors / --no-cors
  --cors-origin TEXT
  --no-cache
  --backlog INTEGER
  --precompress / --no-precompress
  --max-upload-mb INTEGER
```

### Other commands

```
blaze checksum [FILES...]     Print SHA256 checksums.
blaze version                 Show version.
```

## Endpoints

- `GET /__health__` -> `{"status":"ok"}`
- `GET /__stats__` -> `{"bytes_sent": <int>}`
- `GET /__speed__?bytes=104857600` -> streams zeros for client speed testing
- `GET /__zip__?path=relative/or/absolute/path` -> streams a ZIP
- `PUT|POST /__upload__/path/to/file` -> saves request body to disk (requires Content-Length)

## Examples

Share a directory on port 8080 with CORS:

```bash
blaze serve /srv/files -p 8080 --cors --cors-origin https://example.com
```

Serve one file over TLS:

```bash
blaze serve --single ./movie.mp4 --tls-cert cert.pem --tls-key key.pem
```

Limit download rate to 200 MB/s:

```bash
blaze serve . --rate-mbps 200
```

Upload a file:

```bash
curl -T ./big.iso http://host:8000/__upload__/uploads/big.iso
```

Stream a zip of a folder:

```bash
curl -L "http://host:8000/__zip__?path=./photos" -o photos.zip
```

## Auth

Enable Basic Auth:

```bash
blaze serve . --auth user:pass
# or from env
export BLAZE_AUTH=user:pass
blaze serve . --auth-env BLAZE_AUTH
```

## Notes

- If `--no-cache` is set, responses use `Cache-Control: no-store`.
- Precompressed `.gz` files are served only for non-range requests to keep range semantics correct.
- In single-file mode, listing is disabled and the fast path is favored.

## Systemd

```
[Unit]
Description=BlazeServe
After=network.target

[Service]
ExecStart=/usr/bin/blaze serve /srv/downloads --port 8080 --rate-mbps 200 --cors
Restart=on-failure
User=www-data
Group=www-data
WorkingDirectory=/srv/downloads

[Install]
WantedBy=multi-user.target
```

## Docker

```
FROM python:3.12-slim
RUN pip install --no-cache-dir blazeserve
WORKDIR /data
EXPOSE 8000
CMD ["blaze", "serve", ".", "--host", "0.0.0.0", "--port", "8000"]
```

## License

MIT. See [LICENSE](./LICENSE).
