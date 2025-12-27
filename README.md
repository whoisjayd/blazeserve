# BlazeServe

⚡ **Ultra-fast**, dependable HTTP file server for sharing files and folders. Optimized for maximum throughput with platform-specific TCP optimizations, multiple I/O fast paths, and efficient resource management.

## Features

- **High Performance**: Optimized buffers (128MB send, 256MB chunks), zero-copy sendfile, memory-mapped I/O
- **Platform Optimizations**: SO_REUSEPORT, TCP_QUICKACK, TCP_NODELAY for maximum speed
- Static file serving over HTTP/1.1 with strong ETag, Last-Modified, and If-Range
- Range and multi-range responses
- Zero-copy sendfile fast path, windowed mmap, and buffered fallback
- Per-connection rate limiting with token bucket algorithm
- **Performance Monitoring**: Real-time metrics via `/__perf__` endpoint
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
  --chunk-mb INTEGER               mmap/read window size. [4..4096] [default: 256]
  --sock-sndbuf-mb INTEGER         SO_SNDBUF (MB). [1..2048] [default: 128]
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
  --backlog INTEGER                Listen backlog. [default: 8192]
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
- `GET /__stats__` -> `{"bytes_sent": <int>}` (legacy endpoint)
- `GET /__perf__` -> enhanced performance metrics with config and throughput stats
- `GET /__speed__?bytes=104857600` -> streams zeros for client speed testing
- `GET /__zip__?path=relative/or/absolute/path` -> streams a ZIP (uncompressed for speed)
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

## Performance Tuning

BlazeServe is optimized for high-speed file transfers with sensible defaults. For maximum performance:

### Network Optimization

The default settings are optimized for modern networks:
- **Send buffer**: 128MB (configurable with `--sock-sndbuf-mb`)
- **Chunk size**: 256MB (configurable with `--chunk-mb`)
- **Connection backlog**: 8192 (configurable with `--backlog`)

### Platform-Specific Features

BlazeServe automatically enables platform-specific TCP optimizations:
- **Linux**: SO_REUSEPORT for multi-core load balancing, TCP_QUICKACK for faster ACKs
- **All platforms**: TCP_NODELAY to disable Nagle's algorithm for lower latency

### Fast Paths

BlazeServe uses multiple optimization strategies:
1. **Zero-copy sendfile**: For full file transfers without rate limiting
2. **Memory-mapped I/O**: For windowed reads with minimal memory overhead
3. **Buffered fallback**: Compatible path for all scenarios

### Rate Limiting

When using `--rate-mbps`, a token bucket algorithm provides smooth throttling with burst capacity:
```bash
blaze serve . --rate-mbps 100  # Limit to 100 MB/s with 2-second burst allowance
```

### Monitoring Performance

Check real-time server metrics:
```bash
curl http://localhost:8000/__perf__
```

This returns detailed statistics including:
- Uptime and throughput
- Current configuration
- Bytes sent/received
- Active requests

### Tips for Maximum Speed

1. **LAN Transfers**: Disable rate limiting for local network transfers
   ```bash
   blaze serve . --chunk-mb 512 --sock-sndbuf-mb 256
   ```

2. **Internet Sharing**: Use rate limiting to prevent bandwidth saturation
   ```bash
   blaze serve . --rate-mbps 50
   ```

3. **Multiple Clients**: The server uses SO_REUSEPORT on Linux for multi-core scaling

4. **Direct Connections**: For maximum speed between two machines on the same network:
   - Connect both to the same WiFi/LAN
   - Server shows its LAN IP on startup
   - Client connects directly to that IP (no internet routing)

## Notes

- If `--no-cache` is set, responses use `Cache-Control: no-store`.
- Precompressed `.gz` files are served only for non-range requests to keep range semantics correct.
- In single-file mode, listing is disabled and the fast path is favored.
- ZIP downloads use uncompressed storage (ZIP_STORED) for maximum speed by default.

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
