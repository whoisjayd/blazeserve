# Upgrading

Run `blaze upgrade` to move to a newer version; see [Getting started](getting-started.md#keep-it-up-to-date).

## From 1.1 to 2.0

- The default port is now **5949** instead of 8000. Add `--port 8000` to keep the old address, and check proxies, firewall rules and scripts.
- OpenTelemetry export and the bundled monitoring configs were removed: `--otlp-endpoint`, the `OTEL_*` variables and the `trace_id` and `span_id` log fields are gone. `/__metrics__` stays.
- Usage analytics now go to PostHog and say more; the notice is shown again. See [Telemetry](telemetry.md).

New: `blaze` on its own opens a menu; help grouped by task; `blaze info URL`; framed live panels for `get`, `put`, `serve` and `send`; `blaze verify`, `blaze man`, `blaze bug`, `blaze attach` (`fg`); a job dashboard in `blaze status --watch`, where `d` deletes finished jobs; `serve --uploads`; a block map, adaptive connections, `--dry-run`, `--nested` and `--password-env` for `get`; upload verification; `-q`, `--name` and `--progress json` everywhere; install scripts.

## From 1.0 to 1.1

Nothing needs changing for most setups. These behaviours are different:

- **Uploads need hard links.** A new file is published with a hard link so a reader never sees a partial file. On a filesystem that cannot make them, such as some network shares and FAT drives, an upload is now refused with `501` instead of being copied in place.
- **`--hide` covers uploads.** A hidden name answers `404` under `/__upload__/` as well, and in-progress upload files (`.name.blaze-part-...`) are never served, listed or zipped.
- **`blaze get` names the file.** Without `-o`, it uses the name the server suggests in `Content-Disposition`, so a ZIP of a folder is saved as `folder.zip` instead of `__zip__`.
- **More exit codes.** `get` and `put` exit with `3` for a full disk, `4` for a failed integrity check and `5` for refused credentials, where they used to exit with `1`. A script that tested for exactly `1` should test for non-zero. See [exit codes](reference.md#exit-codes).
- **Building from source** needs Rust 1.93 or newer and a C compiler, because archive extraction builds a bundled copy of zstd. The program and the wheels need nothing extra.
- **Python.** `blazeserve.Server` accepts every option of `blaze serve`, every command is a function, and `Ctrl+C` stops a running command. See [Python and Rust](python-and-rust.md).
- **Container image.** It now sets its install channel to `docker`, so the anonymous usage report says so.

New in 1.1: `blaze upgrade`, `--background` with `blaze status` and `blaze stop`, `blaze get --extract` and `--verify server-sha256`, `--connect-timeout`, `--idle-timeout` and `--max-time`, `blaze put --if-match` and `--limit-rate`, `blaze send --expires-after`, `blaze doctor --host`, and up to 128 download connections.

## From 0.x to 1.0

BlazeServe 1.0 is a rewrite in Rust. The command-line options and the web addresses are the same as before, apart from the changes below.

## Things that changed

**The Python API is gone.** Functions and classes such as `create_server`, `run_server`, `BlazeHandler`, `ServerMetrics`, `TokenBucket` and the old argument parser no longer exist. The Python package now carries the program itself. Use `blazeserve.Server` and `blazeserve.main` instead, described in [Python and Rust](python-and-rust.md).

**Uploads are off by default.** In 0.x, `--max-upload-mb 0` meant unlimited uploads with no password required, which was a security flaw. Now `0` means off. To keep uploading, set a positive size and use a password. See [Uploads](uploads.md).

**Uploads are safer.** Files are staged, verified and then published. An existing file is never replaced unless the request carries a matching `If-Match` tag.

**Smaller memory use.** The default transfer chunk is 1 MiB per active download, down from 256 MiB per connection. The default socket send buffer is 4 MiB, down from 128 MiB.

**Paths are decoded once.** `%252e%252e` is now an ordinary file name, not a way to climb out of the folder.

**Connections are bounded.** There is now a limit (`--max-connections`) and a header timeout. 0.x used one unlimited thread per connection and a 30-minute idle timeout.

**Monitoring.** The alert `BlazeServeHighActiveConnections` is now `BlazeServeHighActiveRequests`, matching the metric it actually uses. Two new metrics were added: `blazeserve_connections_active` and `blazeserve_connections_rejected_total`. Update any dashboards or alert rules that you copied from 0.x.

**Container image.** The image is built from `scratch` and runs as a non-root user. It has no shell and no health check inside the image, so use `/__live__` and `/__ready__` from your orchestrator.

**Telemetry.** There is now a small anonymous usage report, on by default, that you can turn off. See [Telemetry](telemetry.md).

### Checklist for 0.x

1. Install the new version.
2. If you used the Python API, change your code to `blazeserve.Server`.
3. If you accepted uploads, add `--max-upload-mb` with a real limit and a password.
4. Update your alert rules and dashboards if you copied them.
5. Run `blaze doctor` on your served folder.
