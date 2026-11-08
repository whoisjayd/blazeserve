# Upgrading from 0.x

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

## A short checklist

1. Install the new version.
2. If you used the Python API, change your code to `blazeserve.Server`.
3. If you accepted uploads, add `--max-upload-mb` with a real limit and a password.
4. Update your alert rules and dashboards if you copied them.
5. Run `blaze doctor` on your served folder.
