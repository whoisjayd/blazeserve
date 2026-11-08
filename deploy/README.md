# Deployment

BlazeServe is one program, so you can run it directly, under systemd, or in a container. The examples here all listen on the loopback address or a private network. Before you open a server to the internet, set a password, use HTTPS (built in, or at a proxy), and decide whether to allow uploads.

A few things to know up front:

- BlazeServe opens its own port. It does not support systemd socket activation.
- Certificates are read at startup. After renewing one, restart the server.
- `Ctrl+C` or `SIGTERM` stops it accepting new connections at once and gives running downloads a short time to finish.
- Uploads are off unless `--max-upload-mb` is set above zero. Turn them on only with a password and writable storage. The examples below mount data read-only.

For what each option does, see the [documentation](../docs/README.md), especially [Serving files](../docs/serving-files.md).

## Docker and Compose

The image is built from `scratch` with a static binary and runs as user and group 10001. It has no shell and no built-in health check, so have your orchestrator probe `/__live__` and `/__ready__`.

```bash
# Linux and macOS
docker run --rm -p 8000:8000 -v "$PWD/data:/data:ro" ghcr.io/whoisjayd/blazeserve:latest
```

```powershell
# Windows PowerShell
docker run --rm -p 8000:8000 -v "${PWD}\data:/data:ro" ghcr.io/whoisjayd/blazeserve:latest
```

`docker-compose.yml` runs the same image with a read-only root filesystem, `no-new-privileges`, all capabilities dropped, a 64 MiB `/tmp`, and limits of 2 CPUs and 256 MiB of memory.

```console
docker compose up -d
docker compose logs -f blazeserve
```

Compose passes `BLAZE_TELEMETRY` and the `OTEL_*` variables through from your shell when they are set, so no values are stored in the file. To allow uploads, mount a writable volume, set `--max-upload-mb` and require a password.

## Kubernetes

```console
kubectl apply -k deploy/k8s/
kubectl rollout status deployment/blazeserve
```

The base contains two files: a Deployment with one pod, and a ClusterIP Service on port 80. The pod runs as user and group 10001 with a read-only root filesystem, a read-only data mount, dropped capabilities, resource limits, and probes on `/__live__` and `/__ready__`.

The deployment stays at one replica because its data volume is an `emptyDir`, which disappears with the pod and is not shared between pods. If you want more replicas, replace it with storage that suits your needs first.

Two more files are optional and are left out of the base, so applying it never exposes the service by accident:

- `ingress.yaml` is for the Nginx Ingress Controller. Replace `files.example.com` first. It turns proxy buffering off and sets the body limit to `100m`, so raise that if you enable large uploads.
- `servicemonitor.yaml` is for clusters with the Prometheus Operator. It scrapes `/__metrics__` through the Service every 10 seconds.

```console
kubectl apply -f deploy/k8s/ingress.yaml
kubectl apply -f deploy/k8s/servicemonitor.yaml
```

To turn off the usage report, add `BLAZE_TELEMETRY=0` under the container's `env` in `deployment.yaml`.

## systemd

`systemd/blazeserve.service` is a hardened unit that serves `/srv/blazeserve` on `127.0.0.1:8000`. It trusts forwarded visitor addresses only from `127.0.0.1/32`, which matches the local proxy examples below. If nothing proxies to it, remove `--trust-proxy` from the unit.

```bash
sudo useradd -r -u 10001 -s /sbin/nologin -d /srv/blazeserve blazeserve
sudo mkdir -p /srv/blazeserve
sudo chown -R blazeserve:blazeserve /srv/blazeserve
sudo install -m 0755 blaze /usr/local/bin/blaze
sudo cp deploy/systemd/blazeserve.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now blazeserve.service
journalctl -u blazeserve.service -f
```

Get `blaze` from a release archive, and use the musl build on older distributions. `ReadWritePaths` in the unit only matters if you enable uploads.

## Windows and macOS

Download the archive for your system from [Releases](https://github.com/whoisjayd/blazeserve/releases), check it against `SHA256SUMS`, and run `blaze serve`. The repository does not include a Windows service or launchd definition, so use your system's own service manager if you want it to start automatically.

## Reverse proxy

`reverse-proxy/` has configurations for Nginx, Caddy and Traefik v3. Each one passes data through without buffering, because buffering turns range requests and multi-gigabyte downloads into extra disk work.

| Proxy | Setting |
| :--- | :--- |
| Nginx | `proxy_buffering off;` and `proxy_request_buffering off;` |
| Caddy | `flush_interval -1` |
| Traefik | Direct pass-through, with a health check on `/__live__` |

Behind a proxy, every connection appears to come from the proxy's address, so speed limits and logs would treat all visitors as one. Tell BlazeServe which proxy to trust:

```console
blaze serve /srv/files --host 127.0.0.1 --trust-proxy 127.0.0.1/32
```

You can repeat `--trust-proxy`. When a request comes from a trusted proxy, BlazeServe reads the `Forwarded` or `X-Forwarded-For` header and walks the list from the right, skipping trusted proxies. The first address that is not trusted is the visitor. `--max-proxy-hops` limits how far it looks. Headers from anyone else are ignored, and the address that actually connected is logged separately as `peer_ip`.

This is only safe if visitors cannot reach BlazeServe directly, so bind it to the loopback address or a private network and firewall the port. Your proxy must also set `X-Forwarded-For`; the Nginx example does this with `$proxy_add_x_forwarded_for`, and you should check that your Caddy and Traefik setups do the same. Because `Forwarded` wins over `X-Forwarded-For`, the proxy must also remove any `Forwarded` header a visitor sends, as all three examples do. Without that, a visitor can pick their own identity. If your proxy sits behind another trusted proxy, list both networks.

## Monitoring

`monitoring/` has a Prometheus scrape config, alert rules and a Grafana dashboard. Prometheus reads `/__metrics__`, and the metrics are listed in the [monitoring guide](../docs/monitoring.md#metrics). Keep that address off untrusted networks.

- **Alerts** in `alerts.yml`: `BlazeServeInstanceDown`, `BlazeServeHighErrorRate`, `BlazeServeHighActiveRequests` and `BlazeServeConnectionsRejected`.
- **Scrape target:** `prometheus.yml` points at `blazeserve.default.svc.cluster.local:80`, the Service from `k8s/service.yaml`. Use `127.0.0.1:8000` for the systemd unit, or `blazeserve:8000` when Prometheus shares the Compose network. Give Prometheus both `prometheus.yml` and `alerts.yml`.
- **Dashboard:** in Grafana choose Dashboards, then New, then Import, load `monitoring/grafana-dashboard.json`, and pick the Prometheus data source that uses this scrape config.

Traces and metrics can also be exported with OpenTelemetry, described in the [monitoring guide](../docs/monitoring.md#opentelemetry). Those metrics use the `http.server.*` names and are separate from the `blazeserve_*` series the dashboard and alerts use.

For a local backend to try things out, the `observability` Compose profile starts `grafana/otel-lgtm`, which bundles Grafana, Tempo, Loki and Prometheus in one container. Its ports are published on loopback only and it uses default credentials, so keep it to local use.

```bash
# Linux and macOS
OTEL_EXPORTER_OTLP_ENDPOINT=http://lgtm:4318 OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
  docker compose --profile observability up -d
```

```powershell
# Windows PowerShell
$env:OTEL_EXPORTER_OTLP_ENDPOINT = "http://lgtm:4318"
$env:OTEL_EXPORTER_OTLP_PROTOCOL = "http/protobuf"
docker compose --profile observability up -d
```

Then open Grafana at `http://localhost:3000`.

## Linux tuning

`linux-tuning/tuning.sh` takes `--check` (the default), `--dry-run` or `--apply`. With `--apply` it writes `/etc/sysctl.d/99-blazeserve.conf`. `sysctl-blazeserve.conf` and `limits.conf` hold the same values if you would rather apply them by hand.

```console
./deploy/linux-tuning/tuning.sh --check
sudo ./deploy/linux-tuning/tuning.sh --apply
```

`--backlog` cannot exceed `net.core.somaxconn`. If you raise `--max-connections` a lot, also check the open file limit; the systemd unit sets `LimitNOFILE`. Measure before changing defaults, as described in the [performance guide](../docs/performance.md).

## Diagnostics

```console
blaze doctor /srv/files --port 8000
blaze doctor /srv/files --json
```

`doctor` checks the folder, whether the port can be bound, async I/O support, TLS readiness and the open file limit. With `--json` it exits with a non-zero code on failure, which makes it easy to use in scripts.
