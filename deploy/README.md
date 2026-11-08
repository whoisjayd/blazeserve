# Deployment

BlazeServe is one static binary: run it directly, under systemd, or in a container. Every example here binds loopback or a private network. Before exposing it publicly, require authentication, terminate TLS (built in or at a proxy), and decide on an upload policy.

- BlazeServe binds its own socket; systemd socket activation is not supported.
- TLS certificate rotation needs a restart. There is no in-process reload.
- `Ctrl+C` or `SIGTERM` closes the listener at once and gives in-flight requests a bounded grace period.
- Uploads are off unless `--max-upload-mb` is a positive number. Enable them only with `--auth` or `--auth-env` and writable storage; the examples below mount data read-only.

## Docker and Compose

The image is built from `scratch` with a static musl binary and runs as uid/gid 10001. It has no shell and no in-image health check; probe `/__live__` and `/__ready__` from your orchestrator.

```bash
# POSIX
docker run --rm -p 8000:8000 -v "$PWD/data:/data:ro" ghcr.io/whoisjayd/blazeserve:latest
```

```powershell
# PowerShell
docker run --rm -p 8000:8000 -v "${PWD}\data:/data:ro" ghcr.io/whoisjayd/blazeserve:latest
```

`docker-compose.yml` runs the same image with a read-only root, `no-new-privileges`, all capabilities dropped, a 64 MiB `/tmp`, and limits of 2 CPUs and 256 MiB.

```console
docker compose up -d
docker compose logs -f blazeserve
```

Compose passes `BLAZE_TELEMETRY` and the `OTEL_*` variables through from the host when they are set, so no value is stored in the file. To enable uploads, mount a writable volume, set `--max-upload-mb` and require authentication.

## Kubernetes

```console
kubectl apply -k deploy/k8s/
kubectl rollout status deployment/blazeserve
```

The Kustomize base contains only `deployment.yaml` and `service.yaml`: one pod and a ClusterIP Service on port 80. The pod runs as uid/gid 10001 with a read-only root filesystem, a read-only data mount, dropped capabilities, resource limits, and liveness and readiness probes on `/__live__` and `/__ready__`.

Replicas stay at `1` because the data volume is an `emptyDir`, which is ephemeral and not shared between pods. Replace it with storage that has the access semantics you need before scaling out.

Two manifests are optional and left out of the base, so applying it never exposes the service:

- `ingress.yaml` is for the Nginx Ingress Controller. Replace `files.example.com` first. It turns proxy buffering off and sets `proxy-body-size` to `100m`, so raise that if you enable large uploads.
- `servicemonitor.yaml` is for clusters with the Prometheus Operator CRDs. It scrapes `/__metrics__` through the Service every 10 seconds.

```console
kubectl apply -f deploy/k8s/ingress.yaml
kubectl apply -f deploy/k8s/servicemonitor.yaml
```

To turn off usage telemetry, add `BLAZE_TELEMETRY=0` under the container `env` in `deployment.yaml`.

## systemd

`systemd/blazeserve.service` is a hardened unit that serves `/srv/blazeserve` on `127.0.0.1:8000`. It trusts forwarded client addresses only from `127.0.0.1/32`, matching the local proxy examples; drop `--trust-proxy` if nothing proxies to it.

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

`blaze` comes from a release archive; use the musl build on older distributions. `ReadWritePaths` matters only when uploads are enabled.

## Windows and macOS

Download the archive for your platform from [Releases](https://github.com/whoisjayd/blazeserve/releases), check it against `SHA256SUMS`, and run `blaze serve`. The repository ships no Windows service or launchd definition; use your platform's service manager.

## Reverse proxy

`reverse-proxy/` holds configurations for Nginx, Caddy and Traefik v3. Each streams without buffering, because buffering turns range requests and multi-gigabyte downloads into double disk I/O.

| Proxy | Setting |
| :--- | :--- |
| Nginx | `proxy_buffering off;` and `proxy_request_buffering off;` |
| Caddy | `flush_interval -1` |
| Traefik | direct pass-through with a health check on `/__live__` |

Behind a proxy every connection comes from the proxy's address, so rate limits and logs would share one identity. Pass the proxy's address or network:

```console
blaze serve /srv/files --host 127.0.0.1 --trust-proxy 127.0.0.1/32
```

`--trust-proxy` can be repeated. For a request from a trusted peer, BlazeServe reads `Forwarded` or `X-Forwarded-For` and walks the chain from the right, skipping trusted hops. The first untrusted address becomes the client identity, and `--max-proxy-hops` bounds the walk. A peer outside the trusted set has these headers ignored, and the immediate peer is logged in its own field.

This holds only if clients cannot reach BlazeServe directly. Bind it to loopback or a private network and firewall the port. The proxy must also set `X-Forwarded-For`; `nginx.conf` does this with `$proxy_add_x_forwarded_for`. Check that your Caddy and Traefik setups forward it. `Forwarded` takes precedence over `X-Forwarded-For`, so the proxy must also drop any client-supplied `Forwarded` header, as all three examples do; otherwise a client can choose its own identity. If the proxy sits behind another trusted proxy, list both networks.

## Monitoring

`monitoring/` has a Prometheus scrape config, alert rules and a Grafana dashboard. Prometheus scrapes `/__metrics__`; series are listed in the main [README](../README.md#metrics-and-logs). Keep the endpoint off untrusted networks.

- **Alerts** (`alerts.yml`): `BlazeServeInstanceDown`, `BlazeServeHighErrorRate`, `BlazeServeHighActiveRequests` and `BlazeServeConnectionsRejected`.
- **Scrape target:** `prometheus.yml` defaults to `blazeserve.default.svc.cluster.local:80`, the Service from `k8s/service.yaml`. Use `127.0.0.1:8000` for the systemd unit, or `blazeserve:8000` when Prometheus shares the Compose network. Mount both `prometheus.yml` and `alerts.yml` into Prometheus.
- **Dashboard:** import `monitoring/grafana-dashboard.json` from Dashboards, then New, then Import, and pick the Prometheus data source that uses this scrape config.

OTLP export of traces and metrics is configured with the variables in the README's [OpenTelemetry](../README.md#opentelemetry) section. OTLP metrics use the `http.server.*` names, separate from the `blazeserve_*` series the dashboard and alerts use.

For a local OTLP backend, the `observability` Compose profile starts `grafana/otel-lgtm`, with Grafana, Tempo, Loki and Prometheus in one container. Its ports are published on loopback only and it uses default credentials, so keep it to local use.

```bash
# POSIX
OTEL_EXPORTER_OTLP_ENDPOINT=http://lgtm:4318 OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
  docker compose --profile observability up -d
```

```powershell
# PowerShell
$env:OTEL_EXPORTER_OTLP_ENDPOINT = "http://lgtm:4318"
$env:OTEL_EXPORTER_OTLP_PROTOCOL = "http/protobuf"
docker compose --profile observability up -d
```

Open Grafana at `http://localhost:3000`.

## Linux tuning

`linux-tuning/tuning.sh` takes `--check` (the default), `--dry-run` or `--apply`. `--apply` writes `/etc/sysctl.d/99-blazeserve.conf`. `sysctl-blazeserve.conf` and `limits.conf` are the same values for manual use.

```console
./deploy/linux-tuning/tuning.sh --check
sudo ./deploy/linux-tuning/tuning.sh --apply
```

`--backlog` is capped by `net.core.somaxconn`. File descriptor limits matter at a high `--max-connections`; the systemd unit sets `LimitNOFILE`. Measure before changing defaults; the method is in the README's [Performance](../README.md#performance) section.

## Diagnostics

```console
blaze doctor /srv/files --port 8000
blaze doctor /srv/files --json
```

It checks the path, port binding, async I/O, TLS readiness and the file descriptor limit. `--json` exits non-zero on failure.
