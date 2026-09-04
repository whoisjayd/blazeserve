# Production Deployment & Operations Guide for BlazeServe

This guide details enterprise deployment workflows, security sandboxing, containerization, systemd process management, reverse proxy optimization, Linux kernel performance tuning, and SRE monitoring for **BlazeServe**.

---

## Table of Contents

1. [Docker & Container Deployment](#1-docker--container-deployment)
2. [Kubernetes Cloud-Native Deployment](#2-kubernetes-cloud-native-deployment)
3. [Systemd Service](#3-systemd-service)
4. [Reverse Proxy Configurations (Nginx, Caddy, Traefik)](#4-reverse-proxy-configurations)
5. [Linux Kernel Network Tuning (sysctl)](#5-linux-kernel-network-tuning)
6. [SRE Monitoring (Prometheus & Grafana)](#6-sre-monitoring)
7. [Production Health Diagnostics](#7-production-health-diagnostics)

---

## 1. Docker & Container Deployment

BlazeServe includes a production-hardened multi-stage [Dockerfile](./Dockerfile) and [docker-compose.yml](./docker-compose.yml).

### Developer prerequisites

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) using the official installer, then create the locked development environment from the repository root:

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows PowerShell alternative:
# powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

uv sync --all-extras --dev
```

BlazeServe supports Python 3.10 through 3.13. uv can use an installed supported interpreter or manage one with `uv python`; use `uv run ...` for project commands without activating `.venv`.

### Security Architecture

- **Unprivileged Runtime**: Runs as system user `blazeserve` (`uid: 10001`, `gid: 10001`) with no login shell (`/sbin/nologin`).
- **Read-Only Root Filesystem**: `read_only: true` with a temporary `tmpfs` volume mounted on `/tmp`.
- **Capability Drop**: Drops all Linux capabilities (`cap_drop: [ALL]`).
- **Privilege Escalation Blocked**: `no-new-privileges:true`.
- **Automated Healthcheck**: Native Docker `HEALTHCHECK` querying `http://127.0.0.1:8000/__live__`.

### Quick Launch with Docker Compose

```bash
# Start container with resource limits (2 CPUs, 512MB RAM)
docker compose up -d

# Inspect health and logs
docker compose ps
docker compose logs -f
```

---

## 2. Kubernetes Cloud-Native Deployment

The default Kustomize deployment contains:

- [`deployment.yaml`](./deploy/k8s/deployment.yaml): one hardened replica with an ephemeral `emptyDir` data volume.
- [`service.yaml`](./deploy/k8s/service.yaml): an internal ClusterIP Service exposing port 80.

The single replica prevents clients from seeing inconsistent content across independent `emptyDir` volumes. Replace that volume with storage providing the required shared access semantics before scaling beyond one replica.

[`ingress.yaml`](./deploy/k8s/ingress.yaml) and [`servicemonitor.yaml`](./deploy/k8s/servicemonitor.yaml) are optional and deliberately excluded from [`kustomization.yaml`](./deploy/k8s/kustomization.yaml). Apply them individually only after installing and configuring the corresponding Nginx Ingress or Prometheus Operator controller.

### Deployment with Kustomize

```bash
# Apply the private, single-replica default.
kubectl apply -k deploy/k8s/

# Monitor rollout status.
kubectl rollout status deployment/blazeserve
```

---

## 3. Systemd Service

[`deploy/systemd/blazeserve.service`](./deploy/systemd/blazeserve.service) runs BlazeServe as a hardened daemon bound to `127.0.0.1:8000`, the backend address used by the supplied local Nginx, Caddy, and Traefik reverse-proxy configurations. BlazeServe does not consume systemd socket-activation file descriptors.

### Hardening Directives

```ini
[Service]
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=true
ReadWritePaths=/srv/blazeserve
LimitNOFILE=1048576
LimitNPROC=512
```

### Setup on Linux Host

```bash
# 1. Create system user and directory
sudo useradd -r -u 10001 -s /sbin/nologin -d /srv/blazeserve blazeserve
sudo mkdir -p /srv/blazeserve
sudo chown -R blazeserve:blazeserve /srv/blazeserve

# 2. Install uv, if it is not already available on PATH (see the official
#    installer instructions in the developer prerequisites above).
#    Run this from the BlazeServe repository root. Keep the service isolated
#    in its own uv-managed environment rather than modifying system Python.
UV="$(command -v uv)"
sudo mkdir -p /opt/blazeserve
sudo env UV_PROJECT_ENVIRONMENT=/opt/blazeserve/.venv "$UV" sync --locked --no-dev --no-editable

# The supplied unit invokes /usr/local/bin/blaze; expose the venv's console
# script at that stable path without installing into the system prefix.
sudo ln -sfn /opt/blazeserve/.venv/bin/blaze /usr/local/bin/blaze

# 3. Install the service unit
sudo cp deploy/systemd/blazeserve.service /etc/systemd/system/

# 4. Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable --now blazeserve.service

# 5. Check status
sudo systemctl status blazeserve
```

---

## 4. Reverse Proxy Configurations

Reverse proxy blueprints are located in [`deploy/reverse-proxy/`](./deploy/reverse-proxy/):

### Critical Requirement: Disable Proxy Buffering
Because BlazeServe delivers multi-gigabyte files via zero-copy `sendfile` and range streams, proxy buffering **must be disabled** to prevent disk buffer contention.

### Nginx ([`deploy/reverse-proxy/nginx.conf`](./deploy/reverse-proxy/nginx.conf))
```nginx
proxy_buffering off;
proxy_request_buffering off;
proxy_http_version 1.1;
```

### Caddy ([`deploy/reverse-proxy/Caddyfile`](./deploy/reverse-proxy/Caddyfile))
```caddy
reverse_proxy 127.0.0.1:8000 {
    flush_interval -1
}
```

### Traefik v3 ([`deploy/reverse-proxy/traefik.yml`](./deploy/reverse-proxy/traefik.yml))
Includes automated health checks pointing to `/__live__` with dynamic load balancing.

---

## 5. Linux Kernel Network Tuning

High-concurrency HTTP services require kernel socket adjustments to eliminate dropped packets during connection spikes.

Files located in [`deploy/linux-tuning/`](./deploy/linux-tuning/):
- [`sysctl-blazeserve.conf`](./deploy/linux-tuning/sysctl-blazeserve.conf): High-performance network knobs.
- [`limits.conf`](./deploy/linux-tuning/limits.conf): Open file descriptor limits (`1048576`).
- [`tuning.sh`](./deploy/linux-tuning/tuning.sh): Automated audit and apply script.

### Key Tunables Applied

| Parameter | Recommended Value | Purpose |
| :--- | :--- | :--- |
| `net.core.somaxconn` | `65535` | Maximum socket listen backlog queue. |
| `net.ipv4.tcp_max_syn_backlog` | `32768` | SYN backlog queue length. |
| `net.ipv4.tcp_fin_timeout` | `15` | Fast reclamation of closed sockets. |
| `net.ipv4.tcp_tw_reuse` | `1` | Reuse TIME-WAIT sockets safely. |
| `net.core.rmem_max` / `wmem_max` | `16777216` | 16MB TCP window buffer sizing. |
| `fs.file-max` | `2097152` | System-wide open file limits. |

### Run the Tuning Tool

```bash
# Check current system configuration
./deploy/linux-tuning/tuning.sh --check

# Dry-run configuration changes
./deploy/linux-tuning/tuning.sh --dry-run

# Apply permanently (requires sudo)
sudo ./deploy/linux-tuning/tuning.sh --apply
```

---

## 6. SRE Monitoring

Observability templates are located in [`deploy/monitoring/`](./deploy/monitoring/):

- [`prometheus.yml`](./deploy/monitoring/prometheus.yml): an in-cluster scrape job targeting the internal `blazeserve.default.svc.cluster.local:80` Service.
- [`alerts.yml`](./deploy/monitoring/alerts.yml): alerts for instance downtime, errors, and request saturation.
- [`grafana-dashboard.json`](./deploy/monitoring/grafana-dashboard.json): a Grafana dashboard to import.

The default target is reachable from Prometheus running inside the Kubernetes cluster without publishing the ClusterIP Service. For a host Prometheus deployment, change the target to the systemd bind address `127.0.0.1:8000`; for Prometheus on the Docker Compose network, use `blazeserve:8000`.

```yaml
scrape_configs:
  - job_name: "blazeserve"
    metrics_path: "/__metrics__"
    static_configs:
      - targets: ["blazeserve.default.svc.cluster.local:80"]
```

---

## 7. Production Health Diagnostics

BlazeServe includes built-in diagnostic tools for pre-flight environment checks:

```bash
# Validate directories, port bindings, and OS zero-copy support
blaze doctor /data --port 8000

# Machine-readable version check
blaze version --json

# Client throughput benchmark test
blaze benchmark --url http://127.0.0.1:8000 --size-mb 100
```
