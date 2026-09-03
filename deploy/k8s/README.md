# Kubernetes Deployment Guide for BlazeServe

This directory contains cloud-native, production-grade Kubernetes manifests for deploying BlazeServe with automated health checks, security sandboxing, and Prometheus Operator observability.

## Architecture

- **Deployment**: Runs 2 unprivileged replicas (`uid: 10001`) with `readOnlyRootFilesystem: true`, capabilities dropped, and CPU/memory resource quotas.
- **Probes**:
  - Liveness Probe: `GET /__live__` on port 8000.
  - Readiness Probe: `GET /__ready__` on port 8000.
- **Ingress**: Nginx Ingress Controller configuration with unbuffered streaming for high-throughput range requests and unlimited body size for uploads.
- **Observability**: Native `ServiceMonitor` for Prometheus Operator scraping `/__metrics__` every 10 seconds.

## Quick Deploy

```bash
# Apply with kubectl
kubectl apply -k deploy/k8s/

# Verify rollout status
kubectl rollout status deployment/blazeserve
```
