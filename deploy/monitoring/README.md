# SRE Monitoring & Observability for BlazeServe

This directory contains Prometheus alert rules, a scrape configuration, and a Grafana dashboard for BlazeServe.

## Metrics

BlazeServe exposes Prometheus text metrics at `GET /__metrics__`. The supplied configuration tracks request traffic, active requests, errors, byte throughput, and uptime.

## Kubernetes

`prometheus.yml` defaults to `blazeserve.default.svc.cluster.local:80`, the internal ClusterIP Service created by `deploy/k8s/service.yaml`. Run Prometheus in the cluster and mount both `prometheus.yml` and `alerts.yml` into its configuration directory. The metrics endpoint remains on the cluster network; neither the Service nor the default Kustomize deployment creates a public route.

Prometheus Operator users may instead apply the optional monitor after installing the CRD and configuring the operator to select it:

```bash
kubectl apply -f deploy/k8s/servicemonitor.yaml
```

The ServiceMonitor is intentionally not part of `deploy/k8s/kustomization.yaml` because a stock Kubernetes cluster does not provide that custom resource.

## Host deployment

For Prometheus running on the same host as the systemd service, copy `prometheus.yml` and change its target to `127.0.0.1:8080`. For the default Docker Compose deployment, run Prometheus on the Compose network and use `blazeserve:8000` as the target. Do not publish the metrics endpoint to an untrusted network; use firewall or reverse-proxy access controls when Prometheus cannot scrape over a private network.

## Grafana

Import `deploy/monitoring/grafana-dashboard.json` from **Dashboards → New → Import** and select the Prometheus data source that uses this scrape configuration.
