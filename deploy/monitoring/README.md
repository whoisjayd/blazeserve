# SRE Monitoring & Observability for BlazeServe

This directory contains production monitoring artifacts for tracking BlazeServe via **Prometheus** and visualizing real-time telemetry on **Grafana**.

## Monitored Telemetry (Golden Signals)

1. **Traffic**: `blazeserve_requests_total` (total requests processed) and `rate(blazeserve_requests_total[1m])` (RPS).
2. **Saturation**: `blazeserve_requests_active` (concurrent requests handled).
3. **Errors**: `blazeserve_errors_total` (total unhandled connection/socket errors).
4. **Throughput**: `blazeserve_bytes_sent_total` and `blazeserve_bytes_received_total` (egress and ingress rate).
5. **Availability**: `blazeserve_uptime_seconds` (continuous uptime tracker).

## Fast Setup with Prometheus & Grafana

```bash
# 1. Start Prometheus pointing to blazeserve
prometheus --config.file=deploy/monitoring/prometheus.yml

# 2. Import Dashboard into Grafana
# Open Grafana -> Dashboards -> New -> Import -> Upload deploy/monitoring/grafana-dashboard.json
```
