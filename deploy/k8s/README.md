# Kubernetes Deployment Guide for BlazeServe

The default Kustomize deployment installs one unprivileged BlazeServe pod and an internal ClusterIP Service. It uses an `emptyDir` data volume, so content is ephemeral and scoped to that pod.

## Default deployment

```bash
kubectl apply -k deploy/k8s/
kubectl rollout status deployment/blazeserve
```

Only `deployment.yaml` and `service.yaml` are in `kustomization.yaml`. The pod runs as uid/gid 10001 with a read-only root filesystem, dropped capabilities, resource limits, and liveness/readiness probes.

The replica count is intentionally `1`: independent `emptyDir` volumes do not share files. Before scaling out, replace the data volume with storage that provides the required shared access semantics and update the volume mount accordingly.

## Optional ingress

After replacing `files.example.com` and configuring an Nginx Ingress Controller, apply the ingress separately:

```bash
kubectl apply -f deploy/k8s/ingress.yaml
```

The ingress disables request/response buffering for streaming and limits request bodies to `100m`, matching the deployment's `--max-upload-mb 100` setting. It is intentionally excluded from the default deployment so applying Kustomize does not expose BlazeServe publicly.

## Optional Prometheus Operator integration

After installing the Prometheus Operator CRDs and ensuring your Prometheus instance selects the manifest's labels, apply:

```bash
kubectl apply -f deploy/k8s/servicemonitor.yaml
```

The ServiceMonitor scrapes `/__metrics__` through the internal Service. It is intentionally excluded from the default deployment because the custom resource is unavailable on stock Kubernetes clusters.
