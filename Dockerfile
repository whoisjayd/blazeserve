# Multi-stage production build for BlazeServe
FROM python:3.13-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE /build/
COPY blazeserve/ /build/blazeserve/

RUN pip install --no-cache-dir --upgrade pip build && \
    python -m build --wheel --outdir /wheels .

# Runtime container
FROM python:3.13-slim AS runtime

LABEL maintainer="Jaydeep Solanki <whoisjayd@github>" \
      description="BlazeServe HTTP file server with metrics, TLS, and range downloads"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Keep the runtime identity deterministic across Docker and Kubernetes.
RUN groupadd --system --gid 10001 blazeserve && \
    useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin blazeserve && \
    mkdir -p /data && \
    chown 10001:10001 /data

COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

USER blazeserve
WORKDIR /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/__live__', timeout=2).close()"]

ENTRYPOINT ["blaze"]
CMD ["serve", "/data", "--host", "0.0.0.0", "--port", "8000"]
