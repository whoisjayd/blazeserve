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
      description="⚡ Ultra-fast production HTTP file server with metrics, TLS, and range downloads"

# Create non-privileged system user and directories
RUN useradd -r -u 10001 -s /sbin/nologin blazeserve && \
    mkdir -p /data && \
    chown -R blazeserve:blazeserve /data

COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

USER blazeserve
WORKDIR /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/__live__').status == 200 else 1)"

ENTRYPOINT ["blaze"]
CMD ["serve", "/data", "--host", "0.0.0.0", "--port", "8000"]
