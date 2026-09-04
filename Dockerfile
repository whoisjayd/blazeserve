# Multi-stage production build for BlazeServe
FROM python:3.13-slim AS builder

# Copy uv from the official, version-pinned image rather than installing it via Python.
COPY --from=ghcr.io/astral-sh/uv:0.12.9 /uv /uvx /bin/

WORKDIR /app
COPY pyproject.toml README.md LICENSE uv.lock /app/

# Keep dependency installation in a cacheable layer before copying application sources.
ENV UV_LINK_MODE=copy \
    UV_NO_DEV=1
RUN uv sync --locked --no-install-project --no-editable

COPY blazeserve/ /app/blazeserve/
RUN uv sync --locked --no-editable

# Runtime container
FROM python:3.13-slim AS runtime

LABEL maintainer="Jaydeep Solanki <whoisjayd@github>" \
      description="BlazeServe HTTP file server with metrics, TLS, and range downloads"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

# Keep the runtime identity deterministic across Docker and Kubernetes.
RUN groupadd --system --gid 10001 blazeserve && \
    useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin blazeserve && \
    mkdir -p /data && \
    chown 10001:10001 /data

COPY --from=builder /app/.venv /app/.venv

USER blazeserve
WORKDIR /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/__live__', timeout=2).close()"]

ENTRYPOINT ["blaze"]
CMD ["serve", "/data", "--host", "0.0.0.0", "--port", "8000"]
