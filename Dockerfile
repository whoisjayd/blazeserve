# syntax=docker/dockerfile:1
# Builds from source, for local use and CI. Published images are made from the release
# binaries with deploy/docker/release.Dockerfile and need no compiling.
FROM rust:1-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src

ARG BLAZE_POSTHOG_KEY=""
ARG BLAZE_POSTHOG_HOST=""
ENV BLAZE_POSTHOG_KEY=${BLAZE_POSTHOG_KEY} BLAZE_POSTHOG_HOST=${BLAZE_POSTHOG_HOST}
# Thin link-time optimisation links several times faster than the release setting for
# nearly the same program. Pass --build-arg LTO=fat to match the published binaries.
ARG LTO=thin
ENV CARGO_PROFILE_RELEASE_LTO=${LTO} CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16

COPY Cargo.toml Cargo.lock ./
COPY src ./src
# The cache mounts keep downloaded crates and compiled dependencies between builds, so
# only what changed is compiled again.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/blaze /blaze \
    && mkdir -p /rootfs/data /rootfs/tmp

FROM scratch AS runtime
LABEL org.opencontainers.image.title="BlazeServe" \
      org.opencontainers.image.source="https://github.com/whoisjayd/blazeserve" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="A fast file server and transfer tool for large files" \
      org.opencontainers.image.documentation="https://github.com/whoisjayd/blazeserve/tree/main/docs" \
      io.artifacthub.package.logo-url="https://raw.githubusercontent.com/whoisjayd/blazeserve/main/docs/assets/logo-tile.svg" \
      io.artifacthub.package.readme-url="https://raw.githubusercontent.com/whoisjayd/blazeserve/main/README.md" \
      net.unraid.docker.icon="https://raw.githubusercontent.com/whoisjayd/blazeserve/main/docs/assets/logo-tile.svg"

COPY --from=builder /blaze /usr/local/bin/blaze
COPY --from=builder --chown=10001:10001 /rootfs/data /data
COPY --from=builder --chmod=1777 /rootfs/tmp /tmp

ENV BLAZE_INSTALL_CHANNEL=docker
USER 10001:10001
WORKDIR /data
EXPOSE 5949
ENTRYPOINT ["/usr/local/bin/blaze"]
CMD ["serve", "/data", "--host", "0.0.0.0", "--port", "5949"]
