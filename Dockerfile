FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src

# Dependencies build in their own layer so source edits do not invalidate it.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && touch src/lib.rs && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/deps/blazeserve* target/release/blaze*

COPY src ./src
ARG BLAZE_TELEMETRY_URL=""
ENV BLAZE_TELEMETRY_URL=${BLAZE_TELEMETRY_URL}
RUN cargo build --release --locked && mkdir -p /rootfs/data /rootfs/tmp

FROM scratch AS runtime
LABEL org.opencontainers.image.title="BlazeServe" \
      org.opencontainers.image.source="https://github.com/whoisjayd/blazeserve" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /src/target/release/blaze /usr/local/bin/blaze
COPY --from=builder --chown=10001:10001 /rootfs/data /data
COPY --from=builder --chmod=1777 /rootfs/tmp /tmp

USER 10001:10001
WORKDIR /data
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/blaze"]
CMD ["serve", "/data", "--host", "0.0.0.0", "--port", "8000"]
